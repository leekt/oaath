/**
 * connect, requestPermission, resume, signOut, and close.
 *
 * The authorization journey runs entirely over the issuer's Fetch endpoints and
 * the protocol contracts; this module owns orchestration only:
 *
 * ```text
 * requestPermission  PKCE verifier
 *                    -> POST /authorization/requests   (the reviewed scope)
 *                    -> the injected authorization capability returns the code
 *                       the owner's decision released
 *                    -> POST /authorization/codes/consume
 *                    -> POST /authorization/artifacts/{id}/claim
 *                    -> applyPermissionDecision  (protocol owns the binding)
 *                    -> activate + persist       (GrantStore owns durability)
 * resume             the durable Grant is authoritative for authority; the relay
 *                    round-trip proves fresh client authentication, so an absent
 *                    relay record never revokes a Grant and a recorded rejection
 *                    always does
 * ```
 *
 * The scope the owner reviews is exactly the permission request without the
 * relay-assigned `requestId`, so the decision's `requestHash` binds the same
 * bytes the owner saw and the client can reconstruct nothing wider.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  advanceGrant,
  applyPermissionDecision,
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  createGrantFromPermissionRequest,
  deriveCodeChallenge,
  type Grant,
  type GrantPolicy,
  OAATH_GRANT_POLICY_VERSION,
  OAATH_ISSUER_VERSION,
  OAATH_PERMISSION_REQUEST_VERSION,
  type PermissionDecision,
  type PermissionRequest,
  type PermissionSessionSigner,
  parseGrantPolicy,
  parseIssuerIdentity,
  parsePermissionDecision,
  parsePermissionRequest,
  sameGrantIdentity,
} from "@oaath/protocol";
import {
  type KernelAllChainApproval,
  kernelAllChainCapabilityHash,
  parseKernelAllChainApproval,
} from "../kernel/permission/materialize.js";
import type { KeyProfile } from "../kernel/types.js";
import {
  OAATH_CLIENT_CONTEXT_VERSION,
  type OaathClientContext,
  type OaathContextStore,
  type OaathKeyStore,
  parseClientContext,
} from "../persistence/interfaces.js";
import type { GrantStore, GrantStoreRecord, OperationStoreAdapter } from "../store.js";
import type { OaathBinding } from "./binding.js";
import {
  clientCapability,
  clientFail,
  exactClientRecord,
  mapClientFailure,
  OaathClientError,
} from "./errors.js";
import {
  createGrantHandle,
  type OaathCapabilityInvalidationCapability,
  type OaathChainCapability,
  type OaathGrantHandle,
} from "./grant-handle.js";

const MAX_PERMISSIONS = 16;
const MAX_EXPIRES_IN = 86_400;
const VERIFIER_BYTES = 32;

/**
 * The issuer transport. The caller owns credentials: its `fetch` adds whatever
 * the deployment's authentication port expects, so no token, cookie, or bearer
 * material ever lives in SDK memory.
 */
export interface OaathIssuerCapability {
  /** Canonical https issuer base URL. */
  readonly url: string;
  readonly fetch: (request: Request) => Promise<Response>;
  /** Revokes the caller's relay or application authentication, or `null`. */
  readonly signOut: (() => Promise<unknown>) | null;
}

/**
 * Drives the owner's decision and returns the authorization code the issuer
 * released to the redirect target. In a browser this is the consent window and
 * the redirect listener; both are the application's, never the SDK's.
 */
export interface OaathAuthorizationCapability {
  readonly authorize: (
    request: Readonly<{ requestId: string; redirectUri: string; expiresAt: number }>,
  ) => Promise<unknown>;
}

export interface OaathPermissionCallInput {
  readonly target: `0x${string}`;
  readonly selectors: readonly `0x${string}`[];
  /** Canonical decimal uint256 native value ceiling for each of these calls. */
  readonly valueLimit: string;
}

export interface OaathPermissionInput {
  readonly calls: readonly Readonly<OaathPermissionCallInput>[];
}

export interface OaathRequestPermissionInput {
  readonly chainScope: "all";
  readonly permissions: readonly Readonly<OaathPermissionInput>[];
  /** Seconds of Grant lifetime from now. */
  readonly expiresIn: number;
  readonly perChainOperationLimit: number;
}

export interface OaathConnection {
  readonly binding: Readonly<OaathBinding>;
  readonly requestPermission: (input: unknown) => Promise<Readonly<OaathGrantHandle>>;
  /** The realm's persisted active Grant, or `null` when there is none. */
  readonly resume: () => Promise<Readonly<OaathGrantHandle> | null>;
  readonly signOut: () => Promise<void>;
  readonly close: () => Promise<void>;
}

export interface CreateConnectionInput {
  readonly binding: Readonly<OaathBinding>;
  readonly issuer: Readonly<OaathIssuerCapability>;
  readonly authorization: Readonly<OaathAuthorizationCapability>;
  readonly grants: GrantStore;
  readonly operations: OperationStoreAdapter;
  readonly keys: OaathKeyStore;
  readonly contexts: OaathContextStore;
  readonly chains: ReadonlyMap<number, Readonly<OaathChainCapability>>;
  readonly ownerKey: Readonly<KeyProfile>;
  readonly sessionKey: Readonly<KeyProfile>;
  readonly invalidation: Readonly<OaathCapabilityInvalidationCapability>;
  /**
   * Remote session-key custody the deployment declared, or null for frontend
   * custody. Named in every permission request so the owner's approval binds
   * the custody model through the request hash.
   */
  readonly sessionSigner: Readonly<PermissionSessionSigner> | null;
  readonly now: () => number;
}

/** The reviewed scope: a permission request without its relay-assigned id. */
type PermissionScope = Omit<PermissionRequest, "requestId">;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function newCodeVerifier(): string {
  const random = globalThis.crypto?.getRandomValues?.bind(globalThis.crypto);
  if (!random) {
    return clientFail("oaath_client_capability_invalid", "WebCrypto randomness is unavailable");
  }
  return base64Url(random(new Uint8Array(VERIFIER_BYTES)));
}

function safeCount(value: unknown, label: string, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > maximum) {
    return clientFail("oaath_client_input_invalid", `${label} must be a bounded positive integer`);
  }
  return value;
}

/**
 * Expands the application's permissions into the canonical Grant policy. The
 * policy vocabulary is `@oaath/protocol`'s; this only flattens the per-target
 * selector lists an application naturally writes.
 */
function policyFromInput(
  value: unknown,
  requestedAt: number,
  expiresAt: number,
  perChainOperationLimit: number,
  context: CaptureContext,
): Readonly<GrantPolicy> {
  const permissions = captureDenseArray(value, "permissions", context, (message) =>
    clientFail("oaath_client_input_invalid", message),
  );
  if (permissions.length < 1 || permissions.length > MAX_PERMISSIONS) {
    return clientFail("oaath_client_input_invalid", "permissions must hold 1 to 16 entries");
  }
  const calls: Readonly<{
    target: `0x${string}`;
    selector: `0x${string}`;
    valueLimit: string;
    argumentEquals: readonly never[];
  }>[] = [];
  for (const [index, permission] of permissions.entries()) {
    const record = exactClientRecord(permission, ["calls"], `permission ${index}`, context);
    const entries = captureDenseArray(
      record.calls,
      `permission ${index} calls`,
      context,
      (message) => clientFail("oaath_client_input_invalid", message),
    );
    for (const [callIndex, entry] of entries.entries()) {
      const call = exactClientRecord(
        entry,
        ["target", "selectors", "valueLimit"],
        `permission ${index} call ${callIndex}`,
        context,
      );
      const selectors = captureDenseArray(
        call.selectors,
        `permission ${index} call ${callIndex} selectors`,
        context,
        (message) => clientFail("oaath_client_input_invalid", message),
      );
      if (typeof call.target !== "string" || typeof call.valueLimit !== "string") {
        return clientFail("oaath_client_input_invalid", "permission call fields are invalid");
      }
      for (const selector of selectors) {
        if (typeof selector !== "string") {
          return clientFail("oaath_client_input_invalid", "permission selector is invalid");
        }
        calls.push(
          Object.freeze({
            target: call.target as `0x${string}`,
            selector: selector as `0x${string}`,
            valueLimit: call.valueLimit,
            argumentEquals: Object.freeze([]),
          }),
        );
      }
    }
  }
  // parseGrantPolicy owns every exact rule; an invalid policy fails closed there.
  try {
    return parseGrantPolicy({
      version: OAATH_GRANT_POLICY_VERSION,
      calls,
      validAfter: requestedAt,
      // Inclusive policy expiry, strictly inside the exclusive Grant expiry.
      validUntil: expiresAt - 1,
      perChainOperationLimit,
    });
  } catch (error) {
    return mapClientFailure(error, "the requested permissions are not a valid policy");
  }
}

export function createConnection(
  input: Readonly<CreateConnectionInput>,
): Readonly<OaathConnection> {
  let closed = false;
  let signedOut = false;
  const handles: Readonly<OaathGrantHandle>[] = [];

  function assertUsable(): void {
    if (closed) clientFail("oaath_client_closed", "connection is closed");
    if (signedOut) clientFail("oaath_client_signed_out", "connection signed out");
  }

  async function call(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<Record<string, unknown>> {
    const headers = new Headers();
    if (body !== undefined) headers.set("content-type", "application/json");
    const request = new Request(`${input.issuer.url}${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    let response: Response;
    try {
      response = await input.issuer.fetch(request);
    } catch {
      return clientFail("oaath_client_issuer_unavailable", "the issuer could not be reached");
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      return clientFail("oaath_client_issuer_unavailable", "the issuer response is unreadable");
    }
    const record = captureRecord(payload, "issuer response", new WeakSet(), (message) =>
      clientFail("oaath_client_issuer_unavailable", message),
    );
    if (response.ok) return record;
    const error = exactClientRecord(
      record.error,
      ["code"],
      "issuer error",
      new WeakSet(),
      "oaath_client_issuer_unavailable",
    );
    return clientFail(
      "oaath_client_issuer_rejected",
      "the issuer refused the request",
      typeof error.code === "string" ? error.code : null,
    );
  }

  function text(record: Record<string, unknown>, field: string): string {
    const value = record[field];
    if (typeof value !== "string" || value.length < 1) {
      return clientFail(
        "oaath_client_issuer_unavailable",
        `the issuer response field ${field} is invalid`,
      );
    }
    return value;
  }

  async function persistGrant(grant: Grant, expected: number | null): Promise<GrantStoreRecord> {
    try {
      const committed = await input.grants.compareAndSwap({
        grantId: grant.identity.grantId,
        expectedStoreRevision: expected,
        next: grant,
      });
      if (committed.status === "conflict") {
        return clientFail(
          "oaath_client_state_conflict",
          "the Grant record was written by another realm",
          "grant_store_conflict",
        );
      }
      return committed.record;
    } catch (error) {
      return mapClientFailure(error, "the Grant record could not be persisted");
    }
  }

  function handle(
    record: GrantStoreRecord,
    request: Readonly<PermissionRequest>,
    approvedPolicy: Readonly<GrantPolicy>,
    installApproval: Readonly<KernelAllChainApproval> | null,
  ): Readonly<OaathGrantHandle> {
    const created = createGrantHandle({
      binding: input.binding,
      request,
      approvedPolicy,
      installApproval,
      record,
      grants: input.grants,
      operations: input.operations,
      chains: input.chains,
      ownerKey: input.ownerKey,
      sessionKey: input.sessionKey,
      invalidation: input.invalidation,
      now: input.now,
    });
    handles.push(created);
    return created;
  }

  async function writeContext(
    request: Readonly<PermissionRequest>,
    approvedPolicy: Readonly<GrantPolicy>,
    installApproval: Readonly<KernelAllChainApproval> | null,
  ): Promise<void> {
    const context: OaathClientContext = Object.freeze({
      version: OAATH_CLIENT_CONTEXT_VERSION,
      bindingId: input.binding.bindingId,
      grantId: request.requestId,
      request,
      approvedPolicy,
      installApproval,
      updatedAt: input.now(),
    });
    try {
      await input.contexts.write(context);
    } catch (error) {
      return mapClientFailure(error, "the client context could not be persisted");
    }
  }

  async function requestPermission(value: unknown): Promise<Readonly<OaathGrantHandle>> {
    assertUsable();
    const context: CaptureContext = new WeakSet();
    const record = exactClientRecord(
      value,
      ["chainScope", "permissions", "expiresIn", "perChainOperationLimit"],
      "requestPermission input",
      context,
    );
    if (record.chainScope !== "all") {
      return clientFail("oaath_client_input_invalid", "chainScope must be all in 0.1.0");
    }
    const requestedAt = input.now();
    const expiresAt = requestedAt + safeCount(record.expiresIn, "expiresIn", MAX_EXPIRES_IN);
    const policy = policyFromInput(
      record.permissions,
      requestedAt,
      expiresAt,
      safeCount(record.perChainOperationLimit, "perChainOperationLimit", 2 ** 32 - 1),
      context,
    );
    const scope: PermissionScope = Object.freeze({
      version: OAATH_PERMISSION_REQUEST_VERSION,
      application: input.binding.application,
      chainScope: "all",
      logicalAccount: input.binding.account,
      operatorCredential: input.binding.operatorCredential,
      policy,
      requestedAt,
      expiresAt,
      sessionSigner: input.sessionSigner,
    });

    const verifier = newCodeVerifier();
    const created = await call("POST", "/authorization/requests", {
      redirectUri: input.binding.redirectUri,
      codeChallenge: deriveCodeChallenge(verifier, (message) =>
        clientFail("oaath_client_internal", message),
      ),
      requestedScope: JSON.stringify(scope),
    });
    const requestId = text(created, "requestId");
    const relayExpiresAt = created.expiresAt;
    if (typeof relayExpiresAt !== "number" || !Number.isSafeInteger(relayExpiresAt)) {
      return clientFail("oaath_client_issuer_unavailable", "the issuer expiry is invalid");
    }

    let authorized: unknown;
    try {
      authorized = await input.authorization.authorize({
        requestId,
        redirectUri: input.binding.redirectUri,
        expiresAt: relayExpiresAt,
      });
    } catch {
      return clientFail(
        "oaath_client_decision_unavailable",
        "the owner decision could not be obtained",
      );
    }
    const request = (() => {
      try {
        // The reviewed scope plus the issuer's id is exactly the request whose
        // hash the owner's decision must bind.
        return parsePermissionRequest({ ...scope, requestId });
      } catch (error) {
        return mapClientFailure(error, "the permission request is invalid");
      }
    })();
    const code = text(
      exactClientRecord(
        authorized,
        ["code"],
        "authorization result",
        new WeakSet(),
        "oaath_client_capability_invalid",
      ),
      "code",
    );

    const consumed = await call("POST", "/authorization/codes/consume", {
      code,
      codeVerifier: verifier,
      redirectUri: input.binding.redirectUri,
    });
    if (text(consumed, "requestId") !== requestId) {
      return clientFail(
        "oaath_client_state_conflict",
        "the issuer released a code for another request",
        "authorization_request_mismatch",
      );
    }
    const claimed = await call(
      "POST",
      `/authorization/artifacts/${encodeURIComponent(text(consumed, "artifactId"))}/claim`,
    );
    if (text(claimed, "requestId") !== requestId) {
      return clientFail(
        "oaath_client_state_conflict",
        "the issuer released an artifact for another request",
        "authorization_request_mismatch",
      );
    }

    let decision: Readonly<PermissionDecision>;
    let installApproval: Readonly<KernelAllChainApproval> | null = null;
    try {
      const artifact = JSON.parse(text(claimed, "artifact")) as unknown;
      // An approval artifact carries the replayable Kernel install approval
      // beside the decision; the decision's own capabilityHash binds it below,
      // so the two cannot be mixed across requests or capabilities.
      if (artifact !== null && typeof artifact === "object" && "installApproval" in artifact) {
        const { installApproval: rawApproval, ...decisionValue } = artifact as Record<
          string,
          unknown
        >;
        installApproval = parseKernelAllChainApproval(rawApproval);
        decision = parsePermissionDecision(decisionValue);
      } else {
        decision = parsePermissionDecision(artifact);
      }
    } catch (error) {
      return mapClientFailure(error, "the owner decision artifact is invalid");
    }
    const applied = (() => {
      try {
        return applyPermissionDecision({
          request,
          grant: createGrantFromPermissionRequest(request),
          observation: { status: "available", decision },
          evaluatedAt: input.now(),
        });
      } catch (error) {
        return mapClientFailure(error, "the owner decision could not be applied");
      }
    })();
    if (applied.status === "pending") {
      return clientFail(
        "oaath_client_decision_unavailable",
        "the owner decision is not available",
        applied.reason,
      );
    }
    if (applied.grant.state === "rejected") {
      // The rejection is durable, so a replayed artifact cannot become an approval.
      await persistGrant(applied.grant, null);
      return clientFail(
        "oaath_client_permission_rejected",
        "the owner rejected the permission request",
        "grant_rejected",
      );
    }
    if (applied.grant.state !== "approved") {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant is not approved",
        `grant_${applied.grant.state}`,
      );
    }
    if (decision.kind !== "approve") {
      return clientFail(
        "oaath_client_state_conflict",
        "an approved Grant has no approved policy",
        "permission_decision_conflict",
      );
    }
    // An active Grant must be able to prove its permission is installable:
    // the decision's capabilityHash must be exactly the hash of the replayable
    // install approval delivered beside it. An approval with no capability, or
    // one whose capability the owner never named, never activates.
    if (
      installApproval === null ||
      kernelAllChainCapabilityHash(installApproval) !== decision.capabilityHash
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "the decision does not bind its install capability",
        "capability_binding_mismatch",
      );
    }
    const approvedPolicy = decision.approvedPolicy;
    let active: Grant;
    try {
      active = advanceGrant(applied.grant, {
        type: "activate",
        identity: applied.grant.identity,
        activatedAt: input.now(),
      });
    } catch (error) {
      return mapClientFailure(error, "the Grant could not be activated");
    }
    const stored = await persistGrant(active, null);
    await writeContext(request, approvedPolicy, installApproval);
    return handle(stored, request, approvedPolicy, installApproval);
  }

  async function resume(): Promise<Readonly<OaathGrantHandle> | null> {
    assertUsable();
    let persisted: unknown;
    try {
      persisted = await input.contexts.read(input.binding.bindingId);
    } catch (error) {
      return mapClientFailure(error, "the client context could not be read");
    }
    if (persisted === undefined || persisted === null) return null;
    const context = (() => {
      try {
        return parseClientContext(persisted);
      } catch (error) {
        return mapClientFailure(error, "the persisted client context is invalid");
      }
    })();
    if (context.bindingId !== input.binding.bindingId) {
      return clientFail(
        "oaath_client_state_conflict",
        "the persisted context belongs to another realm",
        "context_binding_mismatch",
      );
    }
    let record: GrantStoreRecord | undefined;
    try {
      record = await input.grants.get(context.grantId);
    } catch (error) {
      return mapClientFailure(error, "the Grant record could not be read");
    }
    if (!record) return null;
    const expected = createGrantFromPermissionRequest(context.request);
    if (!sameGrantIdentity(expected.identity, record.value.identity)) {
      return clientFail(
        "oaath_client_state_conflict",
        "the persisted Grant does not match its reviewed request",
        "grant_identity_mismatch",
      );
    }

    // Fresh relay authentication. `relay_not_found` means the relay no longer
    // retains the authorization request, which says nothing about authority; an
    // authentication refusal fails closed above inside `call`.
    let state: Record<string, unknown> | null = null;
    try {
      state = await call("POST", "/authorization/resume", { requestId: context.grantId });
    } catch (error) {
      if (error instanceof OaathClientError && error.source === "relay_not_found") state = null;
      else throw error;
    }
    if (state !== null && state.decision !== null) {
      const decision = exactClientRecord(
        state.decision,
        ["outcome", "decidedAt"],
        "issuer decision state",
        new WeakSet(),
        "oaath_client_issuer_unavailable",
      );
      if (decision.outcome === "rejected") {
        return clientFail(
          "oaath_client_permission_rejected",
          "the issuer recorded a rejection for this Grant",
          "relay_rejected",
        );
      }
    }
    // A revoking Grant resumes too: it authorizes nothing new (sendCalls
    // requires an active Grant), but its handle is the only path to retrying
    // `revoke()` until every chain's removal is conclusively observed —
    // returning null here would strand cleanup forever after a reload.
    if (record.value.state !== "active" && record.value.state !== "revoking") return null;
    if (record.value.state === "active" && input.now() >= record.value.expiresAt) return null;
    return handle(record, context.request, context.approvedPolicy, context.installApproval);
  }

  async function signOut(): Promise<void> {
    if (closed) clientFail("oaath_client_closed", "connection is closed");
    signedOut = true;
    if (!input.issuer.signOut) return;
    try {
      await input.issuer.signOut();
    } catch (error) {
      return mapClientFailure(error, "issuer sign-out failed");
    }
  }

  return Object.freeze({
    binding: input.binding,
    requestPermission,
    resume,
    signOut,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      const failures: unknown[] = [];
      for (const created of handles.splice(0)) {
        await created.close().catch((error: unknown) => failures.push(error));
      }
      for (const store of [input.grants, input.operations, input.keys, input.contexts]) {
        await Promise.resolve(store.close()).catch((error: unknown) => failures.push(error));
      }
      const failure = failures[0];
      if (failure !== undefined) mapClientFailure(failure, "connection cleanup is incomplete");
    },
  });
}

/** Captures the issuer transport exactly. */
export function captureIssuerCapability(value: unknown): Readonly<OaathIssuerCapability> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    ["url", "fetch", "signOut"],
    "OAAth issuer capability",
    context,
    "oaath_client_capability_invalid",
  );
  // The protocol's canonical URL rule is the one owner of what an issuer URL
  // may be, including the loopback development exception the URL-only mode
  // relies on; restating https-only here would strand `http://localhost`.
  let url: string;
  try {
    url = parseIssuerIdentity({ version: OAATH_ISSUER_VERSION, url: record.url }).url;
  } catch {
    return clientFail("oaath_client_capability_invalid", "issuer url must be a canonical URL");
  }
  if (url !== record.url) {
    return clientFail("oaath_client_capability_invalid", "issuer url must already be canonical");
  }
  return Object.freeze({
    url,
    fetch: clientCapability<OaathIssuerCapability["fetch"]>(record.fetch, "issuer fetch"),
    signOut:
      record.signOut === null
        ? null
        : clientCapability<NonNullable<OaathIssuerCapability["signOut"]>>(
            record.signOut,
            "issuer signOut",
          ),
  });
}

/** Captures the owner-decision capability exactly. */
export function captureAuthorizationCapability(
  value: unknown,
): Readonly<OaathAuthorizationCapability> {
  const record = exactClientRecord(
    value,
    ["authorize"],
    "OAAth authorization capability",
    new WeakSet(),
    "oaath_client_capability_invalid",
  );
  return Object.freeze({
    authorize: clientCapability<OaathAuthorizationCapability["authorize"]>(
      record.authorize,
      "authorization authorize",
    ),
  });
}
