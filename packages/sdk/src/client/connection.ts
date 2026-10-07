/**
 * connect, requestPermission, resume, signOut, and close.
 *
 * Issuer mode obtains the decision through Fetch endpoints; local mode obtains
 * the same decision in-process. Protocol application and persistence are shared:
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
  exactCapturedRecord,
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
  type KernelGrantApproval,
  kernelGrantCapabilityHash,
  parseKernelGrantApproval,
} from "../kernel/permission/approval.js";
import type { KeyProfile } from "../kernel/types.js";
import {
  OAATH_CLIENT_CONTEXT_VERSION,
  type OaathClientContext,
  type OaathContextStore,
  type OaathKeyStore,
  parseClientContext,
} from "../persistence/interfaces.js";
import type { WalletCallBundleStore } from "../provider/bundle-store.js";
import type { PreparedCallStore } from "../provider/prepared-call-store.js";
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
  type OaathOwnerRevocationCapability,
} from "./grant-handle.js";

import {
  createPendingAuthorizationJournal,
  type PendingSnapshot,
} from "./pending-authorization.js";

const MAX_PERMISSIONS = 16;
const MAX_EXPIRES_IN = 86_400;
const MAX_OPERATION_COUNT = 2 ** 32 - 1;
const MAX_UINT48 = 2 ** 48 - 1;
const VERIFIER_BYTES = 32;

function sameSessionSigner(
  approved: Readonly<PermissionSessionSigner> | null,
  current: Readonly<PermissionSessionSigner> | null,
): boolean {
  return (
    (approved === null && current === null) ||
    (approved !== null &&
      current !== null &&
      approved.mode === current.mode &&
      approved.providerId === current.providerId)
  );
}

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
    request: Readonly<{
      requestId: string;
      redirectUri: string;
      expiresAt: number;
      signal?: AbortSignal;
    }>,
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
  /** Stops waiting without withdrawing the retained owner request. */
  readonly signal?: AbortSignal;
  /**
   * Issuer mode only: display this code while waiting for the owner, then clear
   * it when requestPermission settles. Compare it with the phone; it is not authority.
   */
  readonly onPending?: (
    request: Readonly<{
      requestId: string;
      matchCode: string;
      /** Issuer request expiry in Unix milliseconds. */
      expiresAt: number;
    }>,
  ) => void | Promise<void>;
  readonly chainScope: "all";
  readonly permissions: readonly Readonly<OaathPermissionInput>[];
  /** Seconds of Grant lifetime from now. */
  readonly expiresIn: number;
  /**
   * Operations each chain may validate: a bare count is a lifetime cap, and
   * `{ count, intervalSeconds }` refills `count` once per fixed window.
   */
  readonly perChainOperationLimit:
    | number
    | Readonly<{
        count: number;
        intervalSeconds: number;
      }>;
}

export interface OaathPendingPermissionResult {
  /** Null only when request creation was interrupted before its acknowledgement. */
  readonly requestId: string | null;
  readonly matchCode: string | null;
  readonly expiresAt: number;
  readonly status: "pending" | "rejected" | "expired" | "withdrawn" | "approved" | "unavailable";
  /** Only a verified, durably applied approval produces a Grant. */
  readonly grant: Readonly<OaathGrantHandle> | null;
  /** An uncertain one-time effect cannot be retried or treated as authority. */
  readonly recovery: "ready" | "uncertain" | null;
}

export interface OaathConnection {
  /** Observe/resume the retained request once, without creating another request. */
  readonly resumePendingPermission: () => Promise<Readonly<OaathPendingPermissionResult> | null>;
  /** Withdraw only if still pending; an already issued approval remains approved. */
  readonly withdrawPendingPermission: () => Promise<Readonly<OaathPendingPermissionResult> | null>;
  readonly binding: Readonly<OaathBinding>;
  readonly requestPermission: (input: unknown) => Promise<Readonly<OaathGrantHandle>>;
  /** The realm's persisted authority/operation handle, or `null` when there is none. */
  readonly resume: () => Promise<Readonly<OaathGrantHandle> | null>;
  readonly signOut: () => Promise<void>;
  readonly close: () => Promise<void>;
}

/** Local approval still returns the canonical protocol decision and Kernel capability. */
export type LocalPermissionAuthorization = (
  request: Readonly<PermissionRequest>,
) => Promise<unknown>;

type ConnectionAuthority =
  | Readonly<{
      kind: "issuer";
      issuer: Readonly<OaathIssuerCapability>;
      authorization: Readonly<OaathAuthorizationCapability>;
    }>
  | Readonly<{ kind: "local"; approve: LocalPermissionAuthorization }>;

export interface CreateConnectionInput {
  readonly binding: Readonly<OaathBinding>;
  readonly authority: ConnectionAuthority;
  readonly grants: GrantStore;
  readonly operations: OperationStoreAdapter;
  readonly walletCallBundles: WalletCallBundleStore;
  readonly preparedCallContexts: PreparedCallStore;
  readonly keys: OaathKeyStore;
  readonly contexts: OaathContextStore;
  readonly chains: ReadonlyMap<number, Readonly<OaathChainCapability>>;
  readonly ownerKey: Readonly<KeyProfile>;
  readonly sessionKey: Readonly<KeyProfile>;
  readonly invalidation: Readonly<OaathCapabilityInvalidationCapability>;
  readonly ownerRevocations: Readonly<OaathOwnerRevocationCapability> | null;
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

function operationLimitFromInput(
  value: unknown,
  context: CaptureContext,
): GrantPolicy["perChainOperationLimit"] {
  if (typeof value === "number") {
    return Object.freeze({
      count: safeCount(value, "perChainOperationLimit", MAX_OPERATION_COUNT),
      intervalSeconds: null,
    });
  }
  const record = exactClientRecord(
    value,
    ["count", "intervalSeconds"],
    "perChainOperationLimit",
    context,
  );
  return Object.freeze({
    count: safeCount(record.count, "perChainOperationLimit count", MAX_OPERATION_COUNT),
    intervalSeconds: safeCount(
      record.intervalSeconds,
      "perChainOperationLimit intervalSeconds",
      MAX_UINT48,
    ),
  });
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
  perChainOperationLimit: GrantPolicy["perChainOperationLimit"],
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
  const cancellation = new AbortController();
  const pending = createPendingAuthorizationJournal(input);
  let closed = false;
  let closeRequested = false;
  let closing: Promise<void> | null = null;
  let signedOut = false;
  let activeHandleProducers = 0;
  const handleProducerWaiters = new Set<() => void>();
  const handles: Readonly<OaathGrantHandle>[] = [];
  const closeResources = [
    input.grants,
    input.operations,
    input.walletCallBundles,
    input.preparedCallContexts,
    input.keys,
    input.contexts,
  ].map((resource) => ({ resource, closed: false }));

  function assertUsable(): void {
    if (closed || closeRequested) clientFail("oaath_client_closed", "connection is closed");
    if (signedOut) clientFail("oaath_client_signed_out", "connection signed out");
  }

  function releaseHandleProducer(): void {
    activeHandleProducers -= 1;
    if (activeHandleProducers !== 0) return;
    for (const resolve of handleProducerWaiters) resolve();
    handleProducerWaiters.clear();
  }

  function waitForHandleProducers(): Promise<void> {
    if (activeHandleProducers === 0) return Promise.resolve();
    return new Promise((resolve) => handleProducerWaiters.add(resolve));
  }

  async function withHandleProducer<Result>(action: () => Promise<Result>): Promise<Result> {
    assertUsable();
    activeHandleProducers += 1;
    try {
      return await action();
    } finally {
      releaseHandleProducer();
    }
  }

  function checkSignal(signal: AbortSignal): void {
    if (!signal.aborted) return;
    assertUsable();
    clientFail(
      "oaath_client_decision_unavailable",
      "authorization wait was stopped",
      "authorization_aborted",
    );
  }

  async function abortable<Value>(
    work: Promise<Value>,
    signal: AbortSignal = cancellation.signal,
  ): Promise<Value> {
    const failure = () =>
      new OaathClientError(
        closeRequested
          ? "oaath_client_closed"
          : signedOut
            ? "oaath_client_signed_out"
            : "oaath_client_decision_unavailable",
        "authorization wait was stopped",
        "authorization_aborted",
      );
    if (signal.aborted) {
      void work.catch(() => undefined);
      throw failure();
    }
    return new Promise((resolve, reject) => {
      const abort = () => {
        signal.removeEventListener("abort", abort);
        reject(failure());
      };
      signal.addEventListener("abort", abort, { once: true });
      work.then(
        (value) => {
          signal.removeEventListener("abort", abort);
          resolve(value);
        },
        (error) => {
          signal.removeEventListener("abort", abort);
          reject(error);
        },
      );
    });
  }

  async function call(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    signal: AbortSignal = cancellation.signal,
  ): Promise<Record<string, unknown>> {
    if (input.authority.kind !== "issuer")
      return clientFail("oaath_client_internal", "local approval has no issuer transport");
    const headers = new Headers();
    if (body !== undefined) headers.set("content-type", "application/json");
    const request = new Request(`${input.authority.issuer.url}${path}`, {
      method,
      headers,
      signal,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    let response: Response;
    try {
      checkSignal(signal);
      response = await abortable(input.authority.issuer.fetch(request), signal);
    } catch (error) {
      if (error instanceof OaathClientError) throw error;
      return clientFail("oaath_client_issuer_unavailable", "the issuer could not be reached");
    }
    let payload: unknown;
    try {
      payload = await abortable(response.json(), signal);
    } catch (error) {
      if (error instanceof OaathClientError) throw error;
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
    installApproval: Readonly<KernelGrantApproval> | null,
  ): Readonly<OaathGrantHandle> {
    const created = createGrantHandle({
      binding: input.binding,
      request,
      approvedPolicy,
      installApproval,
      record,
      grants: input.grants,
      operations: input.operations,
      walletCallBundles: input.walletCallBundles,
      preparedCallContexts: input.preparedCallContexts,
      chains: input.chains,
      ownerKey: input.ownerKey,
      sessionKey: input.sessionKey,
      invalidation: input.invalidation,
      ownerRevocations: input.ownerRevocations,
      now: input.now,
    });
    handles.push(created);
    return created;
  }

  async function writeContext(
    request: Readonly<PermissionRequest>,
    approvedPolicy: Readonly<GrantPolicy>,
    installApproval: Readonly<KernelGrantApproval> | null,
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

  function pendingResult(
    snapshot: Readonly<PendingSnapshot>,
    status: OaathPendingPermissionResult["status"],
    grant: Readonly<OaathGrantHandle> | null = null,
  ): Readonly<OaathPendingPermissionResult> {
    const { value } = snapshot;
    return Object.freeze({
      requestId: value.phase === "creating" ? null : value.request.requestId,
      matchCode: value.matchCode,
      expiresAt: value.expiresAt,
      status,
      grant,
      recovery: grant
        ? "ready"
        : status === "approved" || status === "unavailable"
          ? "uncertain"
          : null,
    });
  }

  async function pendingStatus(
    snapshot: Readonly<PendingSnapshot>,
  ): Promise<OaathPendingPermissionResult["status"]> {
    if (snapshot.value.phase === "creating") return "unavailable";
    const { request } = snapshot.value;
    const state = await call("POST", "/authorization/resume", { requestId: request.requestId });
    try {
      if (
        state.requestId !== request.requestId ||
        state.redirectUri !== input.binding.redirectUri ||
        typeof state.requestedScope !== "string" ||
        JSON.stringify(
          parsePermissionRequest({
            ...JSON.parse(state.requestedScope),
            requestId: request.requestId,
          }),
        ) !== JSON.stringify(request)
      )
        throw new Error();
      if (state.decision !== null) {
        const decision = exactClientRecord(
          state.decision,
          ["outcome", "decidedAt"],
          "pending decision",
          new WeakSet(),
        );
        if (
          decision.outcome !== "approved" &&
          decision.outcome !== "rejected" &&
          decision.outcome !== "withdrawn"
        )
          throw new Error();
        return decision.outcome;
      }
      if (typeof state.expired !== "boolean") throw new Error();
      return state.expired ? "expired" : "pending";
    } catch {
      return clientFail(
        "oaath_client_state_conflict",
        "pending authorization does not match the issuer",
        "pending_authorization_mismatch",
      );
    }
  }

  async function redeem(
    snapshot: Readonly<PendingSnapshot>,
    code: string | null,
    signal = cancellation.signal,
  ): Promise<Readonly<PendingSnapshot>> {
    let current = snapshot;
    const requestId = current.value.request.requestId;
    if (current.value.phase === "pending") {
      if (code === null) return clientFail("oaath_client_internal", "a released code is required");
      checkSignal(signal);
      current = await pending.write(current, { ...current.value, phase: "consuming" });
      const consumed = await call(
        "POST",
        "/authorization/codes/consume",
        { code, codeVerifier: current.value.verifier, redirectUri: input.binding.redirectUri },
        signal,
      );
      if (text(consumed, "requestId") !== requestId)
        return clientFail("oaath_client_state_conflict", "code named another request");
      current = await pending.write(current, {
        ...current.value,
        phase: "claimable",
        artifactId: text(consumed, "artifactId"),
      });
    }
    if (current.value.phase === "claimable") {
      checkSignal(signal);
      current = await pending.write(current, { ...current.value, phase: "claiming" });
      const claimed = await call(
        "POST",
        `/authorization/artifacts/${encodeURIComponent(current.value.artifactId!)}/claim`,
        undefined,
        signal,
      );
      if (text(claimed, "requestId") !== requestId)
        return clientFail("oaath_client_state_conflict", "artifact named another request");
      current = await pending.write(current, {
        ...current.value,
        phase: "claimed",
        artifact: text(claimed, "artifact"),
      });
    }
    return current;
  }

  async function finishPending(
    snapshot: Readonly<PendingSnapshot>,
  ): Promise<Readonly<OaathGrantHandle>> {
    if (snapshot.value.phase !== "claimed" && snapshot.value.phase !== "settled")
      return clientFail(
        "oaath_client_decision_unavailable",
        "one-time authorization redemption is uncertain",
        "authorization_redemption_uncertain",
      );
    const grant = await applyArtifact(
      snapshot.value.request,
      JSON.parse(snapshot.value.artifact!),
      true,
    );
    if (snapshot.value.phase !== "settled") {
      await pending
        .write(snapshot, { ...snapshot.value, phase: "settled" })
        .catch((error: unknown) => {
          if (
            !(error instanceof OaathClientError) ||
            error.source !== "pending_authorization_conflict"
          )
            throw error;
        });
    }
    return grant;
  }

  async function resumePendingPermissionWork(): Promise<Readonly<OaathPendingPermissionResult> | null> {
    assertUsable();
    if (input.authority.kind !== "issuer") return null;
    let snapshot = await pending.read();
    if (snapshot === null) return null;
    const status = await pendingStatus(snapshot);
    if (status !== "approved") return pendingResult(snapshot, status);
    const context = await input.contexts.read(input.binding.bindingId);
    if (context && parseClientContext(context).grantId === snapshot.value.request.requestId) {
      const grant = await resumeWork();
      if (grant) return pendingResult(snapshot, status, grant);
    }
    if (snapshot.value.phase === "consuming" || snapshot.value.phase === "claiming")
      return pendingResult(snapshot, status);
    try {
      let code: string | null = null;
      if (snapshot.value.phase === "pending") {
        const released = await call(
          "GET",
          `/authorization/requests/${encodeURIComponent(snapshot.value.request.requestId)}/code`,
        );
        if (released.outcome !== "approved")
          return clientFail(
            "oaath_client_state_conflict",
            "approval pickup contradicted its decision",
          );
        code = text(released, "code");
      }
      snapshot = await redeem(snapshot, code);
      return pendingResult(snapshot, "approved", await finishPending(snapshot));
    } catch (error) {
      if (
        error instanceof OaathClientError &&
        (error.source === "pending_authorization_conflict" || error.source === "relay_expired")
      )
        return pendingResult(snapshot, "approved");
      throw error;
    }
  }

  async function withdrawPendingPermissionWork(): Promise<Readonly<OaathPendingPermissionResult> | null> {
    assertUsable();
    if (input.authority.kind !== "issuer") return null;
    const snapshot = await pending.read();
    if (snapshot === null) return null;
    if (snapshot.value.phase === "creating") return pendingResult(snapshot, "unavailable");
    const response = await call(
      "POST",
      `/authorization/requests/${encodeURIComponent(snapshot.value.request.requestId)}/withdraw`,
      {},
    );
    if (
      response.requestId !== snapshot.value.request.requestId ||
      !["withdrawn", "approved", "rejected", "expired"].includes(String(response.outcome))
    )
      return clientFail("oaath_client_issuer_unavailable", "withdrawal response is invalid");
    return pendingResult(snapshot, response.outcome as OaathPendingPermissionResult["status"]);
  }

  async function authorizeAtIssuer(
    scope: PermissionScope,
    onPending: OaathRequestPermissionInput["onPending"],
    signal: AbortSignal,
  ): Promise<Readonly<PendingSnapshot>> {
    if (input.authority.kind !== "issuer")
      return clientFail("oaath_client_internal", "local approval has no issuer transport");
    const previous = await pending.read();
    if (previous !== null && previous.value.phase !== "settled") {
      const status = await pendingStatus(previous);
      if (status !== "withdrawn" && status !== "rejected" && status !== "expired")
        return clientFail(
          "oaath_client_state_conflict",
          "resume or withdraw the retained permission request first",
          "authorization_pending",
        );
    }
    checkSignal(signal);
    let snapshot = await pending.write(previous, {
      phase: "creating",
      request: parsePermissionRequest({ ...scope, requestId: crypto.randomUUID() }),
      verifier: newCodeVerifier(),
      matchCode: null,
      expiresAt: scope.expiresAt * 1_000,
      artifactId: null,
      artifact: null,
    });
    const created = await call(
      "POST",
      "/authorization/requests",
      {
        redirectUri: input.binding.redirectUri,
        codeChallenge: deriveCodeChallenge(snapshot.value.verifier),
        requestedScope: JSON.stringify(scope),
      },
      signal,
    );
    const requestId = text(created, "requestId");
    if (
      typeof created.matchCode !== "string" ||
      !/^[A-Za-z0-9_-]{8}$/u.test(created.matchCode) ||
      typeof created.expiresAt !== "number" ||
      !Number.isSafeInteger(created.expiresAt)
    )
      return clientFail("oaath_client_issuer_unavailable", "authorization metadata is invalid");
    snapshot = await pending.write(snapshot, {
      ...snapshot.value,
      phase: "pending",
      request: parsePermissionRequest({ ...scope, requestId }),
      matchCode: created.matchCode,
      expiresAt: created.expiresAt,
    });
    let authorized: unknown;
    try {
      checkSignal(signal);
      await abortable(
        Promise.resolve(
          onPending?.(
            Object.freeze({
              requestId,
              matchCode: created.matchCode,
              expiresAt: created.expiresAt,
            }),
          ),
        ),
        signal,
      );
      checkSignal(signal);
      authorized = await abortable(
        input.authority.authorization.authorize({
          requestId,
          redirectUri: input.binding.redirectUri,
          expiresAt: created.expiresAt,
          signal,
        }),
        signal,
      );
    } catch (error) {
      if (error instanceof OaathClientError) throw error;
      return clientFail(
        "oaath_client_decision_unavailable",
        "the owner decision could not be obtained",
      );
    }
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
    return redeem(snapshot, code, signal);
  }

  async function requestPermissionWork(value: unknown): Promise<Readonly<OaathGrantHandle>> {
    assertUsable();
    const context: CaptureContext = new WeakSet();
    const fail = (message: string): never => clientFail("oaath_client_input_invalid", message);
    const record = captureRecord(value, "requestPermission input", context, fail);
    exactCapturedRecord(
      record,
      [
        "chainScope",
        "permissions",
        "expiresIn",
        "perChainOperationLimit",
        ...(Object.hasOwn(record, "onPending") ? ["onPending"] : []),
        ...(Object.hasOwn(record, "signal") ? ["signal"] : []),
      ],
      "requestPermission input",
      fail,
    );
    const onPending =
      record.onPending === undefined
        ? undefined
        : clientCapability<NonNullable<OaathRequestPermissionInput["onPending"]>>(
            record.onPending,
            "onPending",
          );
    if (record.signal !== undefined && !(record.signal instanceof AbortSignal))
      return fail("signal must be an AbortSignal");
    const signal =
      record.signal === undefined
        ? cancellation.signal
        : AbortSignal.any([cancellation.signal, record.signal]);
    if (record.chainScope !== "all") {
      return clientFail("oaath_client_input_invalid", "chainScope must be all in 0.1.0");
    }
    const requestedAt = input.now();
    const expiresAt = requestedAt + safeCount(record.expiresIn, "expiresIn", MAX_EXPIRES_IN);
    const policy = policyFromInput(
      record.permissions,
      requestedAt,
      expiresAt,
      operationLimitFromInput(record.perChainOperationLimit, context),
      context,
    );
    const scope: PermissionScope = Object.freeze({
      version: OAATH_PERMISSION_REQUEST_VERSION,
      context: input.binding.context,
      application: input.binding.application,
      chainScope: "all",
      logicalAccount: input.binding.account,
      operatorCredential: input.binding.operatorCredential,
      policy,
      requestedAt,
      expiresAt,
      sessionSigner: input.sessionSigner,
    });

    let request: Readonly<PermissionRequest>;
    let artifact: unknown;
    if (input.authority.kind === "local") {
      request = parsePermissionRequest({ ...scope, requestId: globalThis.crypto.randomUUID() });
      try {
        artifact = await input.authority.approve(request);
      } catch (error) {
        if (error instanceof OaathClientError) throw error;
        return clientFail(
          "oaath_client_decision_unavailable",
          "the wallet approval could not be obtained",
        );
      }
    } else {
      return finishPending(await authorizeAtIssuer(scope, onPending, signal));
    }
    return applyArtifact(request, artifact);
  }

  async function applyArtifact(
    request: Readonly<PermissionRequest>,
    artifact: unknown,
    recover = false,
  ): Promise<Readonly<OaathGrantHandle>> {
    assertUsable();
    let decision: Readonly<PermissionDecision>;
    let installApproval: Readonly<KernelGrantApproval> | null = null;
    try {
      // An approval artifact carries the replayable Kernel install approval
      // beside the decision; the decision's own capabilityHash binds it below,
      // so the two cannot be mixed across requests or capabilities.
      if (artifact !== null && typeof artifact === "object" && "installApproval" in artifact) {
        const { installApproval: rawApproval, ...decisionValue } = artifact as Record<
          string,
          unknown
        >;
        installApproval = parseKernelGrantApproval(rawApproval, request.logicalAccount);
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
      kernelGrantCapabilityHash(installApproval) !== decision.capabilityHash
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
    let stored: GrantStoreRecord;
    try {
      stored = await persistGrant(active, null);
    } catch (error) {
      if (
        !recover ||
        !(error instanceof OaathClientError) ||
        error.source !== "grant_store_conflict"
      )
        throw error;
      const existing = await input.grants.get(active.identity.grantId);
      if (
        !existing ||
        existing.value.state !== "active" ||
        !sameGrantIdentity(existing.value.identity, active.identity) ||
        existing.value.approval.capabilityHash !== decision.capabilityHash
      )
        throw error;
      stored = existing;
    }
    await writeContext(request, approvedPolicy, installApproval);
    return handle(stored, request, approvedPolicy, installApproval);
  }

  async function resumeWork(): Promise<Readonly<OaathGrantHandle> | null> {
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
    if (JSON.stringify(context.request.context) !== JSON.stringify(input.binding.context)) {
      return clientFail(
        "oaath_client_state_conflict",
        "the reviewed request belongs to another workspace/account context",
        "workspace_account_context_mismatch",
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
    if (!sameSessionSigner(context.request.sessionSigner, input.sessionSigner)) {
      return clientFail(
        "oaath_client_state_conflict",
        "the current session signer does not match the reviewed Grant",
        "session_signer_binding_mismatch",
      );
    }

    // Fresh relay authentication. `relay_not_found` means the relay no longer
    // retains the authorization request, which says nothing about authority; an
    // authentication refusal fails closed above inside `call`.
    let state: Record<string, unknown> | null = null;
    try {
      if (input.authority.kind === "issuer")
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
    const resumesOperations =
      record.value.state === "active" ||
      record.value.state === "revoking" ||
      record.value.state === "revoked" ||
      (record.value.state === "expired" &&
        (record.value.terminal.from === "active" || record.value.terminal.from === "revoking"));
    if (!resumesOperations) return null;
    return handle(record, context.request, context.approvedPolicy, context.installApproval);
  }

  async function signOut(): Promise<void> {
    if (closed) clientFail("oaath_client_closed", "connection is closed");
    signedOut = true;
    cancellation.abort();
    if (input.authority.kind !== "issuer" || !input.authority.issuer.signOut) return;
    try {
      await input.authority.issuer.signOut();
    } catch (error) {
      return mapClientFailure(error, "issuer sign-out failed");
    }
  }

  function requestPermission(value: unknown): Promise<Readonly<OaathGrantHandle>> {
    return withHandleProducer(() => requestPermissionWork(value));
  }

  function resume(): Promise<Readonly<OaathGrantHandle> | null> {
    return withHandleProducer(resumeWork);
  }

  return Object.freeze({
    binding: input.binding,
    requestPermission,
    resume,
    resumePendingPermission: () => withHandleProducer(resumePendingPermissionWork),
    withdrawPendingPermission: () => withHandleProducer(withdrawPendingPermissionWork),
    signOut,
    async close(): Promise<void> {
      if (closed) return;
      closeRequested = true;
      cancellation.abort();
      const active =
        closing ??
        (async () => {
          await waitForHandleProducers();
          const failures: unknown[] = [];
          for (const created of [...handles]) {
            await created
              .close()
              .then(() => {
                const index = handles.indexOf(created);
                if (index >= 0) handles.splice(index, 1);
              })
              .catch((error: unknown) => failures.push(error));
          }
          for (const owned of closeResources) {
            if (owned.closed) continue;
            await Promise.resolve()
              .then(() => owned.resource.close())
              .then(() => {
                owned.closed = true;
              })
              .catch((error: unknown) => failures.push(error));
          }
          const failure = failures[0];
          if (failure !== undefined) {
            return mapClientFailure(failure, "connection cleanup is incomplete");
          }
          closed = true;
        })();
      closing = active;
      try {
        await active;
      } finally {
        if (closing === active) closing = null;
      }
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
  // may be, including the loopback development exception the service-approved realm
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
