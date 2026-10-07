/**
 * connect, requestPermission, resume, signOut, and close.
 *
 * Every approval realm obtains the owner's decision for the reviewed request
 * (in-process for a wallet, through the portal for OAuth) and hands it here.
 * Protocol application and persistence are shared:
 *
 * ```text
 * requestPermission  the reviewed request -> the realm's approval
 *                    -> applyPermissionDecision  (protocol owns the binding)
 *                    -> activate + persist       (GrantStore owns durability)
 * resume             the durable Grant is authoritative for authority
 * ```
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  advanceGrant,
  applyPermissionDecision,
  type CaptureContext,
  captureAddress,
  captureDenseArray,
  captureRecord,
  createGrantFromPermissionRequest,
  exactCapturedRecord,
  type Grant,
  type GrantPolicy,
  OAATH_GRANT_POLICY_VERSION,
  OAATH_PERMISSION_REQUEST_VERSION,
  type PermissionDecision,
  type PermissionRequest,
  parseGrantPolicy,
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
import { clientFail, exactClientRecord, mapClientFailure, OaathClientError } from "./errors.js";
import {
  createGrantHandle,
  type OaathCapabilityInvalidationCapability,
  type OaathChainCapability,
  type OaathGrantHandle,
} from "./grant-handle.js";

const MAX_PERMISSIONS = 16;
const MAX_EXPIRES_IN = 86_400;
const MAX_OPERATION_COUNT = 2 ** 32 - 1;
const MAX_UINT48 = 2 ** 48 - 1;

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

export interface OaathConnection {
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

export interface CreateConnectionInput {
  readonly binding: Readonly<OaathBinding>;
  /** The realm's approval: the owner's decision for exactly the reviewed request. */
  readonly approve: LocalPermissionAuthorization;
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
  readonly now: () => number;
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
            target: captureAddress(
              call.target,
              `permission ${index} call ${callIndex} target`,
              (message) => clientFail("oaath_client_input_invalid", message),
            ),
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

/** One captured `requestPermission` input: the canonical policy and lifetime. */
export interface CapturedPermissionInput {
  readonly policy: Readonly<GrantPolicy>;
  /** Unix seconds. */
  readonly requestedAt: number;
  /** Exclusive Grant expiry, Unix seconds. */
  readonly expiresAt: number;
}

/**
 * The one owner of `requestPermission` input: every approval realm builds the
 * same policy from the same application input.
 */
export function capturePermissionInput(
  value: unknown,
  requestedAt: number,
): Readonly<CapturedPermissionInput> {
  const context: CaptureContext = new WeakSet();
  const fail = (message: string): never => clientFail("oaath_client_input_invalid", message);
  const record = captureRecord(value, "requestPermission input", context, fail);
  exactCapturedRecord(
    record,
    ["chainScope", "permissions", "expiresIn", "perChainOperationLimit"],
    "requestPermission input",
    fail,
  );
  if (record.chainScope !== "all") {
    return clientFail("oaath_client_input_invalid", "chainScope must be all in 0.1.0");
  }
  const expiresAt = requestedAt + safeCount(record.expiresIn, "expiresIn", MAX_EXPIRES_IN);
  const policy = policyFromInput(
    record.permissions,
    requestedAt,
    expiresAt,
    operationLimitFromInput(record.perChainOperationLimit, context),
    context,
  );
  return Object.freeze({ policy, requestedAt, expiresAt });
}

/**
 * Applies an approval an external realm already obtained for exactly this
 * connection's binding (the OAuth popup), through the same protocol
 * application, capability binding, and persistence as every other approval.
 * Internal: the composing realm calls it; applications never do.
 */
const approvedAdopters = new WeakMap<
  object,
  (request: Readonly<PermissionRequest>, artifact: unknown) => Promise<Readonly<OaathGrantHandle>>
>();

export function adoptApprovedPermission(
  connection: Readonly<OaathConnection>,
  request: Readonly<PermissionRequest>,
  artifact: unknown,
): Promise<Readonly<OaathGrantHandle>> {
  const adopt = approvedAdopters.get(connection);
  if (!adopt) return clientFail("oaath_client_internal", "the connection adopts no approvals");
  return adopt(request, artifact);
}

/** A wrapper connection adopts through the connection it wraps. */
export function forwardApprovedPermission(
  wrapper: Readonly<OaathConnection>,
  inner: Readonly<OaathConnection>,
): void {
  const adopt = approvedAdopters.get(inner);
  if (adopt) approvedAdopters.set(wrapper, adopt);
}

export function createConnection(
  input: Readonly<CreateConnectionInput>,
): Readonly<OaathConnection> {
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

  async function requestPermissionWork(value: unknown): Promise<Readonly<OaathGrantHandle>> {
    assertUsable();
    const { policy, requestedAt, expiresAt } = capturePermissionInput(value, input.now());
    const request = parsePermissionRequest({
      version: OAATH_PERMISSION_REQUEST_VERSION,
      requestId: globalThis.crypto.randomUUID(),
      context: input.binding.context,
      application: input.binding.application,
      chainScope: "all",
      logicalAccount: input.binding.account,
      operatorCredential: input.binding.operatorCredential,
      policy,
      requestedAt,
      expiresAt,
      sessionSigner: null,
    });
    let artifact: unknown;
    try {
      artifact = await input.approve(request);
    } catch (error) {
      if (error instanceof OaathClientError) throw error;
      return clientFail(
        "oaath_client_decision_unavailable",
        "the owner approval could not be obtained",
      );
    }
    return applyArtifact(request, artifact);
  }

  async function applyArtifact(
    request: Readonly<PermissionRequest>,
    artifact: unknown,
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
    const stored = await persistGrant(active, null);
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
    if (context.request.sessionSigner !== null) {
      return clientFail(
        "oaath_client_state_conflict",
        "the current session signer does not match the reviewed Grant",
        "session_signer_binding_mismatch",
      );
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
    // Every read above awaited: a Connection closed meanwhile returns nothing.
    assertUsable();
    return handle(record, context.request, context.approvedPolicy, context.installApproval);
  }

  async function signOut(): Promise<void> {
    if (closed) clientFail("oaath_client_closed", "connection is closed");
    // Realms hold no issuer session: signing out only stops this connection.
    signedOut = true;
  }

  function requestPermission(value: unknown): Promise<Readonly<OaathGrantHandle>> {
    return withHandleProducer(() => requestPermissionWork(value));
  }

  function resume(): Promise<Readonly<OaathGrantHandle> | null> {
    return withHandleProducer(resumeWork);
  }

  const connection: Readonly<OaathConnection> = Object.freeze({
    binding: input.binding,
    requestPermission,
    resume,
    signOut,
    async close(): Promise<void> {
      if (closed) return;
      closeRequested = true;
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
  approvedAdopters.set(connection, (request, artifact) =>
    withHandleProducer(() => {
      // The adopted request must be this binding's, exactly as a locally
      // composed one would be.
      if (
        JSON.stringify(request.context) !== JSON.stringify(input.binding.context) ||
        JSON.stringify(request.application) !== JSON.stringify(input.binding.application) ||
        JSON.stringify(request.logicalAccount) !== JSON.stringify(input.binding.account) ||
        JSON.stringify(request.operatorCredential) !==
          JSON.stringify(input.binding.operatorCredential) ||
        request.sessionSigner !== null
      )
        return clientFail(
          "oaath_client_state_conflict",
          "the approved request belongs to another binding",
          "approved_request_binding_mismatch",
        );
      return applyArtifact(request, artifact);
    }),
  );
  return connection;
}
