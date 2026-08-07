/**
 * The application-facing handle for one active Grant.
 *
 * Authority state is not owned here: `@oaath/protocol` owns the Grant aggregate
 * and its transitions, `GrantStore` owns durability, and this handle only reads
 * the current record and composes the runtime path for one request:
 *
 * ```text
 * sendCalls  capability diagnosis
 *            -> session coverage from the approved policy
 *            -> scope denial unless conclusively covered (before probe, quote,
 *               journal, signature, and send; never an owner fallback)
 *            -> bundler probe
 *            -> decideExecution (pre-sign; no key, no prepared operation)
 *            -> createKernelRuntime for the session authority
 *            -> prepareOperation through the runner (durable before any send)
 *            -> the caller-supplied submission capability
 *            -> observation
 * ```
 *
 * `sendCalls` composes only session authority. Owner authority is wider than
 * the session policy the owner approved, so no coverage outcome — uncovered,
 * unreadable, or missing usage evidence — may select it; those fail closed
 * with `oaath_client_scope_denied`. The owner runtime remains only for account
 * identity binding and explicit root lifecycle work.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  advanceGrant,
  type CaptureContext,
  type ChainPermissionEvidence,
  captureDenseArray,
  evaluateGrantPolicyCoverage,
  type FinalizedOperation,
  type Grant,
  type GrantPolicy,
  type GrantPolicyCoverageResult,
  type GrantState,
  type GrantTransition,
  type OperationIdentity,
  type OperationKind,
  type PermissionRequest,
  parseOperationIdentity,
} from "@oaath/protocol";
import {
  diagnoseKernelCapability,
  type KernelCapability,
  kernelKeyCapability,
} from "../kernel/capabilities.js";
import { createKernelRuntime } from "../kernel/create-kernel-runtime.js";
import { sameInstall } from "../kernel/internal.js";
import { ownerOperator } from "../kernel/operator/owner.js";
import { sessionOperator } from "../kernel/operator/session.js";
import type { KernelAllChainApproval } from "../kernel/permission/materialize.js";
import type { KernelPolicyProfile, KernelRuntime, KeyProfile } from "../kernel/types.js";
import {
  captureKernelV4Installs,
  encodeKernelV4EnableSignature,
  encodeKernelV4PermissionUninstallCalls,
  type KernelV4AccountDescriptor,
  type KernelV4AccountReadCapability,
  type KernelV4Call,
  type KernelV4UserOperationGas,
  kernelV4Deployment,
} from "../kernel-v4.js";
import {
  createOperationObserver,
  type OperationObserver,
  type OperationObserverCapabilities,
} from "../operation-observer.js";
import {
  createOperationRunner,
  type OperationObserveResult,
  type OperationRunResult,
  type OperationStartResult,
  type OperationSubmissionSession,
} from "../operation-runner.js";
import { deriveOperationId, type PreparedUserOperation } from "../prepared-user-operation.js";
import type { WalletCallBundleStore } from "../provider/bundle-store.js";
import { type OaathBundlerProbeCapability, probeBundlerCapability } from "../routing/bundler.js";
import { feePayerDescriptor, type OaathSessionCoverage } from "../routing/capabilities.js";
import { decideExecution } from "../routing/decide.js";
import type {
  OaathExecutionDecision,
  OaathExecutionRoute,
  OaathExecutionSigner,
  OaathFeePayerDescriptor,
} from "../routing/types.js";
import {
  type GrantStore,
  type GrantStoreRecord,
  OperationStore,
  type OperationStoreAdapter,
  type OperationStoreKey,
  type OperationStoreRecord,
} from "../store.js";
import type { OaathBinding } from "./binding.js";
import { clientCapability, clientFail, exactClientRecord, mapClientFailure } from "./errors.js";
import {
  createOperationHandle,
  type OaathOperationHandle,
  operationOutcome,
} from "./operation-handle.js";

const SUBMISSION_TIMEOUT_MS = 30_000;
const MAX_CALLS = 64;
const USER_OPERATION_HASH = /^0x[0-9a-f]{64}$/u;
const PROVIDER_ACCOUNT = /^0x[0-9a-f]{40}$/u;

export type OaathProviderOperationPointer = Readonly<{
  identity: Readonly<OperationIdentity>;
}>;

export interface OaathProviderOperationPublication {
  readonly reserve: (operation: OaathProviderOperationPointer) => Promise<void>;
  readonly confirm: (operation: OaathProviderOperationPointer) => Promise<void>;
  readonly abandon: (operation: OaathProviderOperationPointer) => Promise<void>;
}

function sameProviderOperationPointer(
  left: OaathProviderOperationPointer,
  right: OaathProviderOperationPointer,
): boolean {
  return (
    left.identity.kind === right.identity.kind &&
    left.identity.grantId === right.identity.grantId &&
    left.identity.chainId === right.identity.chainId &&
    left.identity.entryPoint === right.identity.entryPoint &&
    left.identity.account === right.identity.account &&
    left.identity.nonce === right.identity.nonce &&
    left.identity.userOperationHash === right.identity.userOperationHash &&
    left.identity.requestHash === right.identity.requestHash
  );
}

const GRANT_PROVIDER_PORTS = new WeakMap<object, Readonly<OaathGrantProviderPort>>();

export interface OaathCallInput {
  readonly target: `0x${string}`;
  /** Canonical decimal native value; `"0"` for a plain call. */
  readonly value: string;
  readonly data: `0x${string}`;
}

export interface OaathSendCallsInput {
  readonly chain: number;
  readonly calls: readonly Readonly<OaathCallInput>[];
}

/** The exact snapshot a submission transport receives. It replaces nothing. */
export interface OaathSubmissionRequest {
  readonly prepared: Readonly<PreparedUserOperation>;
  readonly signature: `0x${string}`;
  readonly route: OaathExecutionRoute;
  readonly feePayer: Readonly<OaathFeePayerDescriptor> | null;
}

/**
 * The caller-supplied send boundary. `open` binds the exact snapshot into a
 * zero-argument session; the SDK persists `submission_attempted` before the
 * session is opened and never opens a second one for the same identity.
 */
export interface OaathSubmissionCapability {
  readonly open: (request: Readonly<OaathSubmissionRequest>) => Promise<unknown>;
}

export interface OaathQuoteRequest {
  readonly chainId: number;
  readonly kind: OperationKind;
  readonly signer: OaathExecutionSigner;
  readonly account: `0x${string}`;
  readonly calls: readonly Readonly<KernelV4Call>[];
}

/** Nonce sequence and gas are deployment facts; the SDK never invents them. */
export interface OaathQuoteCapability {
  readonly quote: (request: Readonly<OaathQuoteRequest>) => Promise<unknown>;
}

export interface OaathChainCapability {
  readonly chainId: number;
  readonly reads: KernelV4AccountReadCapability;
  readonly observation: OperationObserverCapabilities;
  readonly bundler: OaathBundlerProbeCapability;
  readonly submission: OaathSubmissionCapability;
  readonly quote: OaathQuoteCapability["quote"];
  /**
   * Finalized per-chain usage evidence for policy coverage, or `null` when the
   * deployment provides none. Absent evidence is inconclusive, never "unused".
   */
  readonly usage:
    | ((request: Readonly<{ grantId: string; chainId: number }>) => Promise<unknown>)
    | null;
  readonly feePayer: Readonly<OaathFeePayerDescriptor> | null;
}

/** Proves the replayable approval capability can no longer authorize anything. */
export interface OaathCapabilityInvalidationCapability {
  readonly invalidateCapability: (
    request: Readonly<{ grantId: string; capabilityHash: `0x${string}` }>,
  ) => Promise<unknown>;
}

export interface OaathGrantHandle {
  readonly state: GrantState;
  readonly expiresAt: number;
  /**
   * The Grant's smart account address on one supported chain. It is derived
   * from the owner's initial packages through the chain's own factory reads —
   * never asserted — and CREATE2 makes it the same address on every supported
   * chain. Public identity only: holding it authorizes nothing.
   */
  readonly account: (chain: unknown) => Promise<`0x${string}`>;
  readonly sendCalls: (input: unknown) => Promise<Readonly<OaathOperationHandle>>;
  readonly revoke: () => Promise<void>;
  readonly close: () => Promise<void>;
}

/** Internal provider capability. It is deliberately absent from the package root. */
export interface OaathGrantProviderPort {
  readonly providerScopeId: string;
  readonly grantId: string;
  readonly walletCallBundles: WalletCallBundleStore;
  readonly now: () => number;
  readonly account: OaathGrantHandle["account"];
  readonly startCalls: (
    input: unknown,
    publication: OaathProviderOperationPublication,
  ) => Promise<Readonly<OaathOperationHandle>>;
  readonly recoverOperation: (input: unknown) => Promise<Readonly<OaathProviderOperationRecovery>>;
  readonly abandonPreparedOperation: (
    input: unknown,
  ) => Promise<Readonly<OaathProviderOperationRecovery>>;
}

export type OaathProviderOperationRecovery =
  | Readonly<{ status: "absent" }>
  | Readonly<{ status: "abandoned" }>
  | Readonly<{ status: "prepared" }>
  | Readonly<{ status: "request_conflict" }>
  | Readonly<{ status: "observable"; operation: Readonly<OaathOperationHandle> }>;

/** Resolves only handles minted by this module; structural lookalikes authorize nothing. */
export function grantProviderPort(handle: unknown): Readonly<OaathGrantProviderPort> {
  if (handle === null || typeof handle !== "object") {
    return clientFail("oaath_client_capability_invalid", "Grant handle is not genuine");
  }
  const port = GRANT_PROVIDER_PORTS.get(handle);
  if (!port) return clientFail("oaath_client_capability_invalid", "Grant handle is not genuine");
  return port;
}

export interface CreateGrantHandleInput {
  readonly binding: Readonly<OaathBinding>;
  readonly request: Readonly<PermissionRequest>;
  readonly approvedPolicy: Readonly<GrantPolicy>;
  /**
   * The owner's replayable install approval the decision's capabilityHash
   * binds, or null for a Grant persisted before approvals carried one. The
   * first covered execution on a chain spends it in enable-replayable mode;
   * without it no unmaterialized chain can execute.
   */
  readonly installApproval: Readonly<KernelAllChainApproval> | null;
  readonly record: GrantStoreRecord;
  readonly grants: GrantStore;
  readonly operations: OperationStoreAdapter;
  readonly walletCallBundles: WalletCallBundleStore;
  readonly chains: ReadonlyMap<number, Readonly<OaathChainCapability>>;
  readonly ownerKey: Readonly<KeyProfile>;
  readonly sessionKey: Readonly<KeyProfile>;
  readonly invalidation: Readonly<OaathCapabilityInvalidationCapability>;
  readonly now: () => number;
}

const GAS_KEYS: readonly string[] = Object.freeze([
  "callGasLimit",
  "verificationGasLimit",
  "preVerificationGas",
  "maxFeePerGas",
  "maxPriorityFeePerGas",
]);

const CHAIN_KEYS: readonly string[] = Object.freeze([
  "chainId",
  "reads",
  "observation",
  "bundler",
  "submission",
  "quote",
  "usage",
  "feePayer",
]);

function unsupported(source: string): never {
  return clientFail("oaath_client_capability_unsupported", "capability is unavailable", source);
}

function requireKernelCapability(chainId: number, capability: KernelCapability): void {
  let fact: ReturnType<typeof diagnoseKernelCapability>;
  try {
    fact = diagnoseKernelCapability({ chainId, capability });
  } catch (error) {
    mapClientFailure(error, "Kernel capability could not be diagnosed");
  }
  if (fact.status !== "available") unsupported(`${capability}:${fact.reason}`);
}

/**
 * Captures a capability object whose required members must all be functions.
 * Narrowing follows the check, and the object itself is handed on unchanged so
 * its own owner (`createKernelRuntime`, `createOperationObserver`,
 * `probeBundlerCapability`) captures it again at its boundary.
 */
function capabilityObject<Capability>(
  value: unknown,
  keys: readonly string[],
  label: string,
  context: CaptureContext,
): Capability {
  const record = exactClientRecord(value, keys, label, context, "oaath_client_capability_invalid");
  for (const key of keys) clientCapability(record[key], `${label} ${key}`);
  return value as Capability;
}

/** Captures one chain capability set exactly; sub-capabilities keep their owners. */
export function captureChainCapability(value: unknown): Readonly<OaathChainCapability> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    CHAIN_KEYS,
    "OAAth chain capability",
    context,
    "oaath_client_capability_invalid",
  );
  const chainId = record.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return clientFail("oaath_client_capability_invalid", "chain capability chainId is invalid");
  }
  return Object.freeze({
    chainId,
    reads: capabilityObject<KernelV4AccountReadCapability>(
      record.reads,
      ["read"],
      "chain reads",
      context,
    ),
    observation: capabilityObject<OperationObserverCapabilities>(
      record.observation,
      ["read", "close"],
      "chain observation",
      context,
    ),
    bundler: capabilityObject<OaathBundlerProbeCapability>(
      record.bundler,
      ["probe"],
      "chain bundler",
      context,
    ),
    submission: capabilityObject<OaathSubmissionCapability>(
      record.submission,
      ["open"],
      "chain submission",
      context,
    ),
    quote: clientCapability<OaathChainCapability["quote"]>(record.quote, "chain quote"),
    usage:
      record.usage === null
        ? null
        : clientCapability<NonNullable<OaathChainCapability["usage"]>>(record.usage, "chain usage"),
    // routing owns the exact fee-payer rules.
    feePayer: feePayerDescriptor(record.feePayer, context, (message) =>
      clientFail("oaath_client_capability_invalid", message),
    ),
  });
}

function captureCalls(value: unknown, context: CaptureContext): readonly Readonly<KernelV4Call>[] {
  const entries = captureDenseArray(value, "calls", context, (message) =>
    clientFail("oaath_client_input_invalid", message),
  );
  if (entries.length < 1 || entries.length > MAX_CALLS) {
    return clientFail("oaath_client_input_invalid", "calls must hold 1 to 64 entries");
  }
  return Object.freeze(
    entries.map((entry, index) => {
      const record = exactClientRecord(
        entry,
        ["target", "value", "data"],
        `call ${index}`,
        context,
      );
      if (
        typeof record.target !== "string" ||
        typeof record.value !== "string" ||
        typeof record.data !== "string"
      ) {
        return clientFail("oaath_client_input_invalid", `call ${index} fields are invalid`);
      }
      // kernel-v4 owns the exact address, value, and calldata rules.
      return Object.freeze({
        target: record.target as `0x${string}`,
        value: record.value,
        data: record.data as `0x${string}`,
      });
    }),
  );
}

function captureProviderRecoveryInput(value: unknown): Readonly<OperationIdentity> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    ["identity"],
    "provider operation recovery",
    context,
    "oaath_client_capability_invalid",
  );
  let identity: Readonly<OperationIdentity>;
  try {
    identity = parseOperationIdentity(record.identity);
  } catch {
    return clientFail(
      "oaath_client_capability_invalid",
      "provider operation recovery identity is invalid",
    );
  }
  if (identity.kind !== "execution" || identity.requestHash === null) {
    return clientFail(
      "oaath_client_capability_invalid",
      "provider operation recovery must name a provider execution",
    );
  }
  return identity;
}

function captureProviderPublication(value: unknown): Readonly<OaathProviderOperationPublication> {
  const record = exactClientRecord(
    value,
    ["reserve", "confirm", "abandon"],
    "provider operation publication",
    new WeakSet(),
    "oaath_client_capability_invalid",
  );
  return Object.freeze({
    reserve: clientCapability<OaathProviderOperationPublication["reserve"]>(
      record.reserve,
      "provider operation reservation",
    ),
    confirm: clientCapability<OaathProviderOperationPublication["confirm"]>(
      record.confirm,
      "provider operation confirmation",
    ),
    abandon: clientCapability<OaathProviderOperationPublication["abandon"]>(
      record.abandon,
      "provider operation abandonment",
    ),
  });
}

/**
 * Maps the approved Grant policy onto Kernel policy hook profiles. This is the
 * one place the two vocabularies meet, and it is deliberately total: an approved
 * constraint with no reviewed hook profile fails closed instead of installing a
 * session that enforces less than the owner approved.
 */
export function deriveSessionPolicyProfiles(
  policy: Readonly<GrantPolicy>,
): readonly KernelPolicyProfile[] {
  // Every approved call maps to exactly one CallPolicy permission carrying that
  // call's own value limit, in the Grant policy's canonical order. No aggregate
  // is computed: a global maximum would install an on-chain allowance on one
  // call that only another call's approval justified.
  const permissions = policy.calls.map((call) => {
    if (call.argumentEquals.length > 0) {
      unsupported("policy_argument_constraint_unsupported");
    }
    return Object.freeze({
      target: call.target,
      selector: call.selector,
      valueLimit: call.valueLimit,
    });
  });
  if (permissions.length === 0) unsupported("policy_has_no_calls");
  if (policy.validUntil === null) unsupported("policy_expiry_unbounded");
  return Object.freeze([
    Object.freeze({ kind: "call" as const, permissions: Object.freeze(permissions) }),
    Object.freeze({
      kind: "expiry" as const,
      validAfter: policy.validAfter.toString(10),
      validUntil: policy.validUntil.toString(10),
    }),
    Object.freeze({
      kind: "operation-limit" as const,
      maximumOperations: policy.perChainOperationLimit.toString(10),
    }),
  ]);
}

function coverageToRouting(result: GrantPolicyCoverageResult): OaathSessionCoverage {
  if (result.status === "covered") return "covered";
  return result.status === "denied" ? "uncovered" : "unreadable";
}

function quoteFields(value: unknown): Readonly<{
  nonceKey: string;
  sequence: string;
  gas: Readonly<KernelV4UserOperationGas>;
}> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    ["nonceKey", "sequence", "gas"],
    "operation quote",
    context,
    "oaath_client_capability_invalid",
  );
  if (typeof record.nonceKey !== "string" || typeof record.sequence !== "string") {
    return clientFail("oaath_client_capability_invalid", "operation quote nonce is invalid");
  }
  const gas = exactClientRecord(
    record.gas,
    GAS_KEYS,
    "operation quote gas",
    context,
    "oaath_client_capability_invalid",
  );
  const fields: Record<string, string> = {};
  for (const key of GAS_KEYS) {
    const field = gas[key];
    if (typeof field !== "string") {
      return clientFail("oaath_client_capability_invalid", "operation quote gas is invalid");
    }
    fields[key] = field;
  }
  // prepareKernelV4UserOperation owns the exact numeric bounds of every field.
  return Object.freeze({
    nonceKey: record.nonceKey,
    sequence: record.sequence,
    gas: Object.freeze({
      callGasLimit: fields.callGasLimit ?? "",
      verificationGasLimit: fields.verificationGasLimit ?? "",
      preVerificationGas: fields.preVerificationGas ?? "",
      maxFeePerGas: fields.maxFeePerGas ?? "",
      maxPriorityFeePerGas: fields.maxPriorityFeePerGas ?? "",
    }),
  });
}

function captureSubmissionSession(value: unknown): Readonly<OperationSubmissionSession> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    ["send", "close"],
    "submission session",
    context,
    "oaath_client_capability_invalid",
  );
  return Object.freeze({
    submit: clientCapability<() => Promise<unknown>>(record.send, "submission session send"),
    close: clientCapability<() => Promise<void>>(record.close, "submission session close"),
  });
}

export function createGrantHandle(
  input: Readonly<CreateGrantHandleInput>,
): Readonly<OaathGrantHandle> {
  let record = input.record;
  let closed = false;
  let closeRequested = false;
  let closing: Promise<void> | null = null;
  let revocationRequested = false;
  let revoking: Promise<void> | null = null;
  let activeExecutions = 0;
  let activeActivities = 0;
  const executionWaiters = new Set<() => void>();
  const activityWaiters = new Set<() => void>();
  const observers = new Map<number, OperationObserver>();
  const handles = new Set<Readonly<OaathOperationHandle>>();

  function assertOpen(): void {
    if (closed || closeRequested) clientFail("oaath_client_closed", "Grant handle is closed");
  }

  function releaseExecution(): void {
    activeExecutions -= 1;
    if (activeExecutions !== 0) return;
    for (const resolve of executionWaiters) resolve();
    executionWaiters.clear();
  }

  function waitForExecutions(): Promise<void> {
    if (activeExecutions === 0) return Promise.resolve();
    return new Promise((resolve) => executionWaiters.add(resolve));
  }

  async function withExecution<Result>(action: () => Promise<Result>): Promise<Result> {
    assertOpen();
    if (revocationRequested) {
      return clientFail(
        "oaath_client_grant_inactive",
        "Grant revocation has started",
        "grant_revocation_requested",
      );
    }
    activeExecutions += 1;
    try {
      return await action();
    } finally {
      releaseExecution();
    }
  }

  function releaseActivity(): void {
    activeActivities -= 1;
    if (activeActivities !== 0) return;
    for (const resolve of activityWaiters) resolve();
    activityWaiters.clear();
  }

  function waitForActivities(): Promise<void> {
    if (activeActivities === 0) return Promise.resolve();
    return new Promise((resolve) => activityWaiters.add(resolve));
  }

  async function withActivity<Result>(action: () => Promise<Result>): Promise<Result> {
    assertOpen();
    activeActivities += 1;
    try {
      return await action();
    } finally {
      releaseActivity();
    }
  }

  function requireExecutionPublication(): void {
    if (closeRequested) clientFail("oaath_client_closed", "Grant handle is closing");
    if (revocationRequested) {
      clientFail(
        "oaath_client_grant_inactive",
        "Grant revocation started before operation publication",
        "grant_revocation_requested",
      );
    }
  }

  function chainCapability(chainId: number): Readonly<OaathChainCapability> {
    const chain = input.chains.get(chainId);
    if (!chain) unsupported("chain_not_configured");
    return chain;
  }

  async function refresh(): Promise<GrantStoreRecord> {
    let current: GrantStoreRecord | undefined;
    try {
      current = await input.grants.get(record.value.identity.grantId);
    } catch (error) {
      return mapClientFailure(error, "Grant record could not be read");
    }
    if (!current) {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant record disappeared",
        "grant_record_absent",
      );
    }
    record = current;
    return current;
  }

  async function commit(
    previous: Readonly<GrantStoreRecord>,
    next: Grant,
  ): Promise<GrantStoreRecord> {
    try {
      const committed = await input.grants.compareAndSwap({
        grantId: previous.value.identity.grantId,
        expectedStoreRevision: previous.storeRevision,
        next,
      });
      if (committed.status === "conflict") {
        if (committed.current !== undefined) record = committed.current;
        return clientFail(
          "oaath_client_state_conflict",
          "another writer advanced the Grant",
          "grant_store_conflict",
        );
      }
      record = committed.record;
      return committed.record;
    } catch (error) {
      return mapClientFailure(error, "Grant transition could not be committed");
    }
  }

  function transition(grant: Grant, change: GrantTransition): Grant {
    try {
      return advanceGrant(grant, change);
    } catch (error) {
      return mapClientFailure(error, "Grant transition is not allowed");
    }
  }

  async function requireActive(): Promise<GrantStoreRecord> {
    const current = await refresh();
    const grant = current.value;
    if (grant.state !== "active") {
      clientFail("oaath_client_grant_inactive", "the Grant is not active", `grant_${grant.state}`);
    }
    if (input.now() >= grant.expiresAt) {
      clientFail("oaath_client_grant_inactive", "the Grant is expired", "grant_expired");
    }
    return current;
  }

  function ownerRuntime(chainId: number): Readonly<KernelRuntime> {
    const chain = chainCapability(chainId);
    try {
      return createKernelRuntime({
        deployment: kernelV4Deployment(chainId),
        operator: ownerOperator({ key: input.ownerKey }),
        reads: chain.reads,
      });
    } catch (error) {
      return mapClientFailure(error, "owner runtime could not be composed");
    }
  }

  function sessionRuntime(chainId: number): Readonly<KernelRuntime> {
    const chain = chainCapability(chainId);
    try {
      return createKernelRuntime({
        deployment: kernelV4Deployment(chainId),
        // The session composition point is opaque here: this handle supplies the
        // key and the policy profiles derived from the approved Grant scope, and
        // never reaches into how the authority is installed.
        operator: sessionOperator({
          key: input.sessionKey,
          policies: deriveSessionPolicyProfiles(input.approvedPolicy),
        }),
        reads: chain.reads,
      });
    } catch (error) {
      return mapClientFailure(error, "session runtime could not be composed");
    }
  }

  /**
   * The account identity is the owner runtime's initial packages, on every chain
   * and for every authority: a session never redefines the account it acts for.
   *
   * The descriptor is bound per send and never cached. A descriptor freezes the
   * account state observed at bind time, so reusing one after the account's first
   * operation deployed it would carry stale factory evidence.
   */
  async function accountDescriptor(chainId: number): Promise<Readonly<KernelV4AccountDescriptor>> {
    const runtime = ownerRuntime(chainId);
    try {
      return await runtime.bindAccount({
        accountIndex: input.binding.account.accountIndex,
        initialPackages: [...runtime.packages],
      });
    } catch (error) {
      return mapClientFailure(error, "Kernel account could not be bound");
    }
  }

  function observer(chainId: number): OperationObserver {
    const cached = observers.get(chainId);
    if (cached) return cached;
    try {
      const created = createOperationObserver(chainCapability(chainId).observation);
      observers.set(chainId, created);
      return created;
    } catch (error) {
      return mapClientFailure(error, "operation observer could not be composed");
    }
  }

  function operationStore(): OperationStore {
    return new OperationStore({
      get: (key: Readonly<OperationStoreKey>) => input.operations.get(key),
      getArchived: (value: Parameters<OperationStoreAdapter["getArchived"]>[0]) =>
        input.operations.getArchived(value),
      compareAndSwap: (value: Parameters<OperationStoreAdapter["compareAndSwap"]>[0]) =>
        input.operations.compareAndSwap(value),
      close: async () => undefined,
    } satisfies OperationStoreAdapter);
  }

  async function sessionCoverage(
    grant: Grant,
    chainId: number,
    calls: readonly Readonly<KernelV4Call>[],
  ): Promise<OaathSessionCoverage> {
    const chain = chainCapability(chainId);
    let usage: unknown = null;
    if (chain.usage) {
      try {
        usage = await chain.usage({ grantId: grant.identity.grantId, chainId });
      } catch {
        // An unavailable usage read is inconclusive, never "unused".
        return "unreadable";
      }
    }
    try {
      return coverageToRouting(
        evaluateGrantPolicyCoverage({
          policy: input.approvedPolicy,
          grantId: grant.identity.grantId,
          chainId,
          evaluatedAt: input.now(),
          calls: calls.map((call) =>
            Object.freeze({ target: call.target, data: call.data, value: call.value }),
          ),
          usage: usage === undefined ? null : usage,
        }),
      );
    } catch {
      // Hostile usage evidence or a call the policy vocabulary cannot express is
      // inconclusive, so the decision table requires owner authority. The send
      // itself still fails closed later if the call is malformed.
      return "unreadable";
    }
  }

  function runner(spec: {
    readonly chainId: number;
    readonly kind: OperationKind;
    readonly runtime: Readonly<KernelRuntime>;
    readonly descriptor: Readonly<KernelV4AccountDescriptor>;
    readonly calls: readonly Readonly<KernelV4Call>[];
    /** The proven authority; a denied decision never reaches a runner. */
    readonly signer: OaathExecutionSigner;
    /**
     * `enable-replayable` spends the owner's install approval on this chain:
     * the prepared operation installs the permission and executes together,
     * and its signature is Kernel's enable envelope rather than a plain
     * session signature.
     */
    readonly mode: "standard" | "enable-replayable";
    readonly installApproval: Readonly<KernelAllChainApproval> | null;
    readonly decision: Readonly<OaathExecutionDecision>;
    readonly terminalBehavior: "replace" | "reuse_same_kind";
    readonly grantId: string;
    readonly requestHash: `0x${string}` | null;
    readonly publication?: Readonly<OaathProviderOperationPublication>;
    readonly authorizeOperation?: (operation: OaathProviderOperationPointer) => Promise<void>;
    readonly abandonOperation?: (operation: OaathProviderOperationPointer) => Promise<void>;
  }): ReturnType<typeof createOperationRunner> {
    const chain = chainCapability(spec.chainId);
    const shared = observer(spec.chainId);
    let reservedOperation: OaathProviderOperationPointer | null = null;
    let publicationConfirmed = false;
    try {
      return createOperationRunner({
        terminalBehavior: spec.terminalBehavior,
        requestHash: spec.requestHash,
        // A scoped store and facades: the realm owns the adapter, the observer,
        // and the caller's transports, so closing one runner never disables
        // another that still has work.
        store: operationStore(),
        observer: {
          observeOperation: (value: unknown) => shared.observeOperation(value),
          close: async () => undefined,
        },
        preparation: {
          prepare: async () => {
            const quote = quoteFields(
              await chain.quote({
                chainId: spec.chainId,
                kind: spec.kind,
                signer: spec.signer,
                account: spec.descriptor.account,
                calls: spec.calls,
              }),
            );
            const fields = {
              grantId: spec.grantId,
              account: spec.descriptor,
              nonceKey: quote.nonceKey,
              sequence: quote.sequence,
              calls: [...spec.calls],
              gas: quote.gas,
            };
            let prepared: PreparedUserOperation;
            if (spec.mode === "enable-replayable") {
              const approval = spec.installApproval;
              if (approval === null) return unsupported("grant_capability_unavailable");
              const packages = captureKernelV4Installs(spec.runtime.packages);
              if (
                approval.account !== spec.descriptor.account ||
                approval.packages.length !== packages.length ||
                !packages.every((install, index) => {
                  const approved = approval.packages[index];
                  return approved !== undefined && sameInstall(install, approved);
                })
              ) {
                return clientFail(
                  "oaath_client_state_conflict",
                  "the install approval does not bind this permission runtime",
                  "kernel_runtime_binding_mismatch",
                );
              }
              prepared = spec.runtime.prepareOperation({
                ...fields,
                kind: spec.kind,
                mode: "enable-replayable",
              });
            } else {
              prepared = spec.runtime.prepareOperation({ kind: spec.kind, ...fields });
            }
            return prepared;
          },
          reserveOperation: async (prepared: PreparedUserOperation) => {
            if (!spec.publication) return;
            if (reservedOperation !== null) {
              return clientFail(
                "oaath_client_internal",
                "the provider operation reservation was invoked more than once",
              );
            }
            const identity = deriveOperationId(prepared, spec.requestHash);
            const exact: OaathProviderOperationPointer = Object.freeze({ identity });
            await spec.publication.reserve(exact);
            reservedOperation = exact;
          },
          authorizeOperation: async (prepared: PreparedUserOperation) => {
            if (!spec.authorizeOperation) return;
            await spec.authorizeOperation(
              Object.freeze({ identity: deriveOperationId(prepared, spec.requestHash) }),
            );
          },
          abandonOperation: async (prepared: PreparedUserOperation) => {
            const exact = Object.freeze({
              identity: deriveOperationId(prepared, spec.requestHash),
            });
            let failure: unknown;
            if (spec.abandonOperation) {
              await spec.abandonOperation(exact).catch((error: unknown) => {
                failure = error;
              });
            }
            if (spec.publication && reservedOperation !== null) {
              if (!sameProviderOperationPointer(reservedOperation, exact)) {
                failure ??= new Error("provider operation abandonment identity mismatch");
              } else {
                await spec.publication.abandon(exact).catch((error: unknown) => {
                  failure ??= error;
                });
              }
            }
            if (failure !== undefined) throw failure;
          },
          confirmOperationPublished: async (prepared: PreparedUserOperation) => {
            if (!spec.publication) return;
            if (
              reservedOperation === null ||
              publicationConfirmed ||
              !sameProviderOperationPointer(reservedOperation, {
                identity: deriveOperationId(prepared, spec.requestHash),
              })
            ) {
              return clientFail(
                "oaath_client_internal",
                "the provider operation publication confirmation is inconsistent",
              );
            }
            await spec.publication.confirm(reservedOperation);
            publicationConfirmed = true;
          },
          close: async () => undefined,
        },
        submission: {
          openSubmission: async (prepared: PreparedUserOperation) => {
            // The authority signs the already-durable snapshot; the route was
            // decided before any signature existed and cannot change it. The
            // enable envelope is minted here, after provider binding and the
            // runner's durable submission-attempt transition, for this exact
            // snapshot and nothing else.
            const userOperationSignature = await spec.runtime.signOperation(prepared);
            let signature = userOperationSignature;
            if (spec.mode === "enable-replayable") {
              const approval = spec.installApproval;
              if (approval === null) return unsupported("grant_capability_unavailable");
              signature = encodeKernelV4EnableSignature({
                nonce: approval.installNonce,
                packages: approval.packages,
                enableSignature: approval.enableSignature,
                userOperationSignature,
              });
            }
            return captureSubmissionSession(
              await chain.submission.open({
                prepared,
                signature,
                route: spec.decision.route,
                feePayer: spec.decision.feePayer,
              }),
            );
          },
          close: async () => undefined,
        },
      });
    } catch (error) {
      return mapClientFailure(error, "operation runner could not be composed");
    }
  }

  function observationOnlyRunner(chainId: number): ReturnType<typeof createOperationRunner> {
    const shared = observer(chainId);
    try {
      return createOperationRunner({
        terminalBehavior: "reuse_same_kind",
        requestHash: null,
        store: operationStore(),
        observer: {
          observeOperation: (value: unknown) => shared.observeOperation(value),
          close: async () => undefined,
        },
        preparation: {
          prepare: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot prepare",
            ),
          reserveOperation: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot reserve publication",
            ),
          authorizeOperation: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot authorize publication",
            ),
          abandonOperation: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot abandon publication",
            ),
          confirmOperationPublished: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot confirm publication",
            ),
          close: async () => undefined,
        },
        submission: {
          openSubmission: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot submit",
            ),
          close: async () => undefined,
        },
      });
    } catch (error) {
      return mapClientFailure(error, "provider observation runner could not be composed");
    }
  }

  async function exactOperation(
    key: Readonly<OperationStoreKey>,
    userOperationHash: `0x${string}`,
  ): Promise<OperationStoreRecord | undefined> {
    const journal = operationStore();
    try {
      return await journal.getExact(key, userOperationHash);
    } catch (error) {
      return mapClientFailure(error, "provider operation history could not be read");
    } finally {
      await journal.close().catch(() => undefined);
    }
  }

  function trackedOperationHandle(
    handleInput: Readonly<Parameters<typeof createOperationHandle>[0]>,
  ): Readonly<OaathOperationHandle> {
    let created: Readonly<OaathOperationHandle>;
    created = createOperationHandle({
      ...handleInput,
      onClosed: () => handles.delete(created),
    });
    handles.add(created);
    return created;
  }

  function observationHandle(
    key: Readonly<OperationStoreKey>,
    record: OperationStoreRecord,
  ): Readonly<OaathOperationHandle> {
    return trackedOperationHandle({
      runner: observationOnlyRunner(key.chainId),
      key,
      kind: "execution",
      timeoutMs: SUBMISSION_TIMEOUT_MS,
      now: input.now,
      initial: Object.freeze({ status: "started" as const, record }),
      observation: chainCapability(key.chainId).observation.read,
      onObserved: (observed: OperationObserveResult) =>
        recordRecoveredMaterialization(record.value.identity.account, observed),
    });
  }

  async function recoverOperationWork(
    value: unknown,
  ): Promise<Readonly<OaathProviderOperationRecovery>> {
    assertOpen();
    const exact = captureProviderRecoveryInput(value);
    if (exact.grantId !== record.value.identity.grantId) {
      return clientFail(
        "oaath_client_state_conflict",
        "provider operation belongs to another Grant",
        "provider_operation_grant_mismatch",
      );
    }
    const key = Object.freeze({
      grantId: exact.grantId,
      chainId: exact.chainId,
      kind: "execution" as const,
    });
    const operationRecord = await exactOperation(key, exact.userOperationHash);
    if (operationRecord === undefined) return Object.freeze({ status: "absent" as const });
    const retained = operationRecord.value.identity;
    if (
      retained.kind !== exact.kind ||
      retained.grantId !== exact.grantId ||
      retained.chainId !== exact.chainId ||
      retained.entryPoint !== exact.entryPoint ||
      retained.account !== exact.account ||
      retained.nonce !== exact.nonce ||
      retained.userOperationHash !== exact.userOperationHash
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "provider operation identity contradicts its durable publication",
        "provider_operation_identity_mismatch",
      );
    }
    if (retained.requestHash !== exact.requestHash) {
      return Object.freeze({ status: "request_conflict" as const });
    }
    if (operationRecord.value.state === "abandoned") {
      await releaseAbandonedMaterialization(exact).catch(() => undefined);
      return Object.freeze({ status: "abandoned" as const });
    }

    if (operationRecord.value.state === "prepared") {
      return Object.freeze({ status: "prepared" as const });
    }

    return Object.freeze({
      status: "observable" as const,
      operation: observationHandle(key, operationRecord),
    });
  }

  async function releaseAbandonedMaterialization(
    exact: Readonly<OperationIdentity>,
  ): Promise<void> {
    const snapshot = await refresh();
    const grant = snapshot.value;
    if (grant.state !== "active" && grant.state !== "revoking") return;
    const current = grant.materializations.find(
      (entry) => entry.chainId === exact.chainId && entry.state !== "unsupported",
    );
    if (
      current?.state !== "installing" ||
      current.account !== exact.account ||
      current.operationId !== exact.userOperationHash
    ) {
      return;
    }
    const abandonedAt = materializationReleaseTime(grant);
    await commit(
      snapshot,
      transition(grant, {
        type: "abandon_materialization",
        identity: grant.identity,
        binding: {
          chainId: current.chainId,
          account: current.account,
          permissionId: current.permissionId,
        },
        operationId: exact.userOperationHash,
        abandonedAt,
      }),
    );
  }

  async function abandonPreparedOperationWork(
    value: unknown,
  ): Promise<Readonly<OaathProviderOperationRecovery>> {
    const exact = captureProviderRecoveryInput(value);
    const current = await recoverOperationWork(Object.freeze({ identity: exact }));
    if (current.status !== "prepared") return current;
    const abandoning = observationOnlyRunner(exact.chainId);
    try {
      await abandoning.abandonPreparedOperation({
        kind: "execution",
        key: {
          grantId: exact.grantId,
          chainId: exact.chainId,
          kind: "execution",
        },
        expectedUserOperationHash: exact.userOperationHash,
        abandonedAt: input.now(),
      });
    } catch {
      // The exact reread below decides whether submission won the CAS.
    } finally {
      await abandoning.close().catch(() => undefined);
    }
    return recoverOperationWork(Object.freeze({ identity: exact }));
  }

  async function runOnce(
    created: ReturnType<typeof createOperationRunner>,
    kind: OperationKind,
    key: Readonly<OperationStoreKey>,
  ): Promise<OperationRunResult> {
    const at = input.now();
    try {
      return await created.runOperation({
        kind,
        key,
        preparedAt: at,
        attemptedAt: at,
        submittedAt: at,
        observedAt: at,
        timeoutMs: SUBMISSION_TIMEOUT_MS,
      });
    } catch (error) {
      return mapClientFailure(error, "operation run failed");
    }
  }

  async function startOnce(
    created: ReturnType<typeof createOperationRunner>,
    kind: OperationKind,
    key: Readonly<OperationStoreKey>,
  ): Promise<OperationStartResult> {
    const at = input.now();
    try {
      return await created.startOperation({
        kind,
        key,
        preparedAt: at,
        attemptedAt: at,
        submittedAt: at,
        observedAt: at,
        timeoutMs: SUBMISSION_TIMEOUT_MS,
      });
    } catch (error) {
      return mapClientFailure(error, "operation start failed");
    }
  }

  async function recordSuccessfulMaterialization(
    binding: Readonly<{
      chainId: number;
      account: `0x${string}`;
      permissionId: `0x${string}`;
    }>,
    result: OperationRunResult | OperationStartResult,
  ): Promise<void> {
    if (result.status !== "observed") return;
    const value = result.record.value;
    if (value.state !== "finalized" || value.inclusion.outcome !== "success") return;
    if (value.identity.chainId !== binding.chainId || value.identity.account !== binding.account) {
      return clientFail(
        "oaath_client_state_conflict",
        "finalized installation operation does not match its Grant binding",
        "grant_materialization_operation_mismatch",
      );
    }

    const snapshot = await refresh();
    const grant = snapshot.value;
    const current = grant.materializations.find(
      (entry) => entry.chainId === binding.chainId && entry.state !== "unsupported",
    );
    if (current?.state === "installed") {
      if (current.account === binding.account && current.permissionId === binding.permissionId)
        return;
      return clientFail(
        "oaath_client_state_conflict",
        "installed Grant materialization has another binding",
        "grant_materialization_binding_mismatch",
      );
    }
    if (current?.state !== "installing") return;
    if (current.account !== binding.account || current.permissionId !== binding.permissionId) {
      return clientFail(
        "oaath_client_state_conflict",
        "installing Grant materialization has another binding",
        "grant_materialization_binding_mismatch",
      );
    }
    if (current.operationId !== value.identity.userOperationHash) {
      return clientFail(
        "oaath_client_state_conflict",
        "installing Grant materialization belongs to another operation",
        "grant_materialization_operation_mismatch",
      );
    }
    try {
      await commit(
        snapshot,
        transition(grant, {
          type: "record_installed",
          identity: grant.identity,
          binding,
          operationId: value.identity.userOperationHash,
          installation: {
            ...binding,
            kind: "permission_present",
            blockNumber: value.finality.blockNumber,
            blockHash: value.finality.blockHash,
            observedAt: value.finality.observedAt,
          },
        }),
      );
    } catch (error) {
      const retained = await refresh().catch(() => {
        throw error;
      });
      const installed = retained.value.materializations.find(
        (entry) => entry.chainId === binding.chainId && entry.state === "installed",
      );
      if (
        installed?.state === "installed" &&
        installed.account === binding.account &&
        installed.permissionId === binding.permissionId
      ) {
        return;
      }
      throw error;
    }
  }

  async function recordRecoveredMaterialization(
    account: `0x${string}`,
    result: OperationObserveResult,
  ): Promise<void> {
    if (
      result.status !== "observed" ||
      result.record.value.state !== "finalized" ||
      result.record.value.inclusion.outcome !== "success"
    ) {
      return;
    }
    const chainId = result.record.value.identity.chainId;
    const grant = (await refresh()).value;
    const installing = grant.materializations.find(
      (entry) => entry.chainId === chainId && entry.state === "installing",
    );
    if (installing?.state !== "installing") return;
    if (installing.account !== account) {
      return clientFail(
        "oaath_client_state_conflict",
        "recovered installation belongs to another account",
        "grant_materialization_operation_mismatch",
      );
    }
    await recordSuccessfulMaterialization(
      Object.freeze({
        chainId,
        account,
        permissionId: installing.permissionId,
      }),
      result,
    );
  }

  function requireMaterializationOperation(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    operation: OaathProviderOperationPointer,
  ): `0x${string}` {
    const identity = operation.identity;
    if (
      identity.kind !== "execution" ||
      identity.grantId !== record.value.identity.grantId ||
      identity.chainId !== binding.chainId ||
      identity.account !== binding.account
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "the operation does not match its Grant materialization",
        "grant_materialization_operation_mismatch",
      );
    }
    return identity.userOperationHash;
  }

  async function authorizeExecutionOperation(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    mode: "standard" | "enable-replayable",
    operation: OaathProviderOperationPointer,
  ): Promise<void> {
    const operationId = requireMaterializationOperation(binding, operation);
    requireExecutionPublication();
    const snapshot = await requireActive();
    const current = snapshot.value.materializations.find(
      (entry) => entry.chainId === binding.chainId && entry.state !== "unsupported",
    );
    if (
      !current ||
      current.state === "unsupported" ||
      current.account !== binding.account ||
      current.permissionId !== binding.permissionId
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant materialization binding changed before signing",
        "grant_materialization_binding_mismatch",
      );
    }

    if (mode === "enable-replayable") {
      if (current.state === "unmaterialized") {
        await commit(
          snapshot,
          transition(snapshot.value, {
            type: "begin_materialization",
            identity: snapshot.value.identity,
            binding,
            operationId,
            startedAt: input.now(),
          }),
        );
        return;
      }
      if (current.state !== "installing" || current.operationId !== operationId) {
        return clientFail(
          "oaath_client_state_conflict",
          "another operation owns Grant materialization",
          "grant_materialization_operation_mismatch",
        );
      }
    } else if (current.state !== "installed") {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant permission is not installed",
        "grant_materialization_not_installed",
      );
    }

    // Even when the aggregate value is unchanged, this CAS is the durable
    // admission linearization point against another handle beginning revocation.
    await commit(snapshot, snapshot.value);
  }

  function materializationReleaseTime(grant: Grant): number {
    const observedAt = input.now();
    return grant.state === "active"
      ? Math.min(Math.max(observedAt, grant.updatedAt), grant.expiresAt - 1)
      : Math.max(observedAt, grant.updatedAt);
  }

  async function abandonExecutionOperation(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    mode: "standard" | "enable-replayable",
    operation: OaathProviderOperationPointer,
  ): Promise<void> {
    if (mode !== "enable-replayable") return;
    const operationId = requireMaterializationOperation(binding, operation);
    const snapshot = await refresh();
    const grant = snapshot.value;
    if (grant.state !== "active" && grant.state !== "revoking") return;
    const current = grant.materializations.find(
      (entry) => entry.chainId === binding.chainId && entry.state !== "unsupported",
    );
    if (
      current?.state !== "installing" ||
      current.account !== binding.account ||
      current.permissionId !== binding.permissionId ||
      current.operationId !== operationId
    ) {
      return;
    }
    const abandonedAt = materializationReleaseTime(grant);
    await commit(
      snapshot,
      transition(grant, {
        type: "abandon_materialization",
        identity: grant.identity,
        binding,
        operationId,
        abandonedAt,
      }),
    );
  }

  async function reconcileInstallingMaterialization(
    snapshot: GrantStoreRecord,
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    operationId: `0x${string}`,
  ): Promise<GrantStoreRecord> {
    const operation = await exactOperation(
      { grantId: snapshot.value.identity.grantId, chainId: binding.chainId, kind: "execution" },
      operationId,
    );
    if (
      operation === undefined ||
      operation.value.identity.account !== binding.account ||
      operation.value.identity.userOperationHash !== operationId
    ) {
      return snapshot;
    }
    if (operation.value.state === "finalized" && operation.value.inclusion.outcome === "success") {
      return commit(
        snapshot,
        transition(snapshot.value, {
          type: "record_installed",
          identity: snapshot.value.identity,
          binding,
          operationId,
          installation: {
            ...binding,
            kind: "permission_present",
            blockNumber: operation.value.finality.blockNumber,
            blockHash: operation.value.finality.blockHash,
            observedAt: operation.value.finality.observedAt,
          },
        }),
      );
    }
    const conclusivelyNotInstalled =
      operation.value.state === "abandoned" ||
      operation.value.state === "superseded" ||
      (operation.value.state === "dropped" && operation.value.priorInclusion === null) ||
      (operation.value.state === "finalized" && operation.value.inclusion.outcome === "reverted");
    if (!conclusivelyNotInstalled) return snapshot;
    return commit(
      snapshot,
      transition(snapshot.value, {
        type: "abandon_materialization",
        identity: snapshot.value.identity,
        binding,
        operationId,
        abandonedAt: materializationReleaseTime(snapshot.value),
      }),
    );
  }

  async function authorizeRevocationOperation(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    operation: OaathProviderOperationPointer,
  ): Promise<void> {
    const identity = operation.identity;
    if (
      identity.kind !== "revocation" ||
      identity.grantId !== record.value.identity.grantId ||
      identity.chainId !== binding.chainId ||
      identity.account !== binding.account
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "the revocation operation does not match its Grant materialization",
        "grant_materialization_operation_mismatch",
      );
    }
    const snapshot = await refresh();
    const grant = snapshot.value;
    const current = grant.materializations.find(
      (entry) => entry.chainId === binding.chainId && entry.state !== "unsupported",
    );
    if (
      grant.state !== "revoking" ||
      current?.state !== "revoking" ||
      current.account !== binding.account ||
      current.permissionId !== binding.permissionId
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant no longer admits this revocation operation",
        "grant_materialization_binding_mismatch",
      );
    }
    await commit(snapshot, grant);
  }

  async function executeCalls(
    value: unknown,
    action: "run" | "start",
    requestHash: `0x${string}` | null,
    publication?: Readonly<OaathProviderOperationPublication>,
  ): Promise<Readonly<OaathOperationHandle>> {
    const context: CaptureContext = new WeakSet();
    const request = exactClientRecord(value, ["chain", "calls"], "sendCalls input", context);
    const chainId = request.chain;
    if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
      return clientFail("oaath_client_input_invalid", "sendCalls chain is invalid");
    }
    const calls = captureCalls(request.calls, context);
    const grantSnapshot = await requireActive();
    const grant = grantSnapshot.value;
    const chain = chainCapability(chainId);
    const deployment = (() => {
      try {
        return kernelV4Deployment(chainId);
      } catch (error) {
        return mapClientFailure(error, "chain is not a supported Kernel deployment");
      }
    })();

    requireKernelCapability(chainId, kernelKeyCapability("owner", input.ownerKey.kind));
    const coverage = await sessionCoverage(grant, chainId, calls);
    // A Grant may authorize at most the owner-approved scope. Denial happens
    // here — before the bundler probe, the quote, the durable journal, any
    // signature, and any send — and it is conclusive: unreadable or missing
    // usage evidence is not coverage.
    if (coverage !== "covered") {
      return clientFail(
        "oaath_client_scope_denied",
        coverage === "uncovered"
          ? "the calls are outside the approved Grant scope"
          : "Grant scope coverage could not be conclusively evaluated",
        coverage === "uncovered" ? "session_calls_uncovered" : "session_coverage_unreadable",
      );
    }
    const bundler = await probeBundlerCapability({
      capability: chain.bundler,
      request: { chainId, entryPoint: deployment.entryPoint.address },
      timeoutMs: SUBMISSION_TIMEOUT_MS,
    }).catch((error: unknown) => mapClientFailure(error, "bundler probe failed"));
    const decision = decideExecution({
      operationKind: "execution",
      sessionCoverage: coverage,
      bundler,
      feePayer: chain.feePayer,
    });
    if (decision.route === "none") {
      return clientFail(
        "oaath_client_route_unavailable",
        "no safe submission route is available",
        decision.reasons.join(","),
      );
    }
    requireKernelCapability(chainId, kernelKeyCapability("session", input.sessionKey.kind));
    requireKernelCapability(chainId, "hook_call");
    // Coverage was proven above and the decision table maps covered execution
    // to the session signer, so this handle never composes owner authority for
    // a send. `ownerRuntime` remains only for account identity binding.
    const runtime = sessionRuntime(chainId);
    const descriptor = await accountDescriptor(chainId);
    requireExecutionPublication();
    let publicationSnapshot = await requireActive();
    requireExecutionPublication();
    if (publicationSnapshot.storeRevision !== grantSnapshot.storeRevision) {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant advanced before operation publication",
        "grant_store_conflict",
      );
    }
    let publicationGrant = publicationSnapshot.value;
    const key = Object.freeze({
      grantId: publicationGrant.identity.grantId,
      chainId,
      kind: "execution" as const,
    });

    // One approval, materialized independently per chain: the first covered
    // execution on an unmaterialized chain spends the owner's replayable
    // install approval in enable mode and executes together with it; every
    // later operation validates through the standard permission path. The
    // durable Grant record owns each chain's state, committed before any
    // signature or send exists.
    if (runtime.validation.kind !== "permission") {
      return unsupported("session_validation_not_permission");
    }
    const binding = Object.freeze({
      chainId,
      account: descriptor.account,
      permissionId: runtime.validation.permissionId,
    });
    let materialization = publicationGrant.materializations.find(
      (entry) => entry.chainId === chainId && entry.state !== "unsupported",
    );
    if (materialization?.state === "installing") {
      publicationSnapshot = await reconcileInstallingMaterialization(
        publicationSnapshot,
        binding,
        materialization.operationId,
      );
      publicationGrant = publicationSnapshot.value;
      materialization = publicationGrant.materializations.find(
        (entry) => entry.chainId === chainId && entry.state !== "unsupported",
      );
    }
    let mode: "standard" | "enable-replayable" = "standard";
    let latest = publicationSnapshot;
    if (materialization === undefined || materialization.state === "unmaterialized") {
      if (input.installApproval === null) {
        return unsupported("grant_capability_unavailable");
      }
      mode = "enable-replayable";
      if (materialization === undefined) {
        latest = await commit(
          latest,
          transition(latest.value, {
            type: "record_unmaterialized",
            identity: latest.value.identity,
            binding,
            recordedAt: input.now(),
          }),
        );
      }
    } else if (materialization.state === "installing") {
      // A prior materialization attempt exists; the lane below owns its exact
      // identity and never submits twice. Re-entering enable mode can only
      // observe or, on a terminal lane, mint an operation the chain refuses
      // because the install nonce is spent — never a second authority.
      if (input.installApproval === null) {
        return unsupported("grant_capability_unavailable");
      }
      mode = "enable-replayable";
    } else if (materialization.state !== "installed") {
      return unsupported(`grant_materialization_${materialization.state}`);
    }

    const shape = {
      chainId,
      kind: "execution" as const,
      runtime,
      descriptor,
      calls,
      signer: "session" as const,
      mode,
      installApproval: input.installApproval,
      decision,
      grantId: publicationGrant.identity.grantId,
      requestHash,
      authorizeOperation: (operation: OaathProviderOperationPointer) =>
        authorizeExecutionOperation(binding, mode, operation),
      abandonOperation: (operation: OaathProviderOperationPointer) =>
        abandonExecutionOperation(binding, mode, operation),
    };
    // The sender may replace a terminal lane, while the returned handle receives
    // a separate read-only runner and pins the exact hash below. Neither can
    // submit twice for one identity.
    const sender = runner({
      ...shape,
      terminalBehavior: "replace",
      ...(publication ? { publication } : {}),
    });
    let result: OperationRunResult | OperationStartResult;
    try {
      result =
        action === "start"
          ? await startOnce(sender, "execution", key)
          : await runOnce(sender, "execution", key);
    } finally {
      // A cleanup failure never replaces the outcome of the send.
      await sender.close().catch(() => undefined);
    }
    // Raises a state conflict before any handle exists to leak.
    operationOutcome(result);
    if (action === "run" && mode === "enable-replayable") {
      await recordSuccessfulMaterialization(binding, result).catch(() => undefined);
    }
    return trackedOperationHandle({
      runner: runner({ ...shape, terminalBehavior: "reuse_same_kind" }),
      key,
      kind: "execution",
      timeoutMs: SUBMISSION_TIMEOUT_MS,
      now: input.now,
      initial: result,
      observation: (readRequest) => chain.observation.read(readRequest),
      ...(mode === "enable-replayable"
        ? {
            onObserved: (observed: OperationObserveResult) =>
              recordSuccessfulMaterialization(binding, observed),
          }
        : {}),
    });
  }

  function sendCalls(value: unknown): Promise<Readonly<OaathOperationHandle>> {
    return withExecution(() => executeCalls(value, "run", null));
  }

  function startCalls(
    value: unknown,
    publicationValue: OaathProviderOperationPublication,
  ): Promise<Readonly<OaathOperationHandle>> {
    return withExecution(() => {
      const context: CaptureContext = new WeakSet();
      const request = exactClientRecord(
        value,
        ["chain", "calls", "requestHash"],
        "provider sendCalls input",
        context,
      );
      if (
        typeof request.requestHash !== "string" ||
        !USER_OPERATION_HASH.test(request.requestHash)
      ) {
        return clientFail(
          "oaath_client_input_invalid",
          "provider request hash must be a lowercase 32-byte hash",
        );
      }
      return executeCalls(
        Object.freeze({ chain: request.chain, calls: request.calls }),
        "start",
        request.requestHash as `0x${string}`,
        captureProviderPublication(publicationValue),
      );
    });
  }

  function recoverOperation(value: unknown): Promise<Readonly<OaathProviderOperationRecovery>> {
    return withActivity(() => recoverOperationWork(value));
  }

  function abandonPreparedOperation(
    value: unknown,
  ): Promise<Readonly<OaathProviderOperationRecovery>> {
    return withActivity(() => abandonPreparedOperationWork(value));
  }

  async function invalidateCapability(grant: Grant): Promise<Grant> {
    if (grant.approval === null) {
      return clientFail(
        "oaath_client_state_conflict",
        "a revoking Grant has no approval",
        "grant_approval_absent",
      );
    }
    const capabilityHash = grant.approval.capabilityHash;
    let evidence: unknown;
    try {
      evidence = await input.invalidation.invalidateCapability({
        grantId: grant.identity.grantId,
        capabilityHash,
      });
    } catch (error) {
      return mapClientFailure(error, "approval capability invalidation failed");
    }
    const proof = exactClientRecord(
      evidence,
      ["evidenceHash", "invalidatedAt"],
      "capability invalidation evidence",
      new WeakSet(),
      "oaath_client_capability_invalid",
    );
    if (typeof proof.evidenceHash !== "string" || typeof proof.invalidatedAt !== "number") {
      return clientFail(
        "oaath_client_capability_invalid",
        "capability invalidation evidence is invalid",
      );
    }
    // The Grant aggregate owns the exact hash and time rules for the invalidation.
    return transition(grant, {
      type: "record_capability_invalidated",
      identity: grant.identity,
      invalidation: {
        kind: "approval_capability_invalidated",
        capabilityHash,
        evidenceHash: proof.evidenceHash as `0x${string}`,
        invalidatedAt: proof.invalidatedAt,
      },
    });
  }

  /**
   * Finalized-anchored observation that a chain's permission is no longer
   * installed: Kernel's own `isModuleInstalled(6, signer, permissionId)` view
   * turning false at a finalized block later than the installation. This is
   * how a realm that cannot sign owner operations (URL mode never holds owner
   * authority) still completes `revoking` once the owner's console removed the
   * permission out-of-band.
   *
   * Fail closed everywhere: only an exact `false` at a block that rebinds to
   * the same finalized hash counts; every other answer is inconclusive.
   */
  async function observeChainRemoval(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    installedAtBlock: string,
  ): Promise<Readonly<ChainPermissionEvidence> | null> {
    if (input.installApproval === null) return null;
    const signer = input.installApproval.packages.find((entry) => entry.moduleType === 6)?.module;
    if (signer === undefined) return null;
    try {
      const chain = chainCapability(binding.chainId);
      const finalized = await chain.observation.read({
        type: "finalized_block",
        chainId: binding.chainId,
      });
      const block = finalized as { readonly number?: unknown; readonly hash?: unknown } | null;
      if (
        !block ||
        typeof block.number !== "string" ||
        !/^0x[0-9a-f]+$/u.test(block.number) ||
        typeof block.hash !== "string" ||
        !/^0x[0-9a-f]{64}$/u.test(block.hash)
      ) {
        return null;
      }
      const blockNumber = BigInt(block.number).toString(10);
      // The protocol requires removal evidence to follow the installation; a
      // chain that has not advanced past the install block proves nothing yet.
      if (BigInt(blockNumber) <= BigInt(installedAtBlock)) return null;
      const installed = await chain.observation.read({
        type: "kernel_permission_installed",
        chainId: binding.chainId,
        account: binding.account,
        signer,
        permissionId: binding.permissionId,
        blockNumber,
      });
      if (installed !== false) return null;
      // The read was answered by number alone, so rebind: the block at that
      // number must still be the finalized block this evidence names.
      const rebound = (await chain.observation.read({
        type: "canonical_block",
        chainId: binding.chainId,
        blockNumber,
      })) as { readonly number?: unknown; readonly hash?: unknown } | null;
      if (rebound?.hash !== block.hash || rebound.number !== block.number) return null;
      return Object.freeze({
        ...binding,
        kind: "permission_absent" as const,
        blockNumber,
        blockHash: block.hash as `0x${string}`,
        observedAt: input.now(),
      });
    } catch {
      return null;
    }
  }

  /**
   * Owner-signed removal of one chain's installed permission: the exact
   * reverse-ordered uninstall self-calls, derived from the same install
   * packages the owner's approval bound, run on the chain's revocation lane.
   *
   * A realm that cannot mint or route the owner operation falls back to
   * observation: once the owner's own console has removed the permission, the
   * chain itself proves it and the entry completes. Otherwise the Grant stays
   * durably `revoking` — only finalized success of the uninstall operation or
   * finalized-anchored absence evidence records the chain revoked.
   */
  async function revokeChainPermission(
    snapshot: GrantStoreRecord,
    entry: Grant["materializations"][number],
  ): Promise<GrantStoreRecord> {
    const grant = snapshot.value;
    if (entry.state !== "installed" && entry.state !== "revoking") return snapshot;
    // Without installation evidence there is nothing a removal can be proven
    // against, and without the approval there are no install packages to
    // derive the uninstall calls from.
    if (entry.installation === null || input.installApproval === null) return snapshot;
    const chainId = entry.chainId;
    const binding = Object.freeze({
      chainId,
      account: entry.account,
      permissionId: entry.permissionId,
    });
    let latest = snapshot;
    // Durable intent precedes the probe, the quote, any signature, and any
    // send; a `revoking` entry re-enters here without a second begin.
    if (entry.state === "installed") {
      latest = await commit(
        latest,
        transition(latest.value, {
          type: "begin_chain_revocation",
          identity: latest.value.identity,
          binding,
          startedAt: input.now(),
        }),
      );
    }
    const laneKey = Object.freeze({
      grantId: latest.value.identity.grantId,
      chainId,
      kind: "revocation" as const,
    });
    let value: FinalizedOperation | null = null;
    try {
      // A prior removal that already finalized successfully completes
      // directly — a Grant commit lost to a crash never mints a second
      // uninstall. Any other terminal attempt (dropped, superseded, included
      // but failed) is replaceable below, so one bad attempt cannot strand
      // cleanup forever.
      const journal = new OperationStore({
        get: (key: Readonly<OperationStoreKey>) => input.operations.get(key),
        getArchived: (value: Parameters<OperationStoreAdapter["getArchived"]>[0]) =>
          input.operations.getArchived(value),
        compareAndSwap: (record: Parameters<OperationStoreAdapter["compareAndSwap"]>[0]) =>
          input.operations.compareAndSwap(record),
        close: async () => undefined,
      } satisfies OperationStoreAdapter);
      const prior = await journal.get(laneKey);
      if (
        prior !== undefined &&
        prior.value.state === "finalized" &&
        prior.value.inclusion.outcome === "success" &&
        prior.value.identity.account === entry.account
      ) {
        value = prior.value;
      }
    } catch {
      // An unreadable journal decides nothing; the run below owns the lane.
    }
    if (value === null) {
      let result: OperationRunResult | null = null;
      try {
        const chain = chainCapability(chainId);
        const deployment = kernelV4Deployment(chainId);
        requireKernelCapability(chainId, kernelKeyCapability("owner", input.ownerKey.kind));
        const calls = encodeKernelV4PermissionUninstallCalls({
          account: entry.account,
          packages: input.installApproval.packages,
        });
        const bundler = await probeBundlerCapability({
          capability: chain.bundler,
          request: { chainId, entryPoint: deployment.entryPoint.address },
          timeoutMs: SUBMISSION_TIMEOUT_MS,
        });
        const decision = decideExecution({
          operationKind: "revocation",
          sessionCoverage: "uncovered",
          bundler,
          feePayer: chain.feePayer,
        });
        const descriptor = decision.route === "none" ? null : await accountDescriptor(chainId);
        if (descriptor !== null && descriptor.account === entry.account) {
          const sender = runner({
            chainId,
            kind: "revocation",
            runtime: ownerRuntime(chainId),
            descriptor,
            calls,
            signer: "owner",
            mode: "standard",
            installApproval: null,
            decision,
            terminalBehavior: "replace",
            grantId: latest.value.identity.grantId,
            requestHash: null,
            authorizeOperation: (operation: OaathProviderOperationPointer) =>
              authorizeRevocationOperation(binding, operation),
          });
          try {
            result = await runOnce(sender, "revocation", laneKey);
          } finally {
            // A cleanup failure never replaces the outcome of the run.
            await sender.close().catch(() => undefined);
          }
        }
      } catch {
        // The realm cannot mint or route the owner operation here; the
        // observation fallback below is its only completion path.
        result = null;
      }
      if (
        result !== null &&
        result.status === "observed" &&
        result.record.value.state === "finalized" &&
        result.record.value.inclusion.outcome === "success"
      ) {
        value = result.record.value;
      }
    }
    if (value !== null) {
      latest = await refresh();
      return commit(
        latest,
        transition(latest.value, {
          type: "record_chain_revoked",
          identity: latest.value.identity,
          binding,
          removal: {
            ...binding,
            kind: "permission_absent",
            blockNumber: value.finality.blockNumber,
            blockHash: value.finality.blockHash,
            observedAt: value.finality.observedAt,
          },
        }),
      );
    }
    // No owner operation completed here. If the owner's console already
    // removed the permission out-of-band, the chain proves it.
    const removal = await observeChainRemoval(binding, entry.installation.blockNumber);
    if (removal === null) return latest;
    latest = await refresh();
    return commit(
      latest,
      transition(latest.value, {
        type: "record_chain_revoked",
        identity: latest.value.identity,
        binding,
        removal,
      }),
    );
  }

  async function revokeGrant(): Promise<void> {
    let snapshot = await refresh();
    let grant = snapshot.value;
    if (grant.state === "revoked") return;
    if (grant.state !== "active" && grant.state !== "revoking") {
      clientFail(
        "oaath_client_grant_inactive",
        "the Grant cannot be revoked",
        `grant_${grant.state}`,
      );
    }
    if (grant.state === "active") {
      snapshot = await commit(
        snapshot,
        transition(grant, {
          type: "begin_revocation",
          identity: grant.identity,
          revocationStartedAt: input.now(),
        }),
      );
      grant = snapshot.value;
    }
    // The replayable capability dies first, so no new chain can materialize
    // while installed permissions await removal.
    if (grant.capabilityInvalidation === null) {
      snapshot = await commit(snapshot, await invalidateCapability(grant));
      grant = snapshot.value;
    }
    // Each chain-local installed permission is removed on that chain by an
    // owner-signed revocation operation. A realm holding the owner's signing
    // capability completes it here; one that does not (URL mode never holds
    // owner authority) leaves the chain pending. The Grant stays durably
    // `revoking` until every chain's removal is conclusively observed.
    for (const entry of [...grant.materializations]) {
      snapshot = await revokeChainPermission(snapshot, entry);
      grant = snapshot.value;
    }
    if (
      grant.materializations.some(
        (entry) =>
          entry.state !== "unsupported" &&
          entry.state !== "unmaterialized" &&
          entry.state !== "revoked",
      )
    ) {
      return;
    }
    await commit(
      snapshot,
      transition(grant, {
        type: "complete_revocation",
        identity: grant.identity,
        revokedAt: input.now(),
      }),
    );
  }

  async function revoke(): Promise<void> {
    assertOpen();
    revocationRequested = true;
    const active =
      revoking ??
      (async () => {
        await waitForExecutions();
        await revokeGrant();
      })();
    revoking = active;
    try {
      await active;
    } finally {
      if (revoking === active) revoking = null;
    }
  }

  async function account(chain: unknown): Promise<`0x${string}`> {
    assertOpen();
    if (typeof chain !== "number" || !Number.isSafeInteger(chain) || chain < 1) {
      return clientFail("oaath_client_input_invalid", "account chain is invalid");
    }
    return (await accountDescriptor(chain)).account;
  }

  const handle: Readonly<OaathGrantHandle> = Object.freeze({
    get state(): GrantState {
      return record.value.state;
    },
    get expiresAt(): number {
      return record.value.expiresAt;
    },
    account,
    sendCalls,
    revoke,
    async close(): Promise<void> {
      if (closed) return;
      closeRequested = true;
      const active =
        closing ??
        (async () => {
          await waitForExecutions();
          await waitForActivities();
          if (revoking !== null) await revoking.catch(() => undefined);
          const failures: unknown[] = [];
          for (const operation of [...handles]) {
            await operation.close().catch((error: unknown) => failures.push(error));
          }
          for (const [chainId, created] of [...observers]) {
            await created
              .close()
              .then(() => {
                if (observers.get(chainId) === created) observers.delete(chainId);
              })
              .catch((error: unknown) => failures.push(error));
          }
          const failure = failures[0];
          if (failure !== undefined) {
            return mapClientFailure(failure, "Grant handle cleanup is incomplete");
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
  GRANT_PROVIDER_PORTS.set(
    handle,
    Object.freeze({
      providerScopeId: input.binding.bindingId,
      grantId: record.value.identity.grantId,
      walletCallBundles: input.walletCallBundles,
      now: input.now,
      account,
      startCalls,
      recoverOperation,
      abandonPreparedOperation,
    }),
  );
  return handle;
}
