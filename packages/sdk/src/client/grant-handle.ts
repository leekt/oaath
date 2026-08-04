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
 *            -> bundler probe
 *            -> decideExecution (pre-sign; no key, no prepared operation)
 *            -> createKernelRuntime for the decided authority
 *            -> prepareOperation through the runner (durable before any send)
 *            -> the caller-supplied submission capability
 *            -> observation
 * ```
 *
 * A decided session authority that cannot be composed fails closed. It is never
 * downgraded to owner authority, because owner authority is wider than the
 * session policy the owner approved.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  advanceGrant,
  type CaptureContext,
  captureDenseArray,
  evaluateGrantPolicyCoverage,
  type Grant,
  type GrantPolicy,
  type GrantPolicyCoverageResult,
  type GrantState,
  type GrantTransition,
  type OperationKind,
  type PermissionRequest,
} from "@oaath/protocol";
import {
  diagnoseKernelCapability,
  type KernelCapability,
  kernelKeyCapability,
} from "../kernel/capabilities.js";
import { createKernelRuntime } from "../kernel/create-kernel-runtime.js";
import { ownerOperator } from "../kernel/operator/owner.js";
import { sessionOperator } from "../kernel/operator/session.js";
import type { KernelPolicyProfile, KernelRuntime, KeyProfile } from "../kernel/types.js";
import {
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
  type OperationRunResult,
  type OperationSubmissionSession,
} from "../operation-runner.js";
import type { PreparedUserOperation } from "../prepared-user-operation.js";
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
  readonly sendCalls: (input: unknown) => Promise<Readonly<OaathOperationHandle>>;
  readonly revoke: () => Promise<void>;
  readonly close: () => Promise<void>;
}

export interface CreateGrantHandleInput {
  readonly binding: Readonly<OaathBinding>;
  readonly request: Readonly<PermissionRequest>;
  readonly approvedPolicy: Readonly<GrantPolicy>;
  readonly record: GrantStoreRecord;
  readonly grants: GrantStore;
  readonly operations: OperationStoreAdapter;
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

/**
 * Maps the approved Grant policy onto Kernel policy hook profiles. This is the
 * one place the two vocabularies meet, and it is deliberately total: an approved
 * constraint with no reviewed hook profile fails closed instead of installing a
 * session that enforces less than the owner approved.
 */
export function deriveSessionPolicyProfiles(
  policy: Readonly<GrantPolicy>,
): readonly KernelPolicyProfile[] {
  const byTarget = new Map<`0x${string}`, `0x${string}`[]>();
  let maximumValue = 0n;
  for (const call of policy.calls) {
    if (call.argumentEquals.length > 0) {
      unsupported("policy_argument_constraint_unsupported");
    }
    const selectors = byTarget.get(call.target) ?? [];
    if (!selectors.includes(call.selector)) selectors.push(call.selector);
    byTarget.set(call.target, selectors);
    const limit = BigInt(call.valueLimit);
    if (limit > maximumValue) maximumValue = limit;
  }
  if (byTarget.size === 0) unsupported("policy_has_no_calls");
  if (policy.validUntil === null) unsupported("policy_expiry_unbounded");
  return Object.freeze([
    Object.freeze({
      kind: "call" as const,
      calls: Object.freeze(
        [...byTarget].map(([target, selectors]) =>
          Object.freeze({ target, selectors: Object.freeze([...selectors]) }),
        ),
      ),
    }),
    Object.freeze({ kind: "value" as const, maximumValue: maximumValue.toString(10) }),
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
  const observers = new Map<number, OperationObserver>();
  const handles: Readonly<OaathOperationHandle>[] = [];

  function assertOpen(): void {
    if (closed) clientFail("oaath_client_closed", "Grant handle is closed");
  }

  function chainCapability(chainId: number): Readonly<OaathChainCapability> {
    const chain = input.chains.get(chainId);
    if (!chain) unsupported("chain_not_configured");
    return chain;
  }

  async function refresh(): Promise<Grant> {
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
    return current.value;
  }

  async function commit(next: Grant): Promise<Grant> {
    try {
      const committed = await input.grants.compareAndSwap({
        grantId: record.value.identity.grantId,
        expectedStoreRevision: record.storeRevision,
        next,
      });
      if (committed.status === "conflict") {
        return clientFail(
          "oaath_client_state_conflict",
          "another writer advanced the Grant",
          "grant_store_conflict",
        );
      }
      record = committed.record;
      return committed.record.value;
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

  async function requireActive(): Promise<Grant> {
    const grant = await refresh();
    if (grant.state !== "active") {
      clientFail("oaath_client_grant_inactive", "the Grant is not active", `grant_${grant.state}`);
    }
    if (input.now() >= grant.expiresAt) {
      clientFail("oaath_client_grant_inactive", "the Grant is expired", "grant_expired");
    }
    return grant;
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
    readonly decision: Readonly<OaathExecutionDecision>;
    readonly terminalBehavior: "replace" | "reuse_same_kind";
    readonly grantId: string;
  }): ReturnType<typeof createOperationRunner> {
    const chain = chainCapability(spec.chainId);
    const shared = observer(spec.chainId);
    try {
      return createOperationRunner({
        terminalBehavior: spec.terminalBehavior,
        // A scoped store and facades: the realm owns the adapter, the observer,
        // and the caller's transports, so closing one runner never disables
        // another that still has work.
        store: new OperationStore({
          get: (key: Readonly<OperationStoreKey>) => input.operations.get(key),
          compareAndSwap: (value: Parameters<OperationStoreAdapter["compareAndSwap"]>[0]) =>
            input.operations.compareAndSwap(value),
          close: async () => undefined,
        } satisfies OperationStoreAdapter),
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
                signer: spec.decision.signer,
                account: spec.descriptor.account,
                calls: spec.calls,
              }),
            );
            return spec.runtime.prepareOperation({
              kind: spec.kind,
              grantId: spec.grantId,
              account: spec.descriptor,
              nonceKey: quote.nonceKey,
              sequence: quote.sequence,
              calls: [...spec.calls],
              gas: quote.gas,
            });
          },
          close: async () => undefined,
        },
        submission: {
          openSubmission: async (prepared: PreparedUserOperation) =>
            captureSubmissionSession(
              await chain.submission.open({
                prepared,
                // The authority signs the already-durable snapshot; the route was
                // decided before any signature existed and cannot change it.
                signature: await spec.runtime.signOperation(prepared),
                route: spec.decision.route,
                feePayer: spec.decision.feePayer,
              }),
            ),
          close: async () => undefined,
        },
      });
    } catch (error) {
      return mapClientFailure(error, "operation runner could not be composed");
    }
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

  async function sendCalls(value: unknown): Promise<Readonly<OaathOperationHandle>> {
    assertOpen();
    const context: CaptureContext = new WeakSet();
    const request = exactClientRecord(value, ["chain", "calls"], "sendCalls input", context);
    const chainId = request.chain;
    if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
      return clientFail("oaath_client_input_invalid", "sendCalls chain is invalid");
    }
    const calls = captureCalls(request.calls, context);
    const grant = await requireActive();
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
    if (decision.signer === "session") {
      requireKernelCapability(chainId, kernelKeyCapability("session", input.sessionKey.kind));
      requireKernelCapability(chainId, "hook_call");
    }
    const runtime = decision.signer === "session" ? sessionRuntime(chainId) : ownerRuntime(chainId);
    const descriptor = await accountDescriptor(chainId);
    const key = Object.freeze({ grantId: grant.identity.grantId, chainId });
    const shape = {
      chainId,
      kind: "execution" as const,
      runtime,
      descriptor,
      calls,
      decision,
      grantId: grant.identity.grantId,
    };
    // Two runners over the same durable journal: `replace` may start a new
    // operation once the lane is terminal, `reuse_same_kind` may only observe the
    // one that exists. Neither can submit twice for one identity.
    const sender = runner({ ...shape, terminalBehavior: "replace" });
    let result: OperationRunResult;
    try {
      result = await runOnce(sender, "execution", key);
    } finally {
      // A cleanup failure never replaces the outcome of the send.
      await sender.close().catch(() => undefined);
    }
    // Raises a state conflict before any handle exists to leak.
    operationOutcome(result);
    const handle = createOperationHandle({
      runner: runner({ ...shape, terminalBehavior: "reuse_same_kind" }),
      key,
      kind: "execution",
      timeoutMs: SUBMISSION_TIMEOUT_MS,
      now: input.now,
      initial: result,
    });
    handles.push(handle);
    return handle;
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

  async function revoke(): Promise<void> {
    assertOpen();
    let grant = await refresh();
    if (grant.state === "revoked") return;
    if (grant.state !== "active" && grant.state !== "revoking") {
      clientFail(
        "oaath_client_grant_inactive",
        "the Grant cannot be revoked",
        `grant_${grant.state}`,
      );
    }
    if (grant.state === "active") {
      grant = await commit(
        transition(grant, {
          type: "begin_revocation",
          identity: grant.identity,
          revocationStartedAt: input.now(),
        }),
      );
    }
    // A chain-local installed permission must be removed on that chain first.
    // Materialization and its revocation Operation are owned by the all-chain
    // materialization path, not by this handle.
    if (
      grant.materializations.some(
        (entry) =>
          entry.state !== "unsupported" &&
          entry.state !== "unmaterialized" &&
          entry.state !== "revoked",
      )
    ) {
      unsupported("chain_permission_removal_unavailable");
    }
    if (grant.capabilityInvalidation === null) {
      grant = await commit(await invalidateCapability(grant));
    }
    await commit(
      transition(grant, {
        type: "complete_revocation",
        identity: grant.identity,
        revokedAt: input.now(),
      }),
    );
  }

  return Object.freeze({
    get state(): GrantState {
      return record.value.state;
    },
    get expiresAt(): number {
      return record.value.expiresAt;
    },
    sendCalls,
    revoke,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      const failures: unknown[] = [];
      for (const handle of handles.splice(0)) {
        await handle.close().catch((error: unknown) => failures.push(error));
      }
      for (const created of [...observers.values()]) {
        await created.close().catch((error: unknown) => failures.push(error));
      }
      observers.clear();
      const failure = failures[0];
      if (failure !== undefined) mapClientFailure(failure, "Grant handle cleanup is incomplete");
    },
  });
}
