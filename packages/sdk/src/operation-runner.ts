import {
  advanceOperation,
  applyVerifiedOperationObservation,
  type CaptureContext,
  captureRecord,
  createOperation,
  type ExactRecord,
  exactCapturedRecord,
  type Operation,
  type OperationIdentity,
  type OperationKind,
  operationOccupiesLane,
  parseOperation,
} from "@oaath/protocol";
import type { ObserveOperationResult, OperationObserver } from "./operation-observer.js";
import {
  deriveOperationId,
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "./prepared-user-operation.js";
import {
  OaathStoreError,
  OperationStore,
  type OperationStoreCompareAndSwapResult,
  type OperationStoreKey,
  type OperationStoreRecord,
} from "./store.js";

const MAX_GRANT_ID_LENGTH = 256;
const HASH = /^0x[0-9a-f]{64}$/u;

export type OperationRunnerErrorCode =
  | "operation_runner_input_invalid"
  | "operation_runner_capability_invalid"
  | "operation_runner_preparation_failed"
  | "operation_runner_identity_mismatch"
  | "operation_runner_state_conflict"
  | "operation_runner_store_unavailable"
  | "operation_runner_store_uncertain"
  | "operation_runner_closed"
  | "operation_runner_close_failed";

export class OaathOperationRunnerError extends Error {
  readonly code: OperationRunnerErrorCode;

  constructor(code: OperationRunnerErrorCode, message: string) {
    super(message);
    this.name = "OaathOperationRunnerError";
    this.code = code;
  }
}

export interface OperationPreparationCapability {
  readonly prepare: (
    request: Readonly<{
      kind: OperationKind;
      key: Readonly<OperationStoreKey>;
    }>,
  ) => Promise<unknown>;
  /** Reserves any caller-owned durable reference before the Operation is published. */
  readonly reserveOperation: (prepared: PreparedUserOperation) => Promise<unknown>;
  /** Releases only that reservation after a conclusive publication loss. */
  readonly releaseOperationReservation: (prepared: PreparedUserOperation) => Promise<unknown>;
  /** Admits the now-durable prepared identity before confirmation, signing, or send. */
  readonly authorizeOperation: (prepared: PreparedUserOperation) => Promise<unknown>;
  /** Releases owner state after conclusive pre-submission abandonment. */
  readonly abandonOperation: (prepared: PreparedUserOperation) => Promise<unknown>;
  /** Confirms the caller-owned reference only after the prepared Operation is durable. */
  readonly confirmOperationPublished: (prepared: PreparedUserOperation) => Promise<unknown>;
  readonly close: () => Promise<void>;
}

export interface OperationSubmissionSession {
  /** Sends the exact snapshot captured by openSubmission. It accepts no replacement input. */
  readonly submit: () => Promise<unknown>;
  readonly close: () => Promise<void>;
}

export interface OperationSubmissionCapability {
  /** Signs and binds one already-durable prepared snapshot into a zero-argument send session. */
  readonly openSubmission: (prepared: PreparedUserOperation) => Promise<unknown>;
  readonly close: () => Promise<void>;
}

export type OperationTerminalBehavior = "replace" | "reuse_same_kind";

export interface OperationRunnerConfiguration {
  readonly terminalBehavior: OperationTerminalBehavior;
  /** Provider request provenance, or null for direct and revocation operations. */
  readonly requestHash: `0x${string}` | null;
  readonly store: OperationStore;
  readonly observer: OperationObserver;
  readonly preparation: OperationPreparationCapability;
  readonly submission: OperationSubmissionCapability;
}

export interface OperationRunInput {
  readonly kind: OperationKind;
  readonly key: Readonly<OperationStoreKey>;
  readonly preparedAt: number;
  readonly attemptedAt: number;
  readonly submittedAt: number;
  readonly observedAt: number;
  readonly timeoutMs: number;
}

export interface OperationObserveInput extends OperationRunInput {
  readonly expectedUserOperationHash: `0x${string}`;
}

interface OperationAbandonPreparedInput {
  readonly kind: OperationKind;
  readonly key: Readonly<OperationStoreKey>;
  readonly expectedUserOperationHash: `0x${string}`;
  readonly abandonedAt: number;
}

type OperationStartedResult = Readonly<{
  status: "started";
  record: OperationStoreRecord;
}>;

type OperationSubmissionUncertainResult = Readonly<{
  status: "submission_uncertain";
  reason:
    | "session_unavailable"
    | "session_invalid"
    | "send_ambiguous"
    | "result_invalid"
    | "identity_mismatch";
  record: OperationStoreRecord;
}>;

type OperationObservedResult = Readonly<{
  status: "observed";
  observation: ObserveOperationResult;
  record: OperationStoreRecord;
}>;

type OperationObservationUnavailableResult = Readonly<{
  status: "observation_unavailable";
  reason: "observer_failed" | "result_invalid" | "identity_mismatch";
  record: OperationStoreRecord;
}>;

type OperationStateConflictResult = Readonly<{
  status: "state_conflict";
  record: OperationStoreRecord;
}>;

export type OperationStartResult = OperationStartedResult | OperationSubmissionUncertainResult;

export type OperationObserveResult =
  | OperationObservedResult
  | OperationObservationUnavailableResult
  | OperationStateConflictResult;

export type OperationRunResult = OperationObserveResult | OperationSubmissionUncertainResult;

export interface OperationRunner {
  /** Starts one fresh operation through durable submission acknowledgement without observing it. */
  readonly startOperation: (input: unknown) => Promise<OperationStartResult>;
  /** Observes only the exact durable operation named by expectedUserOperationHash. */
  readonly observeOperation: (input: unknown) => Promise<OperationObserveResult>;
  /** Terminalizes one exact prepared identity without opening any submission capability. */
  readonly abandonPreparedOperation: (
    input: unknown,
  ) => Promise<OperationStoreCompareAndSwapResult>;
  readonly runOperation: (input: unknown) => Promise<OperationRunResult>;
  readonly close: () => Promise<void>;
}

export interface PreparedOperationRunner extends OperationRunner {
  /**
   * Starts or resumes one caller-retained exact prepared identity without
   * observing it. Once submission was attempted, this method only returns the
   * retained record; it never opens another submission session.
   */
  readonly resumePreparedOperation: (input: unknown) => Promise<OperationStartResult>;
}

type CapturedObserver = Readonly<OperationObserver>;
type CapturedPreparation = Readonly<OperationPreparationCapability>;
type CapturedSubmission = Readonly<OperationSubmissionCapability>;
type CloseResource = { readonly close: () => Promise<unknown>; closed: boolean };

class RunnerTimeout extends Error {}

function runnerError(code: OperationRunnerErrorCode, message: string): never {
  throw new OaathOperationRunnerError(code, message);
}

function captureFailure(code: OperationRunnerErrorCode): (message: string) => never {
  return (message) => runnerError(code, message);
}

function exact(
  value: unknown,
  keys: readonly string[],
  label: string,
  code: OperationRunnerErrorCode,
  context: CaptureContext,
): ExactRecord {
  const fail = captureFailure(code);
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}

function callable(
  value: unknown,
  code: OperationRunnerErrorCode,
): (...args: unknown[]) => Promise<unknown> {
  if (typeof value !== "function") return runnerError(code, "runner capability is invalid");
  return value as (...args: unknown[]) => Promise<unknown>;
}

function captureConfiguration(value: unknown): {
  terminalBehavior: OperationTerminalBehavior;
  requestHash: `0x${string}` | null;
  store: OperationStore;
  observer: CapturedObserver;
  preparation: CapturedPreparation;
  submission: CapturedSubmission;
} {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      ["terminalBehavior", "requestHash", "store", "observer", "preparation", "submission"],
      "OperationRunner configuration",
      "operation_runner_capability_invalid",
      context,
    );
    if (!(record.store instanceof OperationStore)) {
      return runnerError("operation_runner_capability_invalid", "runner store is invalid");
    }
    if (record.terminalBehavior !== "replace" && record.terminalBehavior !== "reuse_same_kind") {
      return runnerError(
        "operation_runner_capability_invalid",
        "runner terminal behavior is invalid",
      );
    }
    if (
      record.requestHash !== null &&
      (typeof record.requestHash !== "string" || !HASH.test(record.requestHash))
    ) {
      return runnerError(
        "operation_runner_capability_invalid",
        "runner request provenance is invalid",
      );
    }
    const observer = exact(
      record.observer,
      ["observeOperation", "close"],
      "OperationRunner observer",
      "operation_runner_capability_invalid",
      context,
    );
    const preparation = exact(
      record.preparation,
      [
        "prepare",
        "reserveOperation",
        "releaseOperationReservation",
        "authorizeOperation",
        "abandonOperation",
        "confirmOperationPublished",
        "close",
      ],
      "OperationRunner preparation",
      "operation_runner_capability_invalid",
      context,
    );
    const submission = exact(
      record.submission,
      ["openSubmission", "close"],
      "OperationRunner submission",
      "operation_runner_capability_invalid",
      context,
    );
    return {
      terminalBehavior: record.terminalBehavior,
      requestHash: record.requestHash as `0x${string}` | null,
      store: record.store,
      observer: Object.freeze({
        observeOperation: callable(
          observer.observeOperation,
          "operation_runner_capability_invalid",
        ) as OperationObserver["observeOperation"],
        close: callable(
          observer.close,
          "operation_runner_capability_invalid",
        ) as OperationObserver["close"],
      }),
      preparation: Object.freeze({
        prepare: callable(
          preparation.prepare,
          "operation_runner_capability_invalid",
        ) as OperationPreparationCapability["prepare"],
        reserveOperation: callable(
          preparation.reserveOperation,
          "operation_runner_capability_invalid",
        ) as OperationPreparationCapability["reserveOperation"],
        releaseOperationReservation: callable(
          preparation.releaseOperationReservation,
          "operation_runner_capability_invalid",
        ) as OperationPreparationCapability["releaseOperationReservation"],
        authorizeOperation: callable(
          preparation.authorizeOperation,
          "operation_runner_capability_invalid",
        ) as OperationPreparationCapability["authorizeOperation"],
        abandonOperation: callable(
          preparation.abandonOperation,
          "operation_runner_capability_invalid",
        ) as OperationPreparationCapability["abandonOperation"],
        confirmOperationPublished: callable(
          preparation.confirmOperationPublished,
          "operation_runner_capability_invalid",
        ) as OperationPreparationCapability["confirmOperationPublished"],
        close: callable(
          preparation.close,
          "operation_runner_capability_invalid",
        ) as OperationPreparationCapability["close"],
      }),
      submission: Object.freeze({
        openSubmission: callable(
          submission.openSubmission,
          "operation_runner_capability_invalid",
        ) as OperationSubmissionCapability["openSubmission"],
        close: callable(
          submission.close,
          "operation_runner_capability_invalid",
        ) as OperationSubmissionCapability["close"],
      }),
    };
  } catch (error) {
    if (error instanceof OaathOperationRunnerError) throw error;
    return runnerError(
      "operation_runner_capability_invalid",
      "OperationRunner configuration is invalid",
    );
  }
}

function parseKind(value: unknown): OperationKind {
  if (value !== "execution" && value !== "revocation") {
    return runnerError("operation_runner_input_invalid", "runner operation kind is invalid");
  }
  return value;
}

function parseKey(value: unknown, context: CaptureContext): Readonly<OperationStoreKey> {
  const record = exact(
    value,
    ["grantId", "chainId", "kind"],
    "OperationRunner key",
    "operation_runner_input_invalid",
    context,
  );
  if (
    typeof record.grantId !== "string" ||
    record.grantId.length < 1 ||
    record.grantId.length > MAX_GRANT_ID_LENGTH ||
    record.grantId !== record.grantId.trim() ||
    typeof record.chainId !== "number" ||
    !Number.isSafeInteger(record.chainId) ||
    record.chainId < 1
  ) {
    return runnerError("operation_runner_input_invalid", "runner key is invalid");
  }
  return Object.freeze({
    grantId: record.grantId,
    chainId: record.chainId,
    kind: parseKind(record.kind),
  });
}

function safeTime(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return runnerError("operation_runner_input_invalid", "runner time is invalid");
  }
  return value;
}

const RUN_INPUT_KEYS = [
  "kind",
  "key",
  "preparedAt",
  "attemptedAt",
  "submittedAt",
  "observedAt",
  "timeoutMs",
] as const;

function parseCapturedRunInput(record: ExactRecord, context: CaptureContext): OperationRunInput {
  const preparedAt = safeTime(record.preparedAt);
  const attemptedAt = safeTime(record.attemptedAt);
  const submittedAt = safeTime(record.submittedAt);
  const observedAt = safeTime(record.observedAt);
  if (
    preparedAt > attemptedAt ||
    attemptedAt > submittedAt ||
    submittedAt > observedAt ||
    typeof record.timeoutMs !== "number" ||
    !Number.isSafeInteger(record.timeoutMs) ||
    record.timeoutMs < 1 ||
    record.timeoutMs > 60_000
  ) {
    return runnerError("operation_runner_input_invalid", "runner ordering is invalid");
  }
  const kind = parseKind(record.kind);
  const key = parseKey(record.key, context);
  // The kind is part of the lane: a run can never prepare one kind of work
  // under the other kind's durable journal.
  if (key.kind !== kind) {
    return runnerError("operation_runner_input_invalid", "runner key kind conflicts with run kind");
  }
  return Object.freeze({
    kind,
    key,
    preparedAt,
    attemptedAt,
    submittedAt,
    observedAt,
    timeoutMs: record.timeoutMs,
  });
}

function parseRunInput(value: unknown): OperationRunInput {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      RUN_INPUT_KEYS,
      "OperationRunner input",
      "operation_runner_input_invalid",
      context,
    );
    return parseCapturedRunInput(record, context);
  } catch (error) {
    if (error instanceof OaathOperationRunnerError) throw error;
    return runnerError("operation_runner_input_invalid", "OperationRunner input is invalid");
  }
}

function parseObserveInput(value: unknown): OperationObserveInput {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      [...RUN_INPUT_KEYS, "expectedUserOperationHash"],
      "OperationRunner observation input",
      "operation_runner_input_invalid",
      context,
    );
    const input = parseCapturedRunInput(record, context);
    if (
      typeof record.expectedUserOperationHash !== "string" ||
      !HASH.test(record.expectedUserOperationHash)
    ) {
      return runnerError(
        "operation_runner_input_invalid",
        "expected UserOperation hash is invalid",
      );
    }
    return Object.freeze({
      ...input,
      expectedUserOperationHash: record.expectedUserOperationHash as `0x${string}`,
    });
  } catch (error) {
    if (error instanceof OaathOperationRunnerError) throw error;
    return runnerError(
      "operation_runner_input_invalid",
      "OperationRunner observation input is invalid",
    );
  }
}

function parseAbandonPreparedInput(value: unknown): OperationAbandonPreparedInput {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      ["kind", "key", "expectedUserOperationHash", "abandonedAt"],
      "OperationRunner abandonment input",
      "operation_runner_input_invalid",
      context,
    );
    const kind = parseKind(record.kind);
    const key = parseKey(record.key, context);
    if (key.kind !== kind) {
      return runnerError(
        "operation_runner_input_invalid",
        "runner key kind conflicts with abandonment kind",
      );
    }
    if (
      typeof record.expectedUserOperationHash !== "string" ||
      !HASH.test(record.expectedUserOperationHash)
    ) {
      return runnerError(
        "operation_runner_input_invalid",
        "expected UserOperation hash is invalid",
      );
    }
    const abandonedAt = safeTime(record.abandonedAt);
    if (Object.is(abandonedAt, -0)) {
      return runnerError("operation_runner_input_invalid", "runner abandonment time is invalid");
    }
    return Object.freeze({
      kind,
      key,
      expectedUserOperationHash: record.expectedUserOperationHash as `0x${string}`,
      abandonedAt,
    });
  } catch (error) {
    if (error instanceof OaathOperationRunnerError) throw error;
    return runnerError(
      "operation_runner_input_invalid",
      "OperationRunner abandonment input is invalid",
    );
  }
}

function sameIdentity(left: OperationIdentity, right: OperationIdentity): boolean {
  return (
    left.kind === right.kind &&
    left.grantId === right.grantId &&
    left.chainId === right.chainId &&
    left.entryPoint === right.entryPoint &&
    left.account === right.account &&
    left.nonce === right.nonce &&
    left.userOperationHash === right.userOperationHash &&
    left.requestHash === right.requestHash
  );
}

function sameOperation(left: Operation, right: Operation): boolean {
  return JSON.stringify(parseOperation(left)) === JSON.stringify(parseOperation(right));
}

function deriveObservedOperation(
  current: Operation,
  observation: ObserveOperationResult,
): Operation | null {
  try {
    if (sameOperation(current, observation.operation)) {
      return observation.status === "included" ||
        observation.status === "finalized" ||
        observation.status === "dropped" ||
        observation.status === "superseded" ||
        observation.status === "abandoned"
        ? current
        : null;
    }

    if (observation.status === "abandoned") return null;

    let next = current;
    if (
      observation.status !== "included" &&
      (observation.operation.state === "included" || observation.operation.state === "finalized")
    ) {
      if (next.state !== "included") {
        next = applyVerifiedOperationObservation(next, {
          type: "record_included",
          identity: next.identity,
          inclusion: observation.operation.inclusion,
        });
      }
    }

    if (observation.status === "pending" || observation.status === "unreadable") {
      const weak = observation.operation.observation;
      if (!weak) return null;
      next = applyVerifiedOperationObservation(next, {
        type: observation.status === "pending" ? "record_pending" : "record_unreadable",
        identity: next.identity,
        observedAt: weak.observedAt,
        reason: observation.reason,
      });
    } else if (observation.status === "included") {
      next = applyVerifiedOperationObservation(next, {
        type: "record_included",
        identity: next.identity,
        inclusion: observation.operation.inclusion,
      });
    } else if (observation.status === "finalized") {
      next = applyVerifiedOperationObservation(next, {
        type: "record_finalized",
        identity: next.identity,
        finality: observation.operation.finality,
      });
    } else if (observation.status === "superseded") {
      next = applyVerifiedOperationObservation(next, {
        type: "record_superseded",
        identity: next.identity,
        supersession: observation.operation.supersession,
      });
    } else {
      next = applyVerifiedOperationObservation(next, {
        type: "record_dropped",
        identity: next.identity,
        drop: observation.operation.drop,
      });
    }
    const canonical = parseOperation(next);
    return sameOperation(canonical, observation.operation) ? canonical : null;
  } catch {
    return null;
  }
}

function requireLane(operation: Operation, input: Pick<OperationRunInput, "kind" | "key">): void {
  if (
    operation.identity.kind !== input.kind ||
    operation.identity.grantId !== input.key.grantId ||
    operation.identity.chainId !== input.key.chainId
  ) {
    runnerError("operation_runner_state_conflict", "stored Operation belongs to another run");
  }
}

function mapStoreError(error: unknown): never {
  if (error instanceof OaathStoreError && error.code === "store_identity_mismatch") {
    return runnerError("operation_runner_state_conflict", "Operation identity is already retained");
  }
  if (
    error instanceof OaathStoreError &&
    (error.code === "store_commit_indeterminate" || error.code === "store_commit_unverified")
  ) {
    return runnerError("operation_runner_store_uncertain", "Operation store commit is uncertain");
  }
  return runnerError("operation_runner_store_unavailable", "Operation store is unavailable");
}

function parseSubmissionSession(value: unknown): OperationSubmissionSession {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      ["submit", "close"],
      "Operation submission session",
      "operation_runner_capability_invalid",
      context,
    );
    return Object.freeze({
      submit: callable(
        record.submit,
        "operation_runner_capability_invalid",
      ) as OperationSubmissionSession["submit"],
      close: callable(
        record.close,
        "operation_runner_capability_invalid",
      ) as OperationSubmissionSession["close"],
    });
  } catch {
    return runnerError(
      "operation_runner_capability_invalid",
      "Operation submission session is invalid",
    );
  }
}

function parseReturnedHash(value: unknown): `0x${string}` | null {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      ["userOperationHash"],
      "Operation submission result",
      "operation_runner_capability_invalid",
      context,
    );
    return typeof record.userOperationHash === "string" && HASH.test(record.userOperationHash)
      ? (record.userOperationHash as `0x${string}`)
      : null;
  } catch {
    return null;
  }
}

function captureObservation(value: unknown): ObserveOperationResult | null {
  try {
    const context: CaptureContext = new WeakSet();
    const captured = captureRecord(
      value,
      "Operation observation result",
      context,
      captureFailure("operation_runner_capability_invalid"),
    );
    const status = captured.status;
    const keys =
      status === "pending" || status === "unreadable"
        ? ["status", "reason", "operation"]
        : ["status", "operation"];
    const record = exactCapturedRecord(
      captured,
      keys,
      "Operation observation result",
      captureFailure("operation_runner_capability_invalid"),
    );
    const operation = parseOperation(record.operation);
    if (
      status === "pending" &&
      (record.reason === "receipt_missing" || record.reason === "timeout") &&
      operation.observation?.status === "pending" &&
      operation.observation.reason === record.reason
    ) {
      return Object.freeze({ status, reason: record.reason, operation });
    }
    if (
      status === "unreadable" &&
      (record.reason === "provider_unavailable" ||
        record.reason === "receipt_invalid" ||
        record.reason === "canonicality_unproven" ||
        record.reason === "finality_unproven") &&
      operation.observation?.status === "unreadable" &&
      operation.observation.reason === record.reason
    ) {
      return Object.freeze({ status, reason: record.reason, operation });
    }
    if (status === "included" && operation.state === "included" && operation.observation === null) {
      return Object.freeze({ status, operation });
    }
    if (status === "finalized" && operation.state === "finalized") {
      return Object.freeze({ status, operation });
    }
    if (status === "dropped" && operation.state === "dropped") {
      return Object.freeze({ status, operation });
    }
    if (status === "superseded" && operation.state === "superseded") {
      return Object.freeze({ status, operation });
    }
    if (status === "abandoned" && operation.state === "abandoned") {
      return Object.freeze({ status, operation });
    }
    return null;
  } catch {
    return null;
  }
}

function retainedObservation(operation: Operation): ObserveOperationResult | null {
  if (operation.state === "finalized") {
    return Object.freeze({ status: "finalized" as const, operation });
  }
  if (operation.state === "included") {
    return Object.freeze({ status: "included" as const, operation });
  }
  if (operation.state === "dropped") {
    return Object.freeze({ status: "dropped" as const, operation });
  }
  if (operation.state === "superseded") {
    return Object.freeze({ status: "superseded" as const, operation });
  }
  if (operation.state === "abandoned") {
    return Object.freeze({ status: "abandoned" as const, operation });
  }
  const observation = operation.observation;
  if (observation?.status === "pending") {
    return Object.freeze({
      status: "pending" as const,
      reason: observation.reason,
      operation,
    });
  }
  if (observation?.status === "unreadable") {
    return Object.freeze({
      status: "unreadable" as const,
      reason: observation.reason,
      operation,
    });
  }
  return null;
}

function frozenResult<Result extends OperationRunResult | OperationStartResult>(
  result: Result,
): Result {
  return Object.freeze(result);
}

async function withTimeout<Value>(action: () => Promise<Value>, timeoutMs: number): Promise<Value> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(action),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new RunnerTimeout()), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Transfers ownership of the dedicated store, observer, preparation, and submission resources. */
export function createOperationRunner(configurationValue: unknown): PreparedOperationRunner {
  const configuration = captureConfiguration(configurationValue);
  const sessions: CloseResource[] = [];
  const resources: CloseResource[] = [
    { close: configuration.submission.close, closed: false },
    { close: configuration.preparation.close, closed: false },
    { close: configuration.observer.close, closed: false },
    { close: () => configuration.store.close(), closed: false },
  ];
  let activeRuns = 0;
  let drained: (() => void) | null = null;
  let closeRequested = false;
  let closed = false;
  let closing: Promise<void> | null = null;

  async function getRecord(
    key: Readonly<OperationStoreKey>,
  ): Promise<OperationStoreRecord | undefined> {
    try {
      return await configuration.store.get(key);
    } catch (error) {
      return mapStoreError(error);
    }
  }

  async function getExactRecord(
    key: Readonly<OperationStoreKey>,
    expectedUserOperationHash: `0x${string}`,
  ): Promise<OperationStoreRecord | undefined> {
    try {
      return await configuration.store.getExact(key, expectedUserOperationHash);
    } catch (error) {
      return mapStoreError(error);
    }
  }

  async function commit(
    key: Readonly<OperationStoreKey>,
    expectedStoreRevision: number | null,
    next: Operation,
  ): Promise<OperationStoreCompareAndSwapResult> {
    try {
      return await configuration.store.compareAndSwap({ key, expectedStoreRevision, next });
    } catch (error) {
      return mapStoreError(error);
    }
  }

  async function publishPrepared(
    input: OperationRunInput,
    current: OperationStoreRecord | undefined,
    prepared: PreparedUserOperation,
    conflictBehavior: "resume" | "reject",
  ): Promise<OperationStoreRecord> {
    const operation = createOperation({
      identity: deriveOperationId(prepared, configuration.requestHash),
      preparedAt: input.preparedAt,
    });
    if (current && sameIdentity(current.value.identity, operation.identity)) {
      await releasePreparedReservation(prepared);
      return runnerError(
        "operation_runner_state_conflict",
        "terminal Operation identity cannot be restarted",
      );
    }

    let expectedStoreRevision = current?.storeRevision ?? null;
    const attempts = conflictBehavior === "resume" ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      let persisted: OperationStoreCompareAndSwapResult;
      try {
        persisted = await commit(input.key, expectedStoreRevision, operation);
      } catch (error) {
        if (
          error instanceof OaathOperationRunnerError &&
          error.code === "operation_runner_state_conflict"
        ) {
          await releasePreparedReservation(prepared);
        }
        throw error;
      }
      if (persisted.status === "committed") return persisted.record;
      const conflict = persisted.current;
      if (!conflict) {
        return runnerError(
          "operation_runner_store_uncertain",
          "Operation store conflict has no durable record",
        );
      }
      if (conflictBehavior === "reject") {
        await releasePreparedReservation(prepared);
        return runnerError(
          "operation_runner_state_conflict",
          "another Operation occupies the requested lane",
        );
      }
      if (sameIdentity(conflict.value.identity, operation.identity)) return conflict;
      if (attempt === 0 && !operationOccupiesLane(conflict.value)) {
        expectedStoreRevision = conflict.storeRevision;
        continue;
      }
      await releasePreparedReservation(prepared);
      return runnerError(
        "operation_runner_state_conflict",
        "another Operation occupies the requested lane",
      );
    }
    await releasePreparedReservation(prepared);
    return runnerError("operation_runner_state_conflict", "Operation publish did not converge");
  }

  function requireConflictIdentity(
    record: OperationStoreRecord | undefined,
    identity: OperationIdentity,
  ): OperationStoreRecord {
    if (!record) {
      return runnerError(
        "operation_runner_store_uncertain",
        "Operation store conflict has no durable record",
      );
    }
    if (!sameIdentity(record.value.identity, identity)) {
      return runnerError(
        "operation_runner_state_conflict",
        "another Operation occupies the requested lane",
      );
    }
    return record;
  }

  async function prepareExact(
    input: OperationRunInput,
    expectedIdentity?: OperationIdentity,
  ): Promise<PreparedUserOperation> {
    let raw: unknown;
    try {
      raw = await configuration.preparation.prepare(
        Object.freeze({ kind: input.kind, key: input.key }),
      );
    } catch {
      return runnerError("operation_runner_preparation_failed", "Operation preparation failed");
    }
    let prepared: PreparedUserOperation;
    try {
      prepared = parsePreparedUserOperation(raw);
    } catch {
      return runnerError(
        "operation_runner_preparation_failed",
        "Operation preparation result is invalid",
      );
    }
    const identity = deriveOperationId(prepared, configuration.requestHash);
    if (
      identity.kind !== input.kind ||
      identity.grantId !== input.key.grantId ||
      identity.chainId !== input.key.chainId ||
      (expectedIdentity && !sameIdentity(identity, expectedIdentity))
    ) {
      return runnerError(
        "operation_runner_identity_mismatch",
        "prepared Operation identity does not match the durable run",
      );
    }
    return prepared;
  }

  async function reservePreparedOperation(prepared: PreparedUserOperation): Promise<void> {
    try {
      await configuration.preparation.reserveOperation(prepared);
    } catch {
      return runnerError(
        "operation_runner_preparation_failed",
        "Operation publication reservation failed",
      );
    }
  }

  async function releasePreparedReservation(prepared: PreparedUserOperation): Promise<void> {
    try {
      await configuration.preparation.releaseOperationReservation(prepared);
    } catch {
      // The conclusive publication result remains canonical. The caller-owned
      // reservation is still recoverable through its durable lease.
    }
  }

  async function confirmPreparedPublication(
    input: OperationRunInput,
    record: OperationStoreRecord,
    prepared: PreparedUserOperation,
  ): Promise<void> {
    try {
      await configuration.preparation.confirmOperationPublished(prepared);
      return;
    } catch {
      // Publication is durable but the caller-owned reference did not confirm.
      // Release every exact pre-submission owner only after abandonment commits.
      await abandonBeforeSubmission(input, record, prepared);
      return runnerError(
        "operation_runner_preparation_failed",
        "Operation publication confirmation failed",
      );
    }
  }

  async function abandonBeforeSubmission(
    input: OperationRunInput,
    record: OperationStoreRecord,
    prepared: PreparedUserOperation,
  ): Promise<void> {
    const abandoned = advanceOperation(record.value, {
      type: "mark_abandoned",
      identity: record.value.identity,
      abandonedAt: input.attemptedAt,
      reason: "submission_not_attempted",
    });
    const persisted = await commit(input.key, record.storeRevision, abandoned);
    if (persisted.status === "conflict") {
      const current = requireConflictIdentity(persisted.current, record.value.identity);
      if (current.value.state !== "abandoned") {
        return runnerError(
          "operation_runner_state_conflict",
          "Operation abandonment lost the prepared identity",
        );
      }
    }
    await configuration.preparation.abandonOperation(prepared).catch(() => undefined);
  }

  async function authorizePreparedOperation(
    input: OperationRunInput,
    record: OperationStoreRecord,
    prepared: PreparedUserOperation,
  ): Promise<void> {
    try {
      await configuration.preparation.authorizeOperation(prepared);
    } catch {
      await abandonBeforeSubmission(input, record, prepared);
      return runnerError(
        "operation_runner_preparation_failed",
        "Operation publication authority was not admitted",
      );
    }
  }

  async function observe(
    record: OperationStoreRecord,
    input: OperationRunInput,
    conflictAttempt = 0,
  ): Promise<OperationObserveResult> {
    let raw: unknown;
    try {
      raw = await configuration.observer.observeOperation({
        operation: record.value,
        observedAt: Math.max(input.observedAt, record.value.updatedAt),
        timeoutMs: input.timeoutMs,
      });
    } catch {
      return frozenResult({
        status: "observation_unavailable",
        reason: "observer_failed",
        record,
      });
    }
    const observation = captureObservation(raw);
    if (!observation) {
      return frozenResult({
        status: "observation_unavailable",
        reason: "result_invalid",
        record,
      });
    }
    if (!sameIdentity(observation.operation.identity, record.value.identity)) {
      return frozenResult({
        status: "observation_unavailable",
        reason: "identity_mismatch",
        record,
      });
    }
    const derived = deriveObservedOperation(record.value, observation);
    if (!derived) {
      return frozenResult({
        status: "observation_unavailable",
        reason: "result_invalid",
        record,
      });
    }
    if (sameOperation(derived, record.value)) {
      return frozenResult({ status: "observed", observation, record });
    }
    const persisted = await commit(input.key, record.storeRevision, derived);
    if (persisted.status === "committed") {
      return frozenResult({ status: "observed", observation, record: persisted.record });
    }
    const current = requireConflictIdentity(persisted.current, record.value.identity);
    if (sameOperation(current.value, derived)) {
      return frozenResult({ status: "observed", observation, record: current });
    }
    // Another observer may have advanced the same exact identity. Re-observe
    // that retained state; this path is read-only and can never submit.
    if (conflictAttempt < 2) return observe(current, input, conflictAttempt + 1);
    const retained = retainedObservation(current.value);
    return retained
      ? frozenResult({ status: "observed", observation: retained, record: current })
      : frozenResult({
          status: "observation_unavailable",
          reason: "result_invalid",
          record: current,
        });
  }

  async function withActiveRun<Result>(action: () => Promise<Result>): Promise<Result> {
    if (closeRequested || closed || closing) {
      return runnerError("operation_runner_closed", "OperationRunner is closing or closed");
    }
    activeRuns += 1;
    try {
      return await action();
    } finally {
      activeRuns -= 1;
      if (activeRuns === 0 && drained) {
        const resolve = drained;
        drained = null;
        resolve();
      }
    }
  }

  function executeOperation(inputValue: unknown, mode: "start"): Promise<OperationStartResult>;
  function executeOperation(inputValue: unknown, mode: "resume"): Promise<OperationStartResult>;
  function executeOperation(inputValue: unknown, mode: "run"): Promise<OperationRunResult>;
  async function executeOperation(
    inputValue: unknown,
    mode: "start" | "resume" | "run",
  ): Promise<OperationStartResult | OperationRunResult> {
    let input: OperationRunInput;
    let expectedUserOperationHash: `0x${string}` | null = null;
    if (mode === "resume") {
      const captured = parseObserveInput(inputValue);
      input = captured;
      expectedUserOperationHash = captured.expectedUserOperationHash;
    } else {
      input = parseRunInput(inputValue);
    }
    let record = await getRecord(input.key);
    let prepared: PreparedUserOperation | undefined;

    if (mode === "start") {
      if (record && operationOccupiesLane(record.value)) {
        return runnerError(
          "operation_runner_state_conflict",
          "another Operation occupies the requested lane",
        );
      }
      prepared = await prepareExact(input);
      await reservePreparedOperation(prepared);
      record = await publishPrepared(input, record, prepared, "reject");
    } else if (mode === "resume") {
      prepared = await prepareExact(input);
      const expectedIdentity = deriveOperationId(prepared, configuration.requestHash);
      if (expectedIdentity.userOperationHash !== expectedUserOperationHash) {
        return runnerError(
          "operation_runner_identity_mismatch",
          "prepared Operation does not match the expected UserOperation hash",
        );
      }
      if (record && operationOccupiesLane(record.value)) {
        requireLane(record.value, input);
        if (!sameIdentity(record.value.identity, expectedIdentity)) {
          return runnerError(
            "operation_runner_state_conflict",
            "another Operation occupies the requested lane",
          );
        }
        if (record.value.state !== "prepared") {
          return frozenResult({ status: "started", record });
        }
        // A recreated producer must reacquire its caller-owned publication
        // reference before the retained prepared Operation can advance. The
        // reference owner decides whether this is an idempotent reacquisition.
        await reservePreparedOperation(prepared);
      } else {
        await reservePreparedOperation(prepared);
        record = await publishPrepared(input, record, prepared, "resume");
      }
    } else {
      if (
        record &&
        !operationOccupiesLane(record.value) &&
        configuration.terminalBehavior === "reuse_same_kind" &&
        record.value.identity.kind === input.kind
      ) {
        requireLane(record.value, input);
        return observe(record, input);
      }

      if (!record || !operationOccupiesLane(record.value)) {
        prepared = await prepareExact(input);
        await reservePreparedOperation(prepared);
        record = await publishPrepared(input, record, prepared, "resume");
      }
    }

    requireLane(record.value, input);
    if (record.value.state !== "prepared") {
      if (mode === "start") {
        return runnerError(
          "operation_runner_state_conflict",
          "fresh Operation did not retain the requested lane",
        );
      }
      if (mode === "resume") return frozenResult({ status: "started", record });
      return observe(record, input);
    }
    prepared ??= await prepareExact(input, record.value.identity);
    await authorizePreparedOperation(input, record, prepared);
    await confirmPreparedPublication(input, record, prepared);

    const attempted = advanceOperation(record.value, {
      type: "mark_submission_attempted",
      identity: record.value.identity,
      attemptedAt: input.attemptedAt,
    });
    const attemptedCommit = await commit(input.key, record.storeRevision, attempted);
    if (attemptedCommit.status === "conflict") {
      const current = requireConflictIdentity(attemptedCommit.current, record.value.identity);
      if (mode === "start") {
        return runnerError(
          "operation_runner_state_conflict",
          "fresh Operation lost the requested lane",
        );
      }
      if (mode === "resume") {
        if (current.value.state === "prepared") {
          return runnerError(
            "operation_runner_state_conflict",
            "prepared Operation did not advance to submission",
          );
        }
        return frozenResult({ status: "started", record: current });
      }
      return current.value.state === "prepared"
        ? frozenResult({ status: "state_conflict", record: current })
        : observe(current, input);
    }
    record = attemptedCommit.record;

    let sessionValue: unknown;
    try {
      sessionValue = await withTimeout(
        () => configuration.submission.openSubmission(prepared),
        input.timeoutMs,
      );
    } catch {
      return frozenResult({
        status: "submission_uncertain",
        reason: "session_unavailable",
        record,
      });
    }
    let session: OperationSubmissionSession;
    try {
      session = parseSubmissionSession(sessionValue);
    } catch {
      return frozenResult({
        status: "submission_uncertain",
        reason: "session_invalid",
        record,
      });
    }
    const sessionResource: CloseResource = { close: session.close, closed: false };
    sessions.push(sessionResource);

    let submissionValue: unknown;
    try {
      submissionValue = await withTimeout(session.submit, input.timeoutMs);
    } catch {
      return frozenResult({
        status: "submission_uncertain",
        reason: "send_ambiguous",
        record,
      });
    }
    const returnedHash = parseReturnedHash(submissionValue);
    if (!returnedHash) {
      return frozenResult({
        status: "submission_uncertain",
        reason: "result_invalid",
        record,
      });
    }
    if (returnedHash !== record.value.identity.userOperationHash) {
      return frozenResult({
        status: "submission_uncertain",
        reason: "identity_mismatch",
        record,
      });
    }

    let submittedRecord = record;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      if (submittedRecord.value.state !== "submission_attempted") break;
      const submitted = advanceOperation(submittedRecord.value, {
        type: "mark_submitted",
        identity: submittedRecord.value.identity,
        returnedUserOperationHash: returnedHash,
        submittedAt: Math.max(input.submittedAt, submittedRecord.value.updatedAt),
      });
      const submittedCommit = await commit(input.key, submittedRecord.storeRevision, submitted);
      if (submittedCommit.status === "committed") {
        submittedRecord = submittedCommit.record;
        break;
      }
      // Concurrent observation may advance this exact identity after send. It
      // cannot authorize another send, and the returned exact hash still lets
      // submission acknowledgement converge against the retained revision.
      submittedRecord = requireConflictIdentity(submittedCommit.current, record.value.identity);
    }
    return mode === "start" || mode === "resume"
      ? frozenResult({ status: "started", record: submittedRecord })
      : observe(submittedRecord, input);
  }

  async function startOperation(inputValue: unknown): Promise<OperationStartResult> {
    return withActiveRun(() => executeOperation(inputValue, "start"));
  }

  async function resumePreparedOperation(inputValue: unknown): Promise<OperationStartResult> {
    return withActiveRun(() => executeOperation(inputValue, "resume"));
  }

  async function observeOperation(inputValue: unknown): Promise<OperationObserveResult> {
    return withActiveRun(async () => {
      const input = parseObserveInput(inputValue);
      const record = await getExactRecord(input.key, input.expectedUserOperationHash);
      if (!record) {
        const current = await getRecord(input.key);
        if (current) {
          return runnerError(
            "operation_runner_identity_mismatch",
            "stored Operation does not match the expected UserOperation hash",
          );
        }
        return runnerError(
          "operation_runner_state_conflict",
          "expected Operation is absent from the requested lane",
        );
      }
      requireLane(record.value, input);
      if (record.value.identity.userOperationHash !== input.expectedUserOperationHash) {
        return runnerError(
          "operation_runner_identity_mismatch",
          "stored Operation does not match the expected UserOperation hash",
        );
      }
      if (record.value.state === "prepared") {
        return runnerError(
          "operation_runner_state_conflict",
          "prepared Operation has not entered submission",
        );
      }
      return observe(record, input);
    });
  }

  async function abandonPreparedOperation(
    inputValue: unknown,
  ): Promise<OperationStoreCompareAndSwapResult> {
    return withActiveRun(async () => {
      const input = parseAbandonPreparedInput(inputValue);
      const record = await getRecord(input.key);
      if (!record) {
        return runnerError(
          "operation_runner_state_conflict",
          "expected prepared Operation is absent from the requested lane",
        );
      }
      requireLane(record.value, input);
      if (record.value.identity.userOperationHash !== input.expectedUserOperationHash) {
        return runnerError(
          "operation_runner_identity_mismatch",
          "stored Operation does not match the expected UserOperation hash",
        );
      }
      if (record.value.state !== "prepared") {
        return runnerError(
          "operation_runner_state_conflict",
          "expected Operation is no longer prepared",
        );
      }
      const abandoned = advanceOperation(record.value, {
        type: "mark_abandoned",
        identity: record.value.identity,
        abandonedAt: input.abandonedAt,
        reason: "submission_not_attempted",
      });
      return commit(input.key, record.storeRevision, abandoned);
    });
  }

  async function runOperation(inputValue: unknown): Promise<OperationRunResult> {
    return withActiveRun(() => executeOperation(inputValue, "run"));
  }

  async function close(): Promise<void> {
    if (closed) return;
    closeRequested = true;
    if (closing) return closing;
    const attempt = Promise.resolve()
      .then(async () => {
        if (activeRuns > 0) {
          await new Promise<void>((resolve) => {
            drained = resolve;
          });
        }
        let failed = false;
        for (const resource of [...sessions, ...resources]) {
          if (resource.closed) continue;
          try {
            await resource.close();
            resource.closed = true;
          } catch {
            failed = true;
          }
        }
        if (failed) {
          return runnerError(
            "operation_runner_close_failed",
            "OperationRunner cleanup is incomplete",
          );
        }
        closed = true;
      })
      .finally(() => {
        if (!closed) closing = null;
      });
    closing = attempt;
    return attempt;
  }

  return Object.freeze({
    startOperation,
    resumePreparedOperation,
    observeOperation,
    abandonPreparedOperation,
    runOperation,
    close,
  });
}
