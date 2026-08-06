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
  readonly runOperation: (input: unknown) => Promise<OperationRunResult>;
  readonly close: () => Promise<void>;
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
  store: OperationStore;
  observer: CapturedObserver;
  preparation: CapturedPreparation;
  submission: CapturedSubmission;
} {
  try {
    const context: CaptureContext = new WeakSet();
    const record = exact(
      value,
      ["terminalBehavior", "store", "observer", "preparation", "submission"],
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
    const observer = exact(
      record.observer,
      ["observeOperation", "close"],
      "OperationRunner observer",
      "operation_runner_capability_invalid",
      context,
    );
    const preparation = exact(
      record.preparation,
      ["prepare", "close"],
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

function sameIdentity(left: OperationIdentity, right: OperationIdentity): boolean {
  return (
    left.kind === right.kind &&
    left.grantId === right.grantId &&
    left.chainId === right.chainId &&
    left.entryPoint === right.entryPoint &&
    left.account === right.account &&
    left.nonce === right.nonce &&
    left.userOperationHash === right.userOperationHash
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
        observation.status === "superseded"
        ? current
        : null;
    }

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

function requireLane(operation: Operation, input: OperationRunInput): void {
  if (
    operation.identity.kind !== input.kind ||
    operation.identity.grantId !== input.key.grantId ||
    operation.identity.chainId !== input.key.chainId
  ) {
    runnerError("operation_runner_state_conflict", "stored Operation belongs to another run");
  }
}

function mapStoreError(error: unknown): never {
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
    return null;
  } catch {
    return null;
  }
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
export function createOperationRunner(configurationValue: unknown): OperationRunner {
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
      identity: deriveOperationId(prepared),
      preparedAt: input.preparedAt,
    });
    if (current && sameIdentity(current.value.identity, operation.identity)) {
      return runnerError(
        "operation_runner_state_conflict",
        "terminal Operation identity cannot be restarted",
      );
    }

    let expectedStoreRevision = current?.storeRevision ?? null;
    const attempts = conflictBehavior === "resume" ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const persisted = await commit(input.key, expectedStoreRevision, operation);
      if (persisted.status === "committed") return persisted.record;
      const conflict = persisted.current;
      if (!conflict) {
        return runnerError(
          "operation_runner_store_uncertain",
          "Operation store conflict has no durable record",
        );
      }
      if (conflictBehavior === "reject") {
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
      return runnerError(
        "operation_runner_state_conflict",
        "another Operation occupies the requested lane",
      );
    }
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
    const identity = deriveOperationId(prepared);
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

  async function observe(
    record: OperationStoreRecord,
    input: OperationRunInput,
  ): Promise<OperationObserveResult> {
    let raw: unknown;
    try {
      raw = await configuration.observer.observeOperation({
        operation: record.value,
        observedAt: input.observedAt,
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
    return frozenResult({ status: "state_conflict", record: current });
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
  function executeOperation(inputValue: unknown, mode: "run"): Promise<OperationRunResult>;
  async function executeOperation(
    inputValue: unknown,
    mode: "start" | "run",
  ): Promise<OperationStartResult | OperationRunResult> {
    const input = parseRunInput(inputValue);
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
      record = await publishPrepared(input, record, prepared, "reject");
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
      return observe(record, input);
    }
    prepared ??= await prepareExact(input, record.value.identity);

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

    const submitted = advanceOperation(record.value, {
      type: "mark_submitted",
      identity: record.value.identity,
      returnedUserOperationHash: returnedHash,
      submittedAt: input.submittedAt,
    });
    const submittedCommit = await commit(input.key, record.storeRevision, submitted);
    if (submittedCommit.status === "conflict") {
      const current = requireConflictIdentity(submittedCommit.current, record.value.identity);
      if (mode === "start") {
        return runnerError(
          "operation_runner_state_conflict",
          "fresh Operation submission conflicted with durable state",
        );
      }
      return observe(current, input);
    }
    return mode === "start"
      ? frozenResult({ status: "started", record: submittedCommit.record })
      : observe(submittedCommit.record, input);
  }

  async function startOperation(inputValue: unknown): Promise<OperationStartResult> {
    return withActiveRun(() => executeOperation(inputValue, "start"));
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

  return Object.freeze({ startOperation, observeOperation, runOperation, close });
}
