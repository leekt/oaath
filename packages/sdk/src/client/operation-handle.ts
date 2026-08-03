/**
 * The application-facing view of one operation.
 *
 * It exposes waiting and observing, and nothing that could send: the handle
 * holds an `OperationRunner` configured with `reuse_same_kind`, so a terminal
 * record is observed again and a record left unresolved by a crash resumes
 * through the runner's own semantics. Observation never submits, and a timeout,
 * missing receipt, or unreadable provider is reported as such instead of being
 * retried as a send.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { Operation, OperationKind, OperationOutcome } from "@oaath/protocol";
import type { OperationRunner, OperationRunResult } from "../operation-runner.js";
import type { OperationStoreKey } from "../store.js";
import { clientFail, exactClientRecord, mapClientFailure } from "./errors.js";

const MAX_ATTEMPTS = 16;

export type OaathOperationStatus = "finalized" | "dropped" | "pending" | "unreadable";

export interface OaathOperationOutcome {
  readonly status: OaathOperationStatus;
  readonly state: Operation["state"];
  readonly transactionHash: `0x${string}` | null;
  readonly blockNumber: string | null;
  readonly outcome: OperationOutcome | null;
  /** Structured reason when the operation is not terminal; never prose. */
  readonly reason: string | null;
}

export interface OaathOperationHandle {
  readonly chainId: number;
  /** Outcome of the run that produced this handle. */
  readonly outcome: Readonly<OaathOperationOutcome>;
  /** One read-only observation pass. */
  readonly observe: () => Promise<Readonly<OaathOperationOutcome>>;
  /** Observes until terminal or the attempt bound is reached. Submits nothing. */
  readonly wait: (input?: unknown) => Promise<Readonly<OaathOperationOutcome>>;
  readonly close: () => Promise<void>;
}

export interface CreateOperationHandleInput {
  readonly runner: OperationRunner;
  readonly key: Readonly<OperationStoreKey>;
  readonly kind: OperationKind;
  readonly timeoutMs: number;
  readonly now: () => number;
  readonly initial: OperationRunResult;
}

/**
 * The inclusion this operation claims: its own, or the inclusion a dropped
 * operation had before it was replaced. Both are chain-local evidence bound to
 * this exact identity by the aggregate that recorded them.
 */
function evidence(operation: Operation): Readonly<{
  transactionHash: `0x${string}` | null;
  blockNumber: string | null;
  outcome: OperationOutcome | null;
}> {
  const inclusion =
    operation.state === "included" || operation.state === "finalized"
      ? operation.inclusion
      : operation.state === "dropped"
        ? operation.priorInclusion
        : null;
  return Object.freeze({
    transactionHash: inclusion?.transactionHash ?? null,
    blockNumber: inclusion?.blockNumber ?? null,
    outcome: inclusion?.outcome ?? null,
  });
}

/** Projects one run result onto the application outcome, or fails closed. */
export function operationOutcome(result: OperationRunResult): Readonly<OaathOperationOutcome> {
  const operation = result.record.value;
  const base = { state: operation.state, ...evidence(operation) };
  if (result.status === "state_conflict") {
    return clientFail(
      "oaath_client_state_conflict",
      "another Operation owns this chain lane",
      "operation_runner_state_conflict",
    );
  }
  if (result.status === "observation_unavailable") {
    return Object.freeze({ status: "unreadable", ...base, reason: result.reason });
  }
  if (result.status === "submission_uncertain") {
    // A send was attempted and its outcome is unknown. The identity stays exactly
    // as submitted and only observation may resolve it.
    return Object.freeze({ status: "pending", ...base, reason: result.reason });
  }
  if (operation.state === "finalized") {
    return Object.freeze({ status: "finalized", ...base, reason: null });
  }
  if (operation.state === "dropped") {
    return Object.freeze({ status: "dropped", ...base, reason: null });
  }
  return Object.freeze({
    status: "pending",
    ...base,
    reason: operation.observation?.reason ?? null,
  });
}

function attemptCount(value: unknown): number {
  if (value === undefined) return 3;
  const record = exactClientRecord(value, ["attempts"], "wait input", new WeakSet());
  const attempts = record.attempts;
  if (
    typeof attempts !== "number" ||
    !Number.isSafeInteger(attempts) ||
    attempts < 1 ||
    attempts > MAX_ATTEMPTS
  ) {
    return clientFail("oaath_client_input_invalid", "wait attempts must be a bounded count");
  }
  return attempts;
}

export function createOperationHandle(
  input: Readonly<CreateOperationHandleInput>,
): Readonly<OaathOperationHandle> {
  let latest = operationOutcome(input.initial);
  let closed = false;

  async function observeOnce(): Promise<Readonly<OaathOperationOutcome>> {
    if (closed) clientFail("oaath_client_closed", "operation handle is closed");
    const at = input.now();
    let result: OperationRunResult;
    try {
      result = await input.runner.runOperation({
        kind: input.kind,
        key: input.key,
        preparedAt: at,
        attemptedAt: at,
        submittedAt: at,
        observedAt: at,
        timeoutMs: input.timeoutMs,
      });
    } catch (error) {
      return mapClientFailure(error, "operation observation failed");
    }
    latest = operationOutcome(result);
    return latest;
  }

  return Object.freeze({
    chainId: input.key.chainId,
    get outcome(): Readonly<OaathOperationOutcome> {
      return latest;
    },
    observe: observeOnce,
    async wait(value?: unknown): Promise<Readonly<OaathOperationOutcome>> {
      const attempts = attemptCount(value);
      if (latest.status === "finalized" || latest.status === "dropped") return latest;
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        const outcome = await observeOnce();
        if (outcome.status === "finalized" || outcome.status === "dropped") return outcome;
      }
      // ponytail: no backoff scheduler; the caller decides when to poll again.
      return latest;
    },
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      try {
        await input.runner.close();
      } catch (error) {
        return mapClientFailure(error, "operation handle cleanup is incomplete");
      }
    },
  });
}
