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
import {
  type CaptureContext,
  captureDenseArray,
  type Operation,
  type OperationKind,
  type OperationOutcome,
} from "@oaath/protocol";
import type {
  OperationObserverCapabilities,
  OperationObserverReadRequest,
} from "../operation-observer.js";
import type { OperationRunner, OperationRunResult } from "../operation-runner.js";
import type { OperationStoreKey } from "../store.js";
import { clientFail, exactClientRecord, mapClientFailure } from "./errors.js";

const MAX_ATTEMPTS = 16;
const MAX_LOGS = 10_000;
const HASH = /^0x[0-9a-f]{64}$/u;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const ADDRESS = /^0x[0-9a-f]{40}$/u;

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

/** One receipt log, projected exactly; nothing here is authority. */
export interface OaathOperationLog {
  readonly address: `0x${string}`;
  readonly topics: readonly `0x${string}`[];
  readonly data: `0x${string}`;
}

/**
 * The full inclusion receipt of a terminal operation, read from the chain and
 * bound to the exact transaction the operation's own inclusion evidence
 * names. This is what EIP-5792 status answers and event-driven applications
 * consume; the distilled outcome above stays the authority-relevant fact.
 */
export interface OaathOperationReceipt {
  readonly transactionHash: `0x${string}`;
  readonly blockHash: `0x${string}`;
  /** Canonical decimal string. */
  readonly blockNumber: string;
  /** Canonical decimal string. */
  readonly gasUsed: string;
  readonly status: "success" | "reverted";
  /**
   * The containing transaction's logs. A bundler may batch several operations
   * into one transaction, so filter by address and topics; the gas and status
   * above are already this operation's own.
   */
  readonly logs: readonly Readonly<OaathOperationLog>[];
}

export interface OaathOperationHandle {
  readonly chainId: number;
  /** Outcome of the run that produced this handle. */
  readonly outcome: Readonly<OaathOperationOutcome>;
  /** One read-only observation pass. */
  readonly observe: () => Promise<Readonly<OaathOperationOutcome>>;
  /** Observes until terminal or the attempt bound is reached. Submits nothing. */
  readonly wait: (input?: unknown) => Promise<Readonly<OaathOperationOutcome>>;
  /** The terminal operation's full receipt, evidence-bound. Reads only. */
  readonly receipt: () => Promise<Readonly<OaathOperationReceipt>>;
  readonly close: () => Promise<void>;
}

export interface CreateOperationHandleInput {
  readonly runner: OperationRunner;
  readonly key: Readonly<OperationStoreKey>;
  readonly kind: OperationKind;
  readonly timeoutMs: number;
  readonly now: () => number;
  readonly initial: OperationRunResult;
  /** The chain's observation read, for the receipt projection. */
  readonly observation: OperationObserverCapabilities["read"];
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
  let identity = input.initial.record.value.identity.userOperationHash;
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
    identity = result.record.value.identity.userOperationHash;
    return latest;
  }

  async function receipt(): Promise<Readonly<OaathOperationReceipt>> {
    if (closed) clientFail("oaath_client_closed", "operation handle is closed");
    const transactionHash = latest.transactionHash;
    const blockNumber = latest.blockNumber;
    if (
      (latest.status !== "finalized" && latest.status !== "dropped") ||
      transactionHash === null ||
      blockNumber === null
    ) {
      return clientFail(
        "oaath_client_observation_unavailable",
        "no receipt exists before conclusive inclusion",
        latest.reason,
      );
    }
    let rawOperationReceipt: unknown;
    let rawTransactionReceipt: unknown;
    try {
      rawOperationReceipt = await input.observation({
        type: "user_operation_receipt",
        chainId: input.key.chainId,
        userOperationHash: identity,
      } satisfies OperationObserverReadRequest);
      rawTransactionReceipt = await input.observation({
        type: "transaction_receipt",
        chainId: input.key.chainId,
        transactionHash,
      } satisfies OperationObserverReadRequest);
    } catch (error) {
      return mapClientFailure(error, "the receipt could not be read");
    }
    const context: CaptureContext = new WeakSet();
    const invalid = (): never =>
      clientFail(
        "oaath_client_observation_unavailable",
        "the provider receipt does not match this operation's inclusion evidence",
      );
    const operationReceipt = rawOperationReceipt as Record<string, unknown> | null;
    const record = rawTransactionReceipt as Record<string, unknown> | null;
    if (
      operationReceipt === null ||
      typeof operationReceipt !== "object" ||
      record === null ||
      typeof record !== "object"
    ) {
      return invalid();
    }
    // Evidence binding: both receipts must be for exactly the operation,
    // transaction, and block this operation's own inclusion recorded; anything
    // else — another hash, another block, a reorged provider — is refused,
    // never projected.
    if (
      operationReceipt.userOperationHash !== identity ||
      operationReceipt.transactionHash !== transactionHash ||
      record.transactionHash !== transactionHash ||
      typeof record.blockHash !== "string" ||
      !HASH.test(record.blockHash) ||
      typeof record.blockNumber !== "string" ||
      !QUANTITY.test(record.blockNumber) ||
      BigInt(record.blockNumber) !== BigInt(blockNumber)
    ) {
      return invalid();
    }
    // Gas and status are the operation's own facts from its ERC-4337 receipt —
    // a containing transaction may bundle other operations. The status must
    // also agree with the inclusion outcome the aggregate already recorded.
    const status =
      operationReceipt.success === true
        ? "success"
        : operationReceipt.success === false
          ? "reverted"
          : null;
    const gasUsed = operationReceipt.actualGasUsed;
    if (
      status === null ||
      (latest.outcome !== null && (latest.outcome === "success") !== (status === "success")) ||
      typeof gasUsed !== "string" ||
      !QUANTITY.test(gasUsed)
    ) {
      return invalid();
    }
    const entries = captureDenseArray(record.logs, "receipt logs", context, invalid);
    if (entries.length > MAX_LOGS) return invalid();
    const logs = entries.map((entry) => {
      const log = entry as Record<string, unknown>;
      if (
        log === null ||
        typeof log !== "object" ||
        typeof log.address !== "string" ||
        !ADDRESS.test(log.address) ||
        typeof log.data !== "string" ||
        !BYTES.test(log.data)
      ) {
        return invalid();
      }
      const topics = captureDenseArray(log.topics, "receipt log topics", context, invalid).map(
        (topic) => {
          if (typeof topic !== "string" || !HASH.test(topic)) return invalid();
          return topic as `0x${string}`;
        },
      );
      return Object.freeze({
        address: log.address as `0x${string}`,
        topics: Object.freeze(topics),
        data: log.data as `0x${string}`,
      });
    });
    return Object.freeze({
      transactionHash,
      blockHash: record.blockHash as `0x${string}`,
      blockNumber: BigInt(blockNumber).toString(10),
      gasUsed: BigInt(gasUsed).toString(10),
      status,
      logs: Object.freeze(logs),
    });
  }

  return Object.freeze({
    chainId: input.key.chainId,
    get outcome(): Readonly<OaathOperationOutcome> {
      return latest;
    },
    observe: observeOnce,
    receipt,
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
