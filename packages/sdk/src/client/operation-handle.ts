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
import type {
  Operation,
  OperationIdentity,
  OperationInclusion,
  OperationKind,
  OperationOutcome,
} from "@oaath/protocol";
import {
  type OperationObserverCapabilities,
  type OperationObserverReadRequest,
  verifyOperationReceiptEvidence,
} from "../operation-observer.js";
import type {
  OperationObserveResult,
  OperationRunner,
  OperationRunResult,
  OperationStartResult,
} from "../operation-runner.js";
import type { OperationStoreKey } from "../store.js";
import { clientFail, exactClientRecord, mapClientFailure } from "./errors.js";

const MAX_ATTEMPTS = 16;

export type OaathOperationStatus =
  | "finalized"
  | "dropped"
  | "superseded"
  | "pending"
  | "unreadable";

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
 * The exact inclusion receipt of a terminal operation, read from the chain and
 * bound to the operation's immutable identity and inclusion evidence. This is
 * what EIP-5792 status answers and event-driven applications consume; the
 * distilled outcome above stays the authority-relevant fact.
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
   * Call-relevant logs from this UserOperation's exact EntryPoint execution
   * window, including nested-call logs and its terminal UserOperationEvent.
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
  /** The terminal operation's exact call-relevant receipt. Reads only. */
  readonly receipt: () => Promise<Readonly<OaathOperationReceipt>>;
  readonly close: () => Promise<void>;
}

export interface CreateOperationHandleInput {
  readonly runner: OperationRunner;
  readonly key: Readonly<OperationStoreKey>;
  readonly kind: OperationKind;
  readonly timeoutMs: number;
  readonly now: () => number;
  readonly initial: OperationRunResult | OperationStartResult;
  /** The chain's observation read, for the receipt projection. */
  readonly observation: OperationObserverCapabilities["read"];
  /** Internal Grant transition triggered only by an exact later observation. */
  readonly onObserved?: (result: OperationObserveResult) => Promise<void>;
}

/**
 * The inclusion this exact identity owns. Replacement inclusion is never
 * eligible: a dropped operation may expose only its own prior inclusion.
 */
function exactInclusion(operation: Operation): Readonly<OperationInclusion> | null {
  if (operation.state === "included" || operation.state === "finalized") {
    return operation.inclusion;
  }
  return operation.state === "dropped" ? operation.priorInclusion : null;
}

/** Projects one run result onto the application outcome, or fails closed. */
export function operationOutcome(
  result: OperationRunResult | OperationStartResult,
): Readonly<OaathOperationOutcome> {
  const operation = result.record.value;
  const inclusion = exactInclusion(operation);
  const base = {
    state: operation.state,
    transactionHash: inclusion?.transactionHash ?? null,
    blockNumber: inclusion?.blockNumber ?? null,
    outcome: inclusion?.outcome ?? null,
  };
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
  if (operation.state === "superseded") {
    // The lane is conclusively free — this identity can never be included at
    // its nonce — while whether it executed earlier stays unproven.
    return Object.freeze({ status: "superseded", ...base, reason: null });
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
  const identity: Readonly<OperationIdentity> = input.initial.record.value.identity;
  let current = input.initial.record.value;
  let closed = false;

  async function observeOnce(): Promise<Readonly<OaathOperationOutcome>> {
    if (closed) clientFail("oaath_client_closed", "operation handle is closed");
    const at = input.now();
    let result: OperationObserveResult;
    try {
      result = await input.runner.observeOperation({
        kind: input.kind,
        key: input.key,
        preparedAt: at,
        attemptedAt: at,
        submittedAt: at,
        observedAt: at,
        timeoutMs: input.timeoutMs,
        expectedUserOperationHash: identity.userOperationHash,
      });
    } catch (error) {
      return mapClientFailure(error, "operation observation failed");
    }
    const observed = operationOutcome(result);
    if (input.onObserved) await input.onObserved(result);
    current = result.record.value;
    latest = observed;
    return latest;
  }

  async function receipt(): Promise<Readonly<OaathOperationReceipt>> {
    if (closed) clientFail("oaath_client_closed", "operation handle is closed");
    const inclusion = exactInclusion(current);
    if ((latest.status !== "finalized" && latest.status !== "dropped") || inclusion === null) {
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
        chainId: identity.chainId,
        userOperationHash: identity.userOperationHash,
      } satisfies OperationObserverReadRequest);
      rawTransactionReceipt = await input.observation({
        type: "transaction_receipt",
        chainId: identity.chainId,
        transactionHash: inclusion.transactionHash,
      } satisfies OperationObserverReadRequest);
    } catch {
      return clientFail(
        "oaath_client_observation_unavailable",
        "the receipt could not be read",
        "provider_unavailable",
      );
    }
    let verified: ReturnType<typeof verifyOperationReceiptEvidence>;
    try {
      verified = verifyOperationReceiptEvidence({
        identity,
        inclusion,
        userOperationReceipt: rawOperationReceipt,
        transactionReceipt: rawTransactionReceipt,
      });
    } catch {
      return clientFail(
        "oaath_client_observation_unavailable",
        "the provider receipt does not match this operation's inclusion evidence",
        "receipt_invalid",
      );
    }
    const logs = verified.logs.map((log) =>
      Object.freeze({
        address: log.address,
        topics: log.topics,
        data: log.data,
      }),
    );
    return Object.freeze({
      transactionHash: verified.transactionHash,
      blockHash: verified.blockHash,
      blockNumber: verified.blockNumber,
      gasUsed: verified.gasUsed,
      status: verified.outcome,
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
      const terminal = (status: OaathOperationStatus) =>
        status === "finalized" || status === "dropped" || status === "superseded";
      if (terminal(latest.status)) return latest;
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        const outcome = await observeOnce();
        if (terminal(outcome.status)) return outcome;
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
