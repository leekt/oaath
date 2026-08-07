import {
  type AbandonedOperation,
  applyVerifiedOperationObservation,
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  type DroppedOperation,
  type ExactRecord,
  exactCapturedRecord,
  type FinalizedOperation,
  type IncludedOperation,
  type Operation,
  type OperationFinality,
  type OperationIdentity,
  type OperationInclusion,
  parseOperation,
  type SupersededOperation,
  type UserOperationReference,
} from "@oaath/protocol";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/u;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const USER_OPERATION_EVENT = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";
const BEFORE_EXECUTION = "0xbb47ee3e183a558b1a2ff0874b079f3fc5478b7454eacf2bfc5af2ff5878f972";
const MAX_RECEIPT_LOGS = 10_000;
const MAX_TIMEOUT_MS = 60_000;

export type OperationObserverErrorCode =
  | "operation_observer_input_invalid"
  | "operation_observer_capability_invalid"
  | "operation_observer_closed"
  | "operation_observer_close_failed";

export class OaathOperationObserverError extends Error {
  readonly code: OperationObserverErrorCode;

  constructor(code: OperationObserverErrorCode, message: string) {
    super(message);
    this.name = "OaathOperationObserverError";
    this.code = code;
  }
}

export type OperationObserverReadRequest =
  | Readonly<{ type: "chain_id"; chainId: number }>
  | Readonly<{
      type: "user_operation_receipt";
      chainId: number;
      userOperationHash: `0x${string}`;
    }>
  | Readonly<{ type: "transaction"; chainId: number; transactionHash: `0x${string}` }>
  | Readonly<{
      type: "transaction_receipt";
      chainId: number;
      transactionHash: `0x${string}`;
    }>
  | Readonly<{
      type: "entry_point_nonce";
      chainId: number;
      entryPoint: `0x${string}`;
      account: `0x${string}`;
      /** The operation's own nonce; the provider reads its 192-bit key. */
      nonce: string;
      /** Decimal block height the read must be answered at. */
      blockNumber: string;
    }>
  | Readonly<{
      /**
       * Whether the permission's signer module is installed on the account —
       * Kernel's `isModuleInstalled(6, signer, permissionId)`, true exactly
       * while the permission validation is live. Grant revocation uses this to
       * observe a completed removal it could not sign itself.
       */
      type: "kernel_permission_installed";
      chainId: number;
      account: `0x${string}`;
      /** The permission's signer module address. */
      signer: `0x${string}`;
      permissionId: `0x${string}`;
      /** Decimal block height the read must be answered at. */
      blockNumber: string;
    }>
  | Readonly<{ type: "canonical_block"; chainId: number; blockNumber: string }>
  | Readonly<{ type: "block_by_hash"; chainId: number; blockHash: `0x${string}` }>
  | Readonly<{ type: "finalized_block"; chainId: number }>
  | Readonly<{
      type: "replacement_candidate";
      chainId: number;
      entryPoint: `0x${string}`;
      account: `0x${string}`;
      nonce: string;
      excludedUserOperationHash: `0x${string}`;
    }>;

export interface OperationObserverCapabilities {
  readonly read: (request: OperationObserverReadRequest) => Promise<unknown>;
  readonly close: () => Promise<void>;
}

export interface OperationObserverLogEvidence {
  readonly address: `0x${string}`;
  readonly blockNumber: `0x${string}`;
  readonly blockHash: `0x${string}`;
  readonly transactionHash: `0x${string}`;
  readonly transactionIndex: `0x${string}`;
  readonly logIndex: `0x${string}`;
  readonly removed: boolean;
  readonly topics: readonly `0x${string}`[];
  readonly data: `0x${string}`;
}

export interface OperationObserverUserOperationReceiptEvidence {
  readonly userOperationHash: `0x${string}`;
  readonly entryPoint: `0x${string}`;
  readonly sender: `0x${string}`;
  readonly nonce: `0x${string}`;
  readonly paymaster: `0x${string}`;
  readonly actualGasCost: `0x${string}`;
  readonly actualGasUsed: `0x${string}`;
  readonly success: boolean;
  readonly transactionHash: `0x${string}`;
  readonly blockNumber: `0x${string}`;
  readonly blockHash: `0x${string}`;
}

export interface OperationObserverTransactionReceiptEvidence {
  readonly transactionHash: `0x${string}`;
  readonly blockNumber: `0x${string}`;
  readonly blockHash: `0x${string}`;
  readonly transactionIndex: `0x${string}`;
  readonly status: "0x0" | "0x1";
  readonly gasUsed: `0x${string}`;
  readonly logs: readonly OperationObserverLogEvidence[];
}

export interface VerifiedOperationReceiptEvidence {
  readonly transactionHash: `0x${string}`;
  readonly blockNumber: string;
  readonly blockHash: `0x${string}`;
  readonly gasUsed: string;
  readonly outcome: OperationInclusion["outcome"];
  readonly logs: readonly OperationObserverLogEvidence[];
}

export interface VerifyOperationReceiptEvidenceInput {
  readonly identity: Readonly<OperationIdentity>;
  readonly inclusion: Readonly<OperationInclusion>;
  readonly userOperationReceipt: unknown;
  readonly transactionReceipt: unknown;
}

export interface OperationObserverTransactionEvidence {
  readonly hash: `0x${string}`;
  readonly to: `0x${string}` | null;
  readonly blockNumber: `0x${string}`;
  readonly blockHash: `0x${string}`;
  readonly transactionIndex: `0x${string}`;
}

export interface OperationObserverBlockEvidence {
  readonly number: `0x${string}`;
  readonly hash: `0x${string}`;
  readonly parentHash: `0x${string}`;
  readonly transactions: readonly `0x${string}`[];
}

export type ObserveOperationResult =
  | Readonly<{
      status: "pending";
      reason: "receipt_missing" | "timeout";
      operation: Operation;
    }>
  | Readonly<{
      status: "unreadable";
      reason:
        | "provider_unavailable"
        | "receipt_invalid"
        | "canonicality_unproven"
        | "finality_unproven";
      operation: Operation;
    }>
  | Readonly<{ status: "included"; operation: IncludedOperation }>
  | Readonly<{ status: "finalized"; operation: FinalizedOperation }>
  | Readonly<{ status: "dropped"; operation: DroppedOperation }>
  | Readonly<{ status: "superseded"; operation: SupersededOperation }>
  | Readonly<{ status: "abandoned"; operation: AbandonedOperation }>;

export interface OperationObserver {
  readonly observeOperation: (input: unknown) => Promise<ObserveOperationResult>;
  readonly close: () => Promise<void>;
}

type CapturedCapabilities = Readonly<OperationObserverCapabilities>;
type UnreadableReason = Extract<ObserveOperationResult, { status: "unreadable" }>["reason"];
type PendingReason = Extract<ObserveOperationResult, { status: "pending" }>["reason"];

class EvidenceFailure extends Error {
  readonly reason: UnreadableReason;

  constructor(reason: UnreadableReason) {
    super(reason);
    this.reason = reason;
  }
}

class ProviderFailure extends Error {}
class TimeoutFailure extends Error {}

function failInput(message: string): never {
  throw new OaathOperationObserverError("operation_observer_input_invalid", message);
}

function exact(
  value: unknown,
  keys: readonly string[],
  label: string,
  context: CaptureContext,
  reason: UnreadableReason = "receipt_invalid",
): ExactRecord {
  const fail = (): never => {
    throw new EvidenceFailure(reason);
  };
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}

function parseHash(value: unknown, reason: UnreadableReason = "receipt_invalid"): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) throw new EvidenceFailure(reason);
  return value as `0x${string}`;
}

function parseAddress(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value)) {
    throw new EvidenceFailure("receipt_invalid");
  }
  return value as `0x${string}`;
}

function parseQuantity(value: unknown, reason: UnreadableReason = "receipt_invalid"): bigint {
  if (typeof value !== "string" || !QUANTITY.test(value)) throw new EvidenceFailure(reason);
  return BigInt(value);
}

function decimal(value: bigint): string {
  return value.toString(10);
}

function parseLog(value: unknown, context: CaptureContext): OperationObserverLogEvidence {
  const record = exact(
    value,
    [
      "address",
      "blockNumber",
      "blockHash",
      "transactionHash",
      "transactionIndex",
      "logIndex",
      "removed",
      "topics",
      "data",
    ],
    "operation event log",
    context,
  );
  if (typeof record.removed !== "boolean") throw new EvidenceFailure("receipt_invalid");
  const topics = captureDenseArray(record.topics, "operation event topics", context, () => {
    throw new EvidenceFailure("receipt_invalid");
  }).map((topic) => parseHash(topic));
  if (typeof record.data !== "string" || !HEX_DATA.test(record.data)) {
    throw new EvidenceFailure("receipt_invalid");
  }
  return Object.freeze({
    address: parseAddress(record.address),
    blockNumber: `0x${parseQuantity(record.blockNumber).toString(16)}`,
    blockHash: parseHash(record.blockHash),
    transactionHash: parseHash(record.transactionHash),
    transactionIndex: `0x${parseQuantity(record.transactionIndex).toString(16)}`,
    logIndex: `0x${parseQuantity(record.logIndex).toString(16)}`,
    removed: record.removed,
    topics: Object.freeze(topics),
    data: record.data as `0x${string}`,
  });
}

function parseUserOperationReceipt(
  value: unknown,
  context: CaptureContext,
): OperationObserverUserOperationReceiptEvidence {
  const record = exact(
    value,
    [
      "userOperationHash",
      "entryPoint",
      "sender",
      "nonce",
      "paymaster",
      "actualGasCost",
      "actualGasUsed",
      "success",
      "transactionHash",
      "blockNumber",
      "blockHash",
    ],
    "UserOperation receipt",
    context,
  );
  if (typeof record.success !== "boolean") throw new EvidenceFailure("receipt_invalid");
  return Object.freeze({
    userOperationHash: parseHash(record.userOperationHash),
    entryPoint: parseAddress(record.entryPoint),
    sender: parseAddress(record.sender),
    nonce: `0x${parseQuantity(record.nonce).toString(16)}`,
    paymaster: parseAddress(record.paymaster),
    actualGasCost: `0x${parseQuantity(record.actualGasCost).toString(16)}`,
    actualGasUsed: `0x${parseQuantity(record.actualGasUsed).toString(16)}`,
    success: record.success,
    transactionHash: parseHash(record.transactionHash),
    blockNumber: `0x${parseQuantity(record.blockNumber).toString(16)}`,
    blockHash: parseHash(record.blockHash),
  });
}

function parseTransactionReceipt(
  value: unknown,
  context: CaptureContext,
): OperationObserverTransactionReceiptEvidence {
  const record = exact(
    value,
    [
      "transactionHash",
      "blockNumber",
      "blockHash",
      "transactionIndex",
      "status",
      "gasUsed",
      "logs",
    ],
    "transaction receipt",
    context,
  );
  if (record.status !== "0x0" && record.status !== "0x1") {
    throw new EvidenceFailure("receipt_invalid");
  }
  const entries = captureDenseArray(record.logs, "transaction receipt logs", context, () => {
    throw new EvidenceFailure("receipt_invalid");
  });
  if (entries.length > MAX_RECEIPT_LOGS) throw new EvidenceFailure("receipt_invalid");
  const logs = entries.map((log) => parseLog(log, context));
  return Object.freeze({
    transactionHash: parseHash(record.transactionHash),
    blockNumber: `0x${parseQuantity(record.blockNumber).toString(16)}`,
    blockHash: parseHash(record.blockHash),
    transactionIndex: `0x${parseQuantity(record.transactionIndex).toString(16)}`,
    status: record.status,
    gasUsed: `0x${parseQuantity(record.gasUsed).toString(16)}`,
    logs: Object.freeze(logs),
  });
}

function parseTransaction(
  value: unknown,
  context: CaptureContext,
): OperationObserverTransactionEvidence {
  const record = exact(
    value,
    ["hash", "to", "blockNumber", "blockHash", "transactionIndex"],
    "transaction",
    context,
  );
  return Object.freeze({
    hash: parseHash(record.hash),
    to: record.to === null ? null : parseAddress(record.to),
    blockNumber: `0x${parseQuantity(record.blockNumber).toString(16)}`,
    blockHash: parseHash(record.blockHash),
    transactionIndex: `0x${parseQuantity(record.transactionIndex).toString(16)}`,
  });
}

function parseBlock(
  value: unknown,
  context: CaptureContext,
  reason: "canonicality_unproven" | "finality_unproven",
): OperationObserverBlockEvidence {
  const record = exact(
    value,
    ["number", "hash", "parentHash", "transactions"],
    "canonical block",
    context,
    reason,
  );
  const transactions = captureDenseArray(record.transactions, "block transactions", context, () => {
    throw new EvidenceFailure(reason);
  }).map((transactionHash) => parseHash(transactionHash, reason));
  return Object.freeze({
    number: `0x${parseQuantity(record.number, reason).toString(16)}`,
    hash: parseHash(record.hash, reason),
    parentHash: parseHash(record.parentHash, reason),
    transactions: Object.freeze(transactions),
  });
}

function sameOccurrence(inclusion: OperationInclusion, next: OperationInclusion): boolean {
  return (
    inclusion.transactionHash === next.transactionHash &&
    inclusion.blockNumber === next.blockNumber &&
    inclusion.blockHash === next.blockHash &&
    inclusion.outcome === next.outcome
  );
}

function parseEvent(
  log: OperationObserverLogEvidence,
  reference: UserOperationReference,
): { paymaster: `0x${string}`; actualGasCost: bigint; actualGasUsed: bigint; success: boolean } {
  if (log.topics.length !== 4 || log.data.length !== 258) {
    throw new EvidenceFailure("receipt_invalid");
  }
  const expectedSenderTopic = `0x${"0".repeat(24)}${reference.account.slice(2)}`;
  if (
    log.topics[0] !== USER_OPERATION_EVENT ||
    log.topics[1] !== reference.userOperationHash ||
    log.topics[2] !== expectedSenderTopic
  ) {
    throw new EvidenceFailure("receipt_invalid");
  }
  const paymasterTopic = log.topics[3];
  if (!paymasterTopic || !/^0x0{24}[0-9a-f]{40}$/u.test(paymasterTopic)) {
    throw new EvidenceFailure("receipt_invalid");
  }
  const words = [0, 1, 2, 3].map((index) =>
    BigInt(`0x${log.data.slice(2 + index * 64, 2 + (index + 1) * 64)}`),
  );
  const nonce = words[0];
  const successWord = words[1];
  const actualGasCost = words[2];
  const actualGasUsed = words[3];
  if (
    nonce === undefined ||
    successWord === undefined ||
    actualGasCost === undefined ||
    actualGasUsed === undefined ||
    decimal(nonce) !== reference.nonce ||
    (successWord !== 0n && successWord !== 1n)
  ) {
    throw new EvidenceFailure("receipt_invalid");
  }
  return {
    paymaster: `0x${paymasterTopic.slice(26)}`,
    actualGasCost,
    actualGasUsed,
    success: successWord === 1n,
  };
}

function isEntryPointBoundary(
  log: OperationObserverLogEvidence,
  entryPoint: `0x${string}`,
): boolean {
  if (log.address !== entryPoint) return false;
  if (log.topics[0] === BEFORE_EXECUTION) {
    if (log.topics.length !== 1 || log.data !== "0x") {
      throw new EvidenceFailure("receipt_invalid");
    }
    return true;
  }
  if (log.topics[0] !== USER_OPERATION_EVENT) return false;
  if (
    log.topics.length !== 4 ||
    log.data.length !== 258 ||
    !/^0x0{24}[0-9a-f]{40}$/u.test(log.topics[2] ?? "") ||
    !/^0x0{24}[0-9a-f]{40}$/u.test(log.topics[3] ?? "")
  ) {
    throw new EvidenceFailure("receipt_invalid");
  }
  const success = BigInt(`0x${log.data.slice(66, 130)}`);
  if (success !== 0n && success !== 1n) throw new EvidenceFailure("receipt_invalid");
  return true;
}

function verifyParsedOperationReceiptEvidence(
  reference: Readonly<UserOperationReference>,
  inclusion: Readonly<OperationInclusion>,
  receipt: Readonly<OperationObserverUserOperationReceiptEvidence>,
  transactionReceipt: Readonly<OperationObserverTransactionReceiptEvidence>,
): Readonly<VerifiedOperationReceiptEvidence> {
  const blockNumber = decimal(parseQuantity(receipt.blockNumber));
  const outcome = receipt.success ? "success" : "reverted";
  if (
    receipt.userOperationHash !== reference.userOperationHash ||
    receipt.entryPoint !== reference.entryPoint ||
    receipt.sender !== reference.account ||
    decimal(parseQuantity(receipt.nonce)) !== reference.nonce ||
    receipt.transactionHash !== inclusion.transactionHash ||
    blockNumber !== inclusion.blockNumber ||
    receipt.blockHash !== inclusion.blockHash ||
    outcome !== inclusion.outcome ||
    transactionReceipt.status !== "0x1" ||
    transactionReceipt.transactionHash !== inclusion.transactionHash ||
    decimal(parseQuantity(transactionReceipt.blockNumber)) !== inclusion.blockNumber ||
    transactionReceipt.blockHash !== inclusion.blockHash
  ) {
    throw new EvidenceFailure("receipt_invalid");
  }

  let previousLogIndex: bigint | null = null;
  for (const log of transactionReceipt.logs) {
    const logIndex = parseQuantity(log.logIndex);
    if (
      log.removed ||
      log.transactionHash !== transactionReceipt.transactionHash ||
      log.blockNumber !== transactionReceipt.blockNumber ||
      log.blockHash !== transactionReceipt.blockHash ||
      log.transactionIndex !== transactionReceipt.transactionIndex ||
      (previousLogIndex !== null && logIndex <= previousLogIndex)
    ) {
      throw new EvidenceFailure("receipt_invalid");
    }
    previousLogIndex = logIndex;
  }

  const targetEvents = transactionReceipt.logs
    .map((log, index) => ({ log, index }))
    .filter(
      ({ log }) =>
        log.address === reference.entryPoint &&
        log.topics[0] === USER_OPERATION_EVENT &&
        log.topics[1] === reference.userOperationHash,
    );
  if (targetEvents.length !== 1) throw new EvidenceFailure("receipt_invalid");
  const target = targetEvents[0];
  if (!target) throw new EvidenceFailure("receipt_invalid");
  const event = parseEvent(target.log, reference);
  if (
    receipt.paymaster !== event.paymaster ||
    receipt.success !== event.success ||
    parseQuantity(receipt.actualGasCost) !== event.actualGasCost ||
    parseQuantity(receipt.actualGasUsed) !== event.actualGasUsed
  ) {
    throw new EvidenceFailure("receipt_invalid");
  }

  let boundaryIndex = -1;
  for (let index = target.index - 1; index >= 0; index -= 1) {
    const log = transactionReceipt.logs[index];
    if (log && isEntryPointBoundary(log, reference.entryPoint)) {
      boundaryIndex = index;
      break;
    }
  }
  if (boundaryIndex < 0) throw new EvidenceFailure("receipt_invalid");

  return Object.freeze({
    transactionHash: inclusion.transactionHash,
    blockNumber: inclusion.blockNumber,
    blockHash: inclusion.blockHash,
    // The public wallet receipt is a subset of the containing transaction
    // receipt. UserOperation actualGasUsed remains independently verified
    // above, but it is not the transaction's gasUsed when a bundler batches.
    gasUsed: decimal(parseQuantity(transactionReceipt.gasUsed)),
    outcome: inclusion.outcome,
    logs: Object.freeze(transactionReceipt.logs.slice(boundaryIndex + 1, target.index + 1)),
  });
}

/**
 * Captures hostile provider receipts once and proves the exact target
 * UserOperation execution window. No containing-transaction log escapes this
 * function unless it is after the target's nearest EntryPoint boundary and no
 * later than the target's own UserOperationEvent.
 */
export function verifyOperationReceiptEvidence(
  input: Readonly<VerifyOperationReceiptEvidenceInput>,
): Readonly<VerifiedOperationReceiptEvidence> {
  try {
    const receipt = parseUserOperationReceipt(input.userOperationReceipt, new WeakSet());
    const transactionReceipt = parseTransactionReceipt(input.transactionReceipt, new WeakSet());
    return verifyParsedOperationReceiptEvidence(
      input.identity,
      input.inclusion,
      receipt,
      transactionReceipt,
    );
  } catch (error) {
    if (error instanceof EvidenceFailure) throw error;
    throw new EvidenceFailure("receipt_invalid");
  }
}

function captureCapabilities(value: unknown): CapturedCapabilities {
  try {
    const context: CaptureContext = new WeakSet();
    const fail = (): never => {
      throw new Error("invalid");
    };
    const record = exactCapturedRecord(
      captureRecord(value, "operation observer capabilities", context, fail),
      ["read", "close"],
      "operation observer capabilities",
      fail,
    );
    if (typeof record.read !== "function" || typeof record.close !== "function") fail();
    return Object.freeze({
      read: record.read as OperationObserverCapabilities["read"],
      close: record.close as OperationObserverCapabilities["close"],
    });
  } catch {
    throw new OaathOperationObserverError(
      "operation_observer_capability_invalid",
      "operation observer capabilities are invalid",
    );
  }
}

function captureObserveInput(value: unknown): {
  operation: Operation;
  observedAt: number;
  timeoutMs: number;
} {
  try {
    const context: CaptureContext = new WeakSet();
    const fail = (): never => failInput("operation observation input is invalid");
    const record = exactCapturedRecord(
      captureRecord(value, "operation observation", context, fail),
      ["operation", "observedAt", "timeoutMs"],
      "operation observation",
      fail,
    );
    if (
      typeof record.observedAt !== "number" ||
      !Number.isSafeInteger(record.observedAt) ||
      record.observedAt < 0 ||
      typeof record.timeoutMs !== "number" ||
      !Number.isSafeInteger(record.timeoutMs) ||
      record.timeoutMs < 1 ||
      record.timeoutMs > MAX_TIMEOUT_MS
    ) {
      return fail();
    }
    const operation = parseOperation(record.operation);
    if (record.observedAt < operation.updatedAt) return fail();
    return { operation, observedAt: record.observedAt, timeoutMs: record.timeoutMs };
  } catch (error) {
    if (error instanceof OaathOperationObserverError) throw error;
    return failInput("operation observation input is invalid");
  }
}

function frozenResult<Result extends ObserveOperationResult>(result: Result): Result {
  return Object.freeze(result);
}

function terminalResult(
  operation: FinalizedOperation | DroppedOperation | SupersededOperation | AbandonedOperation,
): ObserveOperationResult {
  if (operation.state === "finalized") return frozenResult({ status: "finalized", operation });
  if (operation.state === "superseded") return frozenResult({ status: "superseded", operation });
  if (operation.state === "abandoned") return frozenResult({ status: "abandoned", operation });
  return frozenResult({ status: "dropped", operation });
}

export function createOperationObserver(capabilityValue: unknown): OperationObserver {
  const capabilities = captureCapabilities(capabilityValue);
  let closed = false;
  let closing: Promise<void> | null = null;
  let activeObservations = 0;
  let drained: (() => void) | null = null;

  async function observeOperation(inputValue: unknown): Promise<ObserveOperationResult> {
    if (closed || closing) {
      throw new OaathOperationObserverError(
        "operation_observer_closed",
        "operation observer is closed",
      );
    }
    activeObservations += 1;
    try {
      const { operation, observedAt, timeoutMs } = captureObserveInput(inputValue);
      if (
        operation.state === "finalized" ||
        operation.state === "dropped" ||
        operation.state === "superseded" ||
        operation.state === "abandoned"
      ) {
        return terminalResult(operation);
      }
      if (operation.state === "prepared") {
        return failInput("prepared operation has not entered submission");
      }

      const deadline = Date.now() + timeoutMs;
      async function read(request: OperationObserverReadRequest): Promise<unknown> {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new TimeoutFailure();
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          return await Promise.race([
            Promise.resolve().then(() => capabilities.read(Object.freeze(request))),
            new Promise<never>((_, reject) => {
              timer = setTimeout(() => reject(new TimeoutFailure()), remaining);
            }),
          ]);
        } catch (error) {
          if (error instanceof TimeoutFailure) throw error;
          throw new ProviderFailure();
        } finally {
          if (timer !== undefined) clearTimeout(timer);
        }
      }

      function weakPending(current: Operation, reason: PendingReason): ObserveOperationResult {
        const next = applyVerifiedOperationObservation(current, {
          type: "record_pending",
          identity: current.identity,
          observedAt,
          reason,
        });
        return frozenResult({ status: "pending", reason, operation: next });
      }

      function weakUnreadable(
        current: Operation,
        reason: UnreadableReason,
      ): ObserveOperationResult {
        const next = applyVerifiedOperationObservation(current, {
          type: "record_unreadable",
          identity: current.identity,
          observedAt,
          reason,
        });
        return frozenResult({ status: "unreadable", reason, operation: next });
      }

      async function verifyInclusion(
        reference: UserOperationReference,
      ): Promise<OperationInclusion | null> {
        const receiptValue = await read({
          type: "user_operation_receipt",
          chainId: reference.chainId,
          userOperationHash: reference.userOperationHash,
        });
        if (receiptValue === null) return null;
        const receipt = parseUserOperationReceipt(receiptValue, new WeakSet());
        if (
          receipt.userOperationHash !== reference.userOperationHash ||
          receipt.entryPoint !== reference.entryPoint ||
          receipt.sender !== reference.account ||
          decimal(parseQuantity(receipt.nonce)) !== reference.nonce
        ) {
          throw new EvidenceFailure("receipt_invalid");
        }

        const transactionReceipt = parseTransactionReceipt(
          await read({
            type: "transaction_receipt",
            chainId: reference.chainId,
            transactionHash: receipt.transactionHash,
          }),
          new WeakSet(),
        );
        const inclusion = Object.freeze({
          transactionHash: receipt.transactionHash,
          blockNumber: decimal(parseQuantity(receipt.blockNumber)),
          blockHash: receipt.blockHash,
          outcome: receipt.success ? ("success" as const) : ("reverted" as const),
          observedAt,
        });
        const verifiedReceipt = verifyParsedOperationReceiptEvidence(
          reference,
          inclusion,
          receipt,
          transactionReceipt,
        );
        const transaction = parseTransaction(
          await read({
            type: "transaction",
            chainId: reference.chainId,
            transactionHash: receipt.transactionHash,
          }),
          new WeakSet(),
        );
        if (
          transaction.hash !== verifiedReceipt.transactionHash ||
          transaction.to !== reference.entryPoint ||
          decimal(parseQuantity(transaction.blockNumber)) !== verifiedReceipt.blockNumber ||
          transaction.blockHash !== verifiedReceipt.blockHash ||
          transactionReceipt.transactionIndex !== transaction.transactionIndex
        ) {
          throw new EvidenceFailure("receipt_invalid");
        }

        const canonical = parseBlock(
          await read({
            type: "canonical_block",
            chainId: reference.chainId,
            blockNumber: verifiedReceipt.blockNumber,
          }),
          new WeakSet(),
          "canonicality_unproven",
        );
        const transactionIndex = Number(parseQuantity(transaction.transactionIndex));
        if (
          decimal(parseQuantity(canonical.number, "canonicality_unproven")) !==
            verifiedReceipt.blockNumber ||
          canonical.hash !== verifiedReceipt.blockHash ||
          !Number.isSafeInteger(transactionIndex) ||
          canonical.transactions[transactionIndex] !== verifiedReceipt.transactionHash ||
          canonical.transactions.filter((hash) => hash === verifiedReceipt.transactionHash)
            .length !== 1
        ) {
          throw new EvidenceFailure("canonicality_unproven");
        }
        return inclusion;
      }

      async function verifyFinality(
        reference: UserOperationReference,
        inclusion: OperationInclusion,
      ): Promise<OperationFinality> {
        try {
          const finalized = parseBlock(
            await read({ type: "finalized_block", chainId: reference.chainId }),
            new WeakSet(),
            "finality_unproven",
          );
          const finalizedNumberValue = parseQuantity(finalized.number, "finality_unproven");
          const finalizedNumber = decimal(finalizedNumberValue);
          const inclusionNumber = BigInt(inclusion.blockNumber);
          if (finalizedNumberValue < inclusionNumber) {
            throw new EvidenceFailure("finality_unproven");
          }

          let descendant = finalized;
          let descendantNumber = finalizedNumberValue;
          while (descendantNumber > inclusionNumber) {
            const parent = parseBlock(
              await read({
                type: "block_by_hash",
                chainId: reference.chainId,
                blockHash: descendant.parentHash,
              }),
              new WeakSet(),
              "finality_unproven",
            );
            const parentNumber = parseQuantity(parent.number, "finality_unproven");
            if (parent.hash !== descendant.parentHash || parentNumber + 1n !== descendantNumber) {
              throw new EvidenceFailure("finality_unproven");
            }
            descendant = parent;
            descendantNumber = parentNumber;
          }
          if (descendant.hash !== inclusion.blockHash) {
            throw new EvidenceFailure("finality_unproven");
          }

          const reboundFinalized = parseBlock(
            await read({
              type: "canonical_block",
              chainId: reference.chainId,
              blockNumber: finalizedNumber,
            }),
            new WeakSet(),
            "finality_unproven",
          );
          const reboundInclusion = parseBlock(
            await read({
              type: "canonical_block",
              chainId: reference.chainId,
              blockNumber: inclusion.blockNumber,
            }),
            new WeakSet(),
            "finality_unproven",
          );
          if (
            reboundFinalized.hash !== finalized.hash ||
            reboundFinalized.number !== finalized.number ||
            reboundInclusion.hash !== inclusion.blockHash ||
            reboundInclusion.number !== `0x${BigInt(inclusion.blockNumber).toString(16)}` ||
            (finalizedNumber === inclusion.blockNumber && finalized.hash !== inclusion.blockHash)
          ) {
            throw new EvidenceFailure("finality_unproven");
          }
          return Object.freeze({
            blockNumber: finalizedNumber,
            blockHash: finalized.hash,
            observedAt,
          });
        } catch (error) {
          if (error instanceof EvidenceFailure && error.reason === "finality_unproven") throw error;
          throw new EvidenceFailure("finality_unproven");
        }
      }

      /**
       * The nonce-advance upgrade: with no receipt and no replacement, a
       * finalized-anchored EntryPoint nonce read proving the operation's own
       * key advanced past its sequence conclusively frees the lane. Purely an
       * upgrade over "receipt_missing" — any failure here falls back to the
       * weak pending observation, never to a new failure mode.
       */
      async function verifySupersession(): Promise<ObserveOperationResult | null> {
        if (operation.state !== "submission_attempted" && operation.state !== "submitted") {
          return null;
        }
        try {
          const finalized = parseBlock(
            await read({ type: "finalized_block", chainId: operation.identity.chainId }),
            new WeakSet(),
            "finality_unproven",
          );
          const blockNumber = decimal(parseQuantity(finalized.number));
          const nonceValue = await read({
            type: "entry_point_nonce",
            chainId: operation.identity.chainId,
            entryPoint: operation.identity.entryPoint,
            account: operation.identity.account,
            nonce: operation.identity.nonce,
            blockNumber,
          });
          if (typeof nonceValue !== "string") return null;
          const observedNonce = decimal(parseQuantity(nonceValue));
          const mask = (1n << 64n) - 1n;
          const observed = BigInt(observedNonce);
          const own = BigInt(operation.identity.nonce);
          if (observed >> 64n !== own >> 64n || (observed & mask) <= (own & mask)) {
            return null;
          }
          // The nonce was read by number alone, so rebind: the block at that
          // number must still be the exact finalized block whose hash the
          // supersession records. A provider answering the nonce from another
          // fork frees no lane.
          const rebound = parseBlock(
            await read({
              type: "canonical_block",
              chainId: operation.identity.chainId,
              blockNumber,
            }),
            new WeakSet(),
            "finality_unproven",
          );
          if (rebound.hash !== finalized.hash || rebound.number !== finalized.number) {
            return null;
          }
          const next = applyVerifiedOperationObservation(operation, {
            type: "record_superseded",
            identity: operation.identity,
            supersession: {
              kind: "entry_point_nonce_advanced",
              observedNonce,
              blockNumber,
              blockHash: finalized.hash,
              observedAt,
            },
          });
          if (next.state !== "superseded") return null;
          return frozenResult({ status: "superseded", operation: next });
        } catch {
          return null;
        }
      }

      try {
        const chainIdValue = await read({ type: "chain_id", chainId: operation.identity.chainId });
        if (chainIdValue !== operation.identity.chainId) {
          throw new EvidenceFailure("receipt_invalid");
        }

        let reference: UserOperationReference = operation.identity;
        let replacement = false;
        let inclusion = await verifyInclusion(reference);
        if (inclusion === null) {
          const candidateValue = await read({
            type: "replacement_candidate",
            chainId: operation.identity.chainId,
            entryPoint: operation.identity.entryPoint,
            account: operation.identity.account,
            nonce: operation.identity.nonce,
            excludedUserOperationHash: operation.identity.userOperationHash,
          });
          if (candidateValue === null) {
            const superseded = await verifySupersession();
            if (superseded) return superseded;
            return weakPending(operation, "receipt_missing");
          }
          const candidate = exact(
            candidateValue,
            ["userOperationHash"],
            "replacement candidate",
            new WeakSet(),
          );
          const candidateHash = parseHash(candidate.userOperationHash);
          if (candidateHash === operation.identity.userOperationHash) {
            throw new EvidenceFailure("receipt_invalid");
          }
          reference = Object.freeze({
            chainId: operation.identity.chainId,
            entryPoint: operation.identity.entryPoint,
            account: operation.identity.account,
            nonce: operation.identity.nonce,
            userOperationHash: candidateHash,
          });
          replacement = true;
          inclusion = await verifyInclusion(reference);
          if (inclusion === null) return weakPending(operation, "receipt_missing");
        }

        let includedOperation: Operation = operation;
        if (!replacement) {
          if (operation.state === "included" && !sameOccurrence(operation.inclusion, inclusion)) {
            return weakUnreadable(operation, "receipt_invalid");
          }
          includedOperation =
            operation.state === "included"
              ? operation
              : applyVerifiedOperationObservation(operation, {
                  type: "record_included",
                  identity: operation.identity,
                  inclusion,
                });
        }

        let finality: OperationFinality;
        try {
          finality = await verifyFinality(reference, inclusion);
        } catch {
          return weakUnreadable(includedOperation, "finality_unproven");
        }

        if (replacement) {
          const dropped = applyVerifiedOperationObservation(operation, {
            type: "record_dropped",
            identity: operation.identity,
            drop: {
              kind: "finalized_nonce_replacement",
              replacement: { identity: reference, inclusion, finality },
            },
          });
          if (dropped.state !== "dropped") throw new EvidenceFailure("receipt_invalid");
          return frozenResult({ status: "dropped", operation: dropped });
        }

        const finalized = applyVerifiedOperationObservation(includedOperation, {
          type: "record_finalized",
          identity: operation.identity,
          finality,
        });
        if (finalized.state !== "finalized") throw new EvidenceFailure("receipt_invalid");
        return frozenResult({ status: "finalized", operation: finalized });
      } catch (error) {
        if (error instanceof TimeoutFailure) return weakPending(operation, "timeout");
        if (error instanceof ProviderFailure)
          return weakUnreadable(operation, "provider_unavailable");
        if (error instanceof EvidenceFailure) return weakUnreadable(operation, error.reason);
        return weakUnreadable(operation, "receipt_invalid");
      }
    } finally {
      activeObservations -= 1;
      if (activeObservations === 0 && drained) {
        const resolve = drained;
        drained = null;
        resolve();
      }
    }
  }

  async function close(): Promise<void> {
    if (closed) return;
    if (closing) return closing;
    const attempt = Promise.resolve()
      .then(async () => {
        if (activeObservations > 0) {
          await new Promise<void>((resolve) => {
            drained = resolve;
          });
        }
        await capabilities.close();
      })
      .then(
        () => {
          closed = true;
        },
        () => {
          throw new OaathOperationObserverError(
            "operation_observer_close_failed",
            "operation observer close failed",
          );
        },
      )
      .finally(() => {
        if (!closed) closing = null;
      });
    closing = attempt;
    return attempt;
  }

  return Object.freeze({ observeOperation, close });
}
