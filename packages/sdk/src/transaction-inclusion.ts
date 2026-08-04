import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  type ExactRecord,
  exactRecord,
} from "@oaath/protocol";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/u;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;

export type CanonicalTransactionInclusionErrorScope = "transaction" | "event" | "canonical_block";

export class OaathCanonicalTransactionInclusionError extends Error {
  readonly scope: CanonicalTransactionInclusionErrorScope;

  constructor(scope: CanonicalTransactionInclusionErrorScope) {
    super("canonical_transaction_inclusion_unproven");
    this.name = "OaathCanonicalTransactionInclusionError";
    this.scope = scope;
  }
}

export interface CanonicalTransactionLogEvidence {
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

export interface CanonicalTransactionInclusionEvidence {
  readonly transactionHash: `0x${string}`;
  readonly blockNumber: `0x${string}`;
  readonly blockHash: `0x${string}`;
  readonly transactionIndex: `0x${string}`;
  readonly eventLog: CanonicalTransactionLogEvidence;
  readonly canonicalBlock: Readonly<{
    number: `0x${string}`;
    hash: `0x${string}`;
    parentHash: `0x${string}`;
    transactions: readonly `0x${string}`[];
  }>;
}

function fail(scope: CanonicalTransactionInclusionErrorScope): never {
  throw new OaathCanonicalTransactionInclusionError(scope);
}

function required(
  record: ExactRecord,
  key: string,
  scope: CanonicalTransactionInclusionErrorScope,
): unknown {
  if (!Object.hasOwn(record, key)) return fail(scope);
  return record[key];
}

function hash(value: unknown, scope: CanonicalTransactionInclusionErrorScope): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) return fail(scope);
  return value as `0x${string}`;
}

function address(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value)) return fail("transaction");
  return value as `0x${string}`;
}

function quantity(
  value: unknown,
  scope: CanonicalTransactionInclusionErrorScope,
): { canonical: `0x${string}`; value: bigint } {
  if (typeof value !== "string" || !QUANTITY.test(value)) return fail(scope);
  return { canonical: value as `0x${string}`, value: BigInt(value) };
}

function record(
  value: unknown,
  label: string,
  context: CaptureContext,
  scope: CanonicalTransactionInclusionErrorScope,
): ExactRecord {
  return captureRecord(value, label, context, () => fail(scope));
}

function logEvidence(
  value: unknown,
  context: CaptureContext,
): CanonicalTransactionLogEvidence &
  Readonly<{ transactionIndexValue: bigint; logIndexValue: bigint }> {
  const captured = record(value, "transaction log", context, "event");
  const topics = captureDenseArray(
    required(captured, "topics", "event"),
    "transaction log topics",
    context,
    () => fail("event"),
  ).map((topic) => hash(topic, "event"));
  const data = required(captured, "data", "event");
  const removed = required(captured, "removed", "event");
  const transactionIndex = quantity(required(captured, "transactionIndex", "event"), "event");
  const logIndex = quantity(required(captured, "logIndex", "event"), "event");
  if (
    typeof data !== "string" ||
    !HEX_DATA.test(data) ||
    typeof removed !== "boolean" ||
    transactionIndex.value > BigInt(Number.MAX_SAFE_INTEGER) ||
    logIndex.value > BigInt(Number.MAX_SAFE_INTEGER)
  )
    return fail("event");
  const logAddress = required(captured, "address", "event");
  if (typeof logAddress !== "string" || !ADDRESS.test(logAddress)) return fail("event");
  return Object.freeze({
    address: logAddress as `0x${string}`,
    blockNumber: quantity(required(captured, "blockNumber", "event"), "event").canonical,
    blockHash: hash(required(captured, "blockHash", "event"), "event"),
    transactionHash: hash(required(captured, "transactionHash", "event"), "event"),
    transactionIndex: transactionIndex.canonical,
    transactionIndexValue: transactionIndex.value,
    logIndex: logIndex.canonical,
    logIndexValue: logIndex.value,
    removed,
    topics: Object.freeze(topics),
    data: data as `0x${string}`,
  });
}

/**
 * Strictly captures and proves one transaction's canonical block membership
 * together with the exact matching EntryPoint event. RPC records may contain
 * unrelated standard fields, but every consumed field must be an enumerable
 * own data property with a canonical wire shape.
 */
export function validateCanonicalTransactionInclusion(
  value: unknown,
): CanonicalTransactionInclusionEvidence {
  const context: CaptureContext = new WeakSet();
  const input = exactRecord(
    value,
    [
      "entryPoint",
      "userOperationHash",
      "transactionHash",
      "transactionReceipt",
      "transaction",
      "canonicalBlock",
    ],
    "canonical transaction inclusion input",
    context,
    () => fail("transaction"),
  );
  const entryPoint = address(input.entryPoint);
  const userOperationHash = hash(input.userOperationHash, "transaction");
  const transactionHash = hash(input.transactionHash, "transaction");
  const receipt = record(input.transactionReceipt, "transaction receipt", context, "transaction");
  const transaction = record(input.transaction, "transaction", context, "transaction");
  const block = record(input.canonicalBlock, "canonical block", context, "canonical_block");

  const receiptTransactionIndex = quantity(
    required(receipt, "transactionIndex", "transaction"),
    "transaction",
  );
  const transactionIndex = quantity(
    required(transaction, "transactionIndex", "transaction"),
    "transaction",
  );
  if (
    receiptTransactionIndex.value > BigInt(Number.MAX_SAFE_INTEGER) ||
    transactionIndex.value > BigInt(Number.MAX_SAFE_INTEGER)
  )
    return fail("transaction");

  const blockNumber = quantity(
    required(receipt, "blockNumber", "transaction"),
    "transaction",
  ).canonical;
  const blockHash = hash(required(receipt, "blockHash", "transaction"), "transaction");
  if (
    hash(required(receipt, "transactionHash", "transaction"), "transaction") !== transactionHash ||
    hash(required(transaction, "hash", "transaction"), "transaction") !== transactionHash ||
    quantity(required(transaction, "blockNumber", "transaction"), "transaction").canonical !==
      blockNumber ||
    hash(required(transaction, "blockHash", "transaction"), "transaction") !== blockHash ||
    transactionIndex.canonical !== receiptTransactionIndex.canonical
  )
    return fail("transaction");

  const logs = captureDenseArray(
    required(receipt, "logs", "event"),
    "transaction receipt logs",
    context,
    () => fail("event"),
  ).map((log) => logEvidence(log, context));
  const logIndexes = new Set<string>();
  for (const log of logs) {
    if (
      log.transactionHash !== transactionHash ||
      log.blockNumber !== blockNumber ||
      log.blockHash !== blockHash ||
      log.transactionIndex !== transactionIndex.canonical ||
      logIndexes.has(log.logIndex)
    )
      return fail("event");
    logIndexes.add(log.logIndex);
  }
  const candidates = logs.filter(
    (log) =>
      log.address === entryPoint &&
      log.topics[0] === "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f" &&
      log.topics[1] === userOperationHash,
  );
  if (candidates.length !== 1) return fail("event");
  const eventLog = candidates[0];
  if (!eventLog || eventLog.removed) return fail("event");

  const canonicalNumber = quantity(
    required(block, "number", "canonical_block"),
    "canonical_block",
  ).canonical;
  const canonicalHash = hash(required(block, "hash", "canonical_block"), "canonical_block");
  const canonicalParentHash = hash(
    required(block, "parentHash", "canonical_block"),
    "canonical_block",
  );
  const transactions = captureDenseArray(
    required(block, "transactions", "canonical_block"),
    "canonical block transactions",
    context,
    () => fail("canonical_block"),
  ).map((item) => hash(item, "canonical_block"));
  const index = Number(transactionIndex.value);
  if (
    canonicalNumber !== blockNumber ||
    canonicalHash !== blockHash ||
    index >= transactions.length ||
    transactions[index] !== transactionHash ||
    transactions.filter((item) => item === transactionHash).length !== 1
  )
    return fail("canonical_block");

  const capturedEventLog: CanonicalTransactionLogEvidence = Object.freeze({
    address: eventLog.address,
    blockNumber: eventLog.blockNumber,
    blockHash: eventLog.blockHash,
    transactionHash: eventLog.transactionHash,
    transactionIndex: eventLog.transactionIndex,
    logIndex: eventLog.logIndex,
    removed: eventLog.removed,
    topics: eventLog.topics,
    data: eventLog.data,
  });
  return Object.freeze({
    transactionHash,
    blockNumber,
    blockHash,
    transactionIndex: transactionIndex.canonical,
    eventLog: capturedEventLog,
    canonicalBlock: Object.freeze({
      number: canonicalNumber,
      hash: canonicalHash,
      parentHash: canonicalParentHash,
      transactions: Object.freeze(transactions),
    }),
  });
}

/** Rejects contradictory by-hash/number views of the same inclusion block. */
export function requireSameCanonicalTransactionInclusion(
  first: CanonicalTransactionInclusionEvidence,
  rebound: CanonicalTransactionInclusionEvidence,
): void {
  if (
    first.transactionHash !== rebound.transactionHash ||
    first.blockNumber !== rebound.blockNumber ||
    first.blockHash !== rebound.blockHash ||
    first.transactionIndex !== rebound.transactionIndex ||
    first.eventLog.logIndex !== rebound.eventLog.logIndex ||
    first.canonicalBlock.parentHash !== rebound.canonicalBlock.parentHash ||
    first.canonicalBlock.transactions.length !== rebound.canonicalBlock.transactions.length ||
    first.canonicalBlock.transactions.some(
      (transactionHash, index) => transactionHash !== rebound.canonicalBlock.transactions[index],
    )
  )
    fail("canonical_block");
}
