/*
 * Strict evidence capture for the repository-owned Anvil demo only. This code
 * checks the owned local transport and chain views; it is not Byzantine RPC
 * verification and is deliberately not part of the public SDK surface.
 *
 * @author taek <leekt216@gmail.com>
 */
import { captureDenseArray, captureRecord, exactRecord } from "@oaath/protocol";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/u;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const USER_OPERATION_EVENT = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";

export class OwnedLocalTransactionInclusionError extends Error {
  constructor(scope) {
    super("owned_local_transaction_inclusion_invalid");
    this.name = "OwnedLocalTransactionInclusionError";
    this.scope = scope;
  }
}

const fail = (scope) => {
  throw new OwnedLocalTransactionInclusionError(scope);
};

const required = (record, key, scope) => {
  if (!Object.hasOwn(record, key)) return fail(scope);
  return record[key];
};

const hash = (value, scope) => {
  if (typeof value !== "string" || !HASH.test(value)) return fail(scope);
  return value;
};

const address = (value) => {
  if (typeof value !== "string" || !ADDRESS.test(value)) return fail("transaction");
  return value;
};

const quantity = (value, scope) => {
  if (typeof value !== "string" || !QUANTITY.test(value)) return fail(scope);
  return { canonical: value, value: BigInt(value) };
};

const record = (value, label, context, scope) =>
  captureRecord(value, label, context, () => fail(scope));

function logEvidence(value, context) {
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
    address: logAddress,
    blockNumber: quantity(required(captured, "blockNumber", "event"), "event").canonical,
    blockHash: hash(required(captured, "blockHash", "event"), "event"),
    transactionHash: hash(required(captured, "transactionHash", "event"), "event"),
    transactionIndex: transactionIndex.canonical,
    logIndex: logIndex.canonical,
    removed,
    topics: Object.freeze(topics),
    data,
  });
}

/** Strictly captures one transaction and EntryPoint event from owned Anvil. */
export function validateOwnedLocalTransactionInclusion(value) {
  const context = new WeakSet();
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
    "owned local transaction inclusion input",
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
  const logIndexes = new Set();
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
      log.topics[0] === USER_OPERATION_EVENT &&
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

  return Object.freeze({
    transactionHash,
    blockNumber,
    blockHash,
    transactionIndex: transactionIndex.canonical,
    eventLog: Object.freeze({ ...eventLog }),
    canonicalBlock: Object.freeze({
      number: canonicalNumber,
      hash: canonicalHash,
      parentHash: canonicalParentHash,
      transactions: Object.freeze(transactions),
    }),
  });
}

/** Every immutable captured field must survive the owned local number rebound. */
export function requireSameOwnedLocalTransactionInclusion(first, rebound) {
  const leftLog = first.eventLog;
  const rightLog = rebound.eventLog;
  if (
    first.transactionHash !== rebound.transactionHash ||
    first.blockNumber !== rebound.blockNumber ||
    first.blockHash !== rebound.blockHash ||
    first.transactionIndex !== rebound.transactionIndex ||
    leftLog.address !== rightLog.address ||
    leftLog.blockNumber !== rightLog.blockNumber ||
    leftLog.blockHash !== rightLog.blockHash ||
    leftLog.transactionHash !== rightLog.transactionHash ||
    leftLog.transactionIndex !== rightLog.transactionIndex ||
    leftLog.logIndex !== rightLog.logIndex ||
    leftLog.removed !== rightLog.removed ||
    leftLog.data !== rightLog.data ||
    leftLog.topics.length !== rightLog.topics.length ||
    leftLog.topics.some((topic, index) => topic !== rightLog.topics[index]) ||
    first.canonicalBlock.number !== rebound.canonicalBlock.number ||
    first.canonicalBlock.hash !== rebound.canonicalBlock.hash ||
    first.canonicalBlock.parentHash !== rebound.canonicalBlock.parentHash ||
    first.canonicalBlock.transactions.length !== rebound.canonicalBlock.transactions.length ||
    first.canonicalBlock.transactions.some(
      (transactionHash, index) => transactionHash !== rebound.canonicalBlock.transactions[index],
    )
  )
    fail("canonical_block");
}

const blockReference = (value) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("owned_local_finality_invalid");
  if (
    Object.keys(value).sort().join(",") !== "hash,number,parentHash" ||
    typeof value.number !== "string" ||
    !QUANTITY.test(value.number) ||
    typeof value.hash !== "string" ||
    !HASH.test(value.hash) ||
    typeof value.parentHash !== "string" ||
    !HASH.test(value.parentHash)
  )
    throw new Error("owned_local_finality_invalid");
  return Object.freeze({ number: value.number, hash: value.hash, parentHash: value.parentHash });
};

/** Bounded ancestry and endpoint rebound over repository-owned Anvil. */
export async function verifyOwnedLocalFinalizedBlockAncestry(input) {
  if (
    !Number.isSafeInteger(input.maxDepth) ||
    input.maxDepth < 0 ||
    typeof input.readParent !== "function" ||
    typeof input.readCanonical !== "function"
  )
    throw new Error("owned_local_finality_invalid");
  const finalized = blockReference(input.finalized);
  const inclusion = blockReference({
    number: input.inclusion.number,
    hash: input.inclusion.hash,
    parentHash: `0x${"00".repeat(32)}`,
  });
  const finalizedNumber = BigInt(finalized.number);
  const inclusionNumber = BigInt(inclusion.number);
  if (finalizedNumber < inclusionNumber || finalizedNumber - inclusionNumber > input.maxDepth)
    throw new Error("owned_local_finality_invalid");

  let descendant = finalized;
  let descendantNumber = finalizedNumber;
  while (descendantNumber > inclusionNumber) {
    const parent = blockReference(await input.readParent(descendant.parentHash));
    const parentNumber = BigInt(parent.number);
    if (parent.hash !== descendant.parentHash || parentNumber + 1n !== descendantNumber)
      throw new Error("owned_local_finality_invalid");
    descendant = parent;
    descendantNumber = parentNumber;
  }
  if (descendant.hash !== inclusion.hash) throw new Error("owned_local_finality_invalid");

  const [reboundFinalized, reboundInclusion] = await Promise.all([
    input.readCanonical(finalizedNumber.toString(10)).then(blockReference),
    input.readCanonical(inclusionNumber.toString(10)).then(blockReference),
  ]);
  if (
    reboundFinalized.number !== finalized.number ||
    reboundFinalized.hash !== finalized.hash ||
    reboundInclusion.number !== inclusion.number ||
    reboundInclusion.hash !== inclusion.hash
  )
    throw new Error("owned_local_finality_invalid");
  return finalized;
}
