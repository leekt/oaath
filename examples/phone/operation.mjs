/*
 * Pure boundary/state helpers for the owner-phone demo. The process keeps one
 * in-memory lane per account/chain; reload discards it and therefore cannot
 * infer authority or resubmit anything.
 *
 * @author taek <leekt216@gmail.com>
 */

import { verifyFinalizedBlockAncestry } from "@oaath/sdk";
import { decodeEventLog, toEventSelector } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";

export const LIVE_FINALITY_MAX_ANCESTRY_DEPTH = 8;
export const LIVE_RPC_MAX_REQUESTS = 81;
export const LIVE_TRANSPORT_CONFIG = Object.freeze({ retryCount: 0 });
export const LIVE_RECEIPT_POLL_ATTEMPTS = 4;
export const LIVE_RECEIPT_POLL_INTERVAL_MS = 1_000;
export const DOCUMENTED_LIVE_FLOW_REQUESTS =
  12 + // owner/session binding misses with immutable evidence cached
  3 + // nonce reads, including the first enable attempt
  3 + // sponsorship
  3 + // submission
  3 *
    (LIVE_RECEIPT_POLL_ATTEMPTS +
      2 + // transaction + receipt
      1 + // finalized head
      LIVE_FINALITY_MAX_ANCESTRY_DEPTH + // bounded parent-hash walk
      2); // canonical rebounds of finalized and inclusion blocks

/** Caches only immutable successful Kernel binding evidence. */
export function cacheImmutableKernelReads(reads) {
  const cache = new Map();
  const immutable = (request, result) =>
    request.type === "chain_id" ||
    request.type === "runtime_code_hash" ||
    request.type === "kernel_factory_implementation" ||
    request.type === "kernel_factory_account" ||
    (request.type === "code" && typeof result === "string" && result !== "0x");
  return Object.freeze({
    async read(request) {
      const key = JSON.stringify(request);
      if (cache.has(key)) return cache.get(key);
      const result = await reads.read(request);
      if (immutable(request, result)) cache.set(key, result);
      return result;
    },
  });
}

export class LiveRequestBudget {
  #count = 0;
  #methods = new Map();

  take(method) {
    if (this.#count >= LIVE_RPC_MAX_REQUESTS) throw new Error("zerodev_request_budget_exhausted");
    this.#count += 1;
    this.#methods.set(method, (this.#methods.get(method) ?? 0) + 1);
    return this.#count;
  }

  snapshot() {
    return Object.freeze({
      count: this.#count,
      methods: Object.freeze(
        [...this.#methods.entries()].sort(([left], [right]) => left.localeCompare(right)),
      ),
    });
  }
}

const UINT256_MAX = (1n << 256n) - 1n;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const DATA = /^0x(?:[0-9a-f]{2})*$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const USER_OPERATION_EVENT = toEventSelector(
  "UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)",
);
const lower = (value) => (typeof value === "string" ? value.toLowerCase() : "");

/** Synchronously reserves a valid one-shot code before its handler can await. */
export class OneShotPairing {
  #hash;
  #expiresAt;
  #consumed = false;

  constructor({ hash, expiresAt }) {
    this.#hash = hash;
    this.#expiresAt = expiresAt;
  }

  reserve({ hash, now }) {
    if (this.#consumed || now >= this.#expiresAt || hash !== this.#hash)
      throw new Error("pairing_invalid");
    this.#consumed = true;
  }
}

export const exactKeys = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === [...keys].sort().join(",");

function quantity(value) {
  if (typeof value !== "string" || !QUANTITY.test(value))
    throw new Error("zerodev_sponsorship_response_invalid");
  const parsed = BigInt(value);
  if (parsed > UINT256_MAX) throw new Error("zerodev_sponsorship_response_invalid");
  return parsed.toString();
}

/** Exact-captures the hostile ZeroDev sponsorship response before conversion. */
export function captureSponsorship(value) {
  const keys = [
    "callGasLimit",
    "verificationGasLimit",
    "preVerificationGas",
    "paymaster",
    "paymasterVerificationGasLimit",
    "paymasterPostOpGasLimit",
    "paymasterData",
  ];
  if (!exactKeys(value, keys)) throw new Error("zerodev_sponsorship_response_invalid");
  const record = value;
  if (typeof record.paymaster !== "string" || !ADDRESS.test(record.paymaster))
    throw new Error("zerodev_sponsorship_response_invalid");
  if (typeof record.paymasterData !== "string" || !DATA.test(record.paymasterData))
    throw new Error("zerodev_sponsorship_response_invalid");
  return Object.freeze({
    callGasLimit: quantity(record.callGasLimit),
    verificationGasLimit: quantity(record.verificationGasLimit),
    preVerificationGas: quantity(record.preVerificationGas),
    paymaster: record.paymaster,
    paymasterVerificationGasLimit: quantity(record.paymasterVerificationGasLimit),
    paymasterPostOpGasLimit: quantity(record.paymasterPostOpGasLimit),
    paymasterData: record.paymasterData,
  });
}

function sortedJsonValue(value) {
  if (Array.isArray(value)) return value.map(sortedJsonValue);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortedJsonValue(value[key])]),
    );
  return value;
}

/** Canonical compact UTF-8 consent JSON: recursively sorted object keys. */
export function canonicalDisplay(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("signature_display_invalid");
  return JSON.stringify(sortedJsonValue(value));
}

/** Rejects whitespace, duplicate-key collapse, noncanonical escapes, and drift. */
export function captureCanonicalDisplay(display, digest) {
  if (typeof display !== "string" || typeof digest !== "string" || !HASH.test(digest))
    throw new Error("signature_display_invalid");
  let parsed;
  try {
    parsed = JSON.parse(display);
  } catch {
    throw new Error("signature_display_invalid");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    parsed.digest !== digest ||
    canonicalDisplay(parsed) !== display
  )
    throw new Error("signature_display_invalid");
  return display;
}

/** Synchronous reservation owner for consent/authority request lanes. */
export class AtomicReservationLane {
  #active = null;
  #lastTerminal = null;

  reserve(token, detail = {}) {
    if (this.#active !== null) throw new Error("reservation_lane_occupied");
    this.#active = { token, state: "pre-submit", requestId: null, ...detail };
    return this.#active;
  }

  markPossiblySubmitted(token) {
    if (this.#active?.token !== token) throw new Error("reservation_lane_mismatch");
    this.#active.state = "possibly-submitted";
  }

  activate(token, requestId) {
    if (this.#active?.token !== token) throw new Error("reservation_lane_mismatch");
    this.#active.state = "active";
    this.#active.requestId = requestId;
  }

  release(token) {
    if (this.#active?.token !== token) throw new Error("reservation_lane_mismatch");
    this.#active = null;
  }

  terminate(token, outcome) {
    if (this.#active?.token !== token) throw new Error("reservation_lane_mismatch");
    if (outcome !== "rejected" && outcome !== "completed")
      throw new Error("reservation_terminal_state_invalid");
    this.#lastTerminal = Object.freeze({ token, state: outcome });
    this.#active = null;
  }

  get active() {
    return this.#active;
  }

  get lastTerminal() {
    return this.#lastTerminal;
  }
}

/**
 * Owns the permission route's indivisible local claim on both permission and
 * shared signature-request lanes. All occupancy checks happen before either
 * lane mutates, and cleanup is allowed only while both token-owned claims are
 * definitely pre-submission.
 */
export class AtomicPermissionReservation {
  #permissionLane;
  #signatureLane;

  constructor(permissionLane, signatureLane) {
    this.#permissionLane = permissionLane;
    this.#signatureLane = signatureLane;
  }

  reserve(token, sessionAddress) {
    if (this.#permissionLane.active !== null) throw new Error("permission_already_requested");
    if (this.#signatureLane.active !== null) throw new Error("signature_request_lane_occupied");
    this.#permissionLane.reserve(token, { sessionAddress });
    this.#signatureLane.reserve(token, { purpose: "permission" });
  }

  markPossiblySubmitted(token) {
    this.#permissionLane.markPossiblySubmitted(token);
    this.#signatureLane.markPossiblySubmitted(token);
  }

  activatePermission(token, requestId) {
    this.#permissionLane.activate(token, requestId);
  }

  releasePreSubmission(token) {
    if (this.#permissionLane.active?.token !== token || this.#signatureLane.active?.token !== token)
      throw new Error("reservation_lane_mismatch");
    if (
      this.#permissionLane.active.state !== "pre-submit" ||
      this.#signatureLane.active.state !== "pre-submit"
    )
      throw new Error("reservation_not_pre_submission");
    this.#permissionLane.release(token);
    this.#signatureLane.release(token);
  }
}

/** One operation lane. Only terminal observation releases it. */
export class OperationLane {
  #active = null;

  claim(operationId) {
    if (this.#active !== null) throw new Error("operation_lane_occupied");
    this.#active = operationId;
  }

  replace(expected, operationId) {
    if (this.#active !== expected) throw new Error("operation_lane_mismatch");
    this.#active = operationId;
  }

  cancel(expected) {
    if (this.#active !== expected) throw new Error("operation_lane_mismatch");
    this.#active = null;
  }

  release(operationId, status) {
    if (this.#active !== operationId) throw new Error("operation_lane_mismatch");
    if (status !== "included" && status !== "reverted") throw new Error("operation_not_terminal");
    this.#active = null;
  }

  get active() {
    return this.#active;
  }
}

export function pairingSecretMayRender({ simulate, isTTY }) {
  return !simulate && isTTY === true;
}

export function operationAction(status) {
  if (status === "prepared") return "submit";
  if (status === "submitted" || status === "unresolved") return "observe";
  if (status === "included" || status === "reverted" || status === "rejected") return "return";
  throw new Error("operation_state_invalid");
}

export function permissionMaterializedAfter({ current, installsPermission, status }) {
  return current || (installsPermission && status === "included");
}

export function validateBundlerAcceptance(preparedHash, returnedHash) {
  if (!HASH.test(preparedHash) || typeof returnedHash !== "string" || !HASH.test(returnedHash))
    throw new Error("zerodev_submission_response_invalid");
  if (returnedHash !== preparedHash) throw new Error("zerodev_submission_hash_mismatch");
  return Object.freeze({ userOperationHash: returnedHash });
}

const requireHash = (value, code) => {
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(code);
  return value;
};
const requireQuantity = (value, code) => {
  if (typeof value !== "string" || !QUANTITY.test(value)) throw new Error(code);
  return BigInt(value);
};

/**
 * Validates the authoritative EntryPoint event, its transaction, canonical
 * inclusion block, and the node's finalized head. No outer status or bundler
 * success flag is treated as UserOperation evidence.
 */
export async function validateFinalizedUserOperation({ operation, transactionHash, rpc }) {
  const prepared = operation.prepared;
  const userOperationHash = requireHash(prepared.userOperationHash, "operation_evidence_invalid");
  const account = lower(prepared.userOperation.sender);
  const entryPoint = lower(prepared.entryPoint.address);
  const txHash = requireHash(transactionHash, "operation_evidence_invalid");
  const [receipt, transaction] = await Promise.all([
    rpc("eth_getTransactionReceipt", [txHash]),
    rpc("eth_getTransactionByHash", [txHash]),
  ]);
  if (
    receipt === null ||
    typeof receipt !== "object" ||
    transaction === null ||
    typeof transaction !== "object" ||
    lower(receipt.transactionHash) !== txHash ||
    lower(transaction.hash) !== txHash ||
    lower(receipt.to) !== entryPoint ||
    lower(transaction.to) !== entryPoint ||
    receipt.status !== "0x1"
  )
    throw new Error("operation_transaction_evidence_invalid");
  const blockHash = requireHash(receipt.blockHash, "operation_transaction_evidence_invalid");
  const blockNumber = requireQuantity(
    receipt.blockNumber,
    "operation_transaction_evidence_invalid",
  );
  if (
    lower(transaction.blockHash) !== blockHash ||
    requireQuantity(transaction.blockNumber, "operation_transaction_evidence_invalid") !==
      blockNumber ||
    (transaction.chainId !== undefined &&
      requireQuantity(transaction.chainId, "operation_transaction_evidence_invalid") !==
        BigInt(operation.chainId)) ||
    !Array.isArray(receipt.logs)
  )
    throw new Error("operation_transaction_evidence_invalid");

  const matches = [];
  for (const log of receipt.logs) {
    if (
      log === null ||
      typeof log !== "object" ||
      lower(log.address) !== entryPoint ||
      !Array.isArray(log.topics) ||
      lower(log.topics[0]) !== USER_OPERATION_EVENT ||
      lower(log.topics[1]) !== userOperationHash
    )
      continue;
    try {
      if (
        typeof log.address !== "string" ||
        !ADDRESS.test(log.address) ||
        log.topics.length !== 4 ||
        log.topics.some((topic) => typeof topic !== "string" || !HASH.test(topic)) ||
        typeof log.data !== "string" ||
        !DATA.test(log.data) ||
        log.data.length !== 258
      )
        throw new Error("operation_event_evidence_invalid");
      const decoded = decodeEventLog({
        abi: entryPoint07Abi,
        data: log.data,
        topics: log.topics,
        strict: true,
      });
      if (
        decoded.eventName !== "UserOperationEvent" ||
        lower(decoded.args.userOpHash) !== userOperationHash ||
        lower(decoded.args.sender) !== account ||
        BigInt(decoded.args.nonce) !== BigInt(prepared.userOperation.nonce) ||
        requireHash(log.transactionHash, "operation_event_evidence_invalid") !== txHash ||
        requireHash(log.blockHash, "operation_event_evidence_invalid") !== blockHash ||
        requireQuantity(log.blockNumber, "operation_event_evidence_invalid") !== blockNumber ||
        log.removed === true ||
        typeof decoded.args.success !== "boolean"
      )
        throw new Error("operation_event_evidence_invalid");
      matches.push(decoded.args.success);
    } catch {
      throw new Error("operation_event_evidence_invalid");
    }
  }
  if (matches.length !== 1) throw new Error("operation_event_evidence_invalid");

  const reference = (value) => {
    if (value === null || typeof value !== "object")
      throw new Error("operation_finality_evidence_invalid");
    return {
      number: value.number,
      hash: value.hash,
      parentHash: value.parentHash,
    };
  };
  let finalized;
  try {
    const finalizedValue = await rpc("eth_getBlockByNumber", ["finalized", false]);
    finalized = await verifyFinalizedBlockAncestry({
      finalized: reference(finalizedValue),
      inclusion: { number: `0x${blockNumber.toString(16)}`, hash: blockHash },
      maxDepth: LIVE_FINALITY_MAX_ANCESTRY_DEPTH,
      readParent: async (parentHash) =>
        reference(await rpc("eth_getBlockByHash", [parentHash, false])),
      readCanonical: async (number) =>
        reference(await rpc("eth_getBlockByNumber", [`0x${BigInt(number).toString(16)}`, false])),
    });
  } catch {
    throw new Error("operation_finality_evidence_invalid");
  }

  return Object.freeze({
    chainId: operation.chainId,
    account,
    userOperationHash,
    transactionHash: txHash,
    blockHash,
    blockNumber: `0x${blockNumber.toString(16)}`,
    finalizedBlockHash: finalized.hash,
    finalizedBlockNumber: finalized.number,
    status: matches[0] ? "included" : "reverted",
  });
}

/** Forces every preparation attempt to capture the current EntryPoint sequence. */
export async function withFreshSequence(input, readSequence) {
  return Object.freeze({ ...input, sequence: await readSequence() });
}

/** Captures the first canonical transaction hash as immutable operation evidence. */
export function captureOperationTransactionHash(operation, value) {
  const transactionHash = requireHash(value, "operation_evidence_invalid");
  if (operation.transactionHash !== undefined) {
    if (operation.transactionHash !== transactionHash)
      throw new Error("operation_transaction_hash_conflict");
    return transactionHash;
  }
  Object.defineProperty(operation, "transactionHash", {
    value: transactionHash,
    enumerable: true,
    writable: false,
    configurable: false,
  });
  return transactionHash;
}

const terminalOperation = (operation) =>
  operation.status === "included" ||
  operation.status === "reverted" ||
  operation.status === "rejected" ||
  operation.status === "cancelled";

const unresolvedResult = (operation) =>
  Object.freeze({
    status: "unresolved",
    operationId: operation.operationId,
    userOperationHash: operation.prepared.userOperationHash,
    ...(operation.transactionHash ? { transactionHash: operation.transactionHash } : {}),
  });

const currentResult = (operation) => operation.result ?? unresolvedResult(operation);
const ownsTransition = (operation, owner, ownsLane) =>
  operation.transition === owner && !terminalOperation(operation) && ownsLane(operation);

function beginTransition(operation, kind, run) {
  if (operation.transition?.promise) return operation.transition.promise;
  const owner = { kind, promise: null };
  operation.transition = owner;
  owner.promise = (async () => {
    try {
      return await run(owner);
    } finally {
      // A stale completion never releases a replacement transition owner.
      if (operation.transition === owner) delete operation.transition;
    }
  })();
  return owner.promise;
}

async function observeOwned({ operation, owner, observe, terminalize, ownsLane }) {
  try {
    const evidence = await observe(operation);
    if (!ownsTransition(operation, owner, ownsLane)) return currentResult(operation);
    if (evidence !== null) return terminalize(operation, evidence);
  } catch {
    if (!ownsTransition(operation, owner, ownsLane)) return currentResult(operation);
    if (terminalOperation(operation)) return currentResult(operation);
  }
  if (!ownsTransition(operation, owner, ownsLane)) return currentResult(operation);
  operation.status = "unresolved";
  return unresolvedResult(operation);
}

/**
 * One synchronous observation owner per operation. Concurrent handlers join
 * the same promise; only the current owner of the still-occupied lane may
 * terminalize or downgrade to unresolved.
 */
export function observeOnce({ operation, observe, terminalize, ownsLane = () => true }) {
  if (operation.transition?.promise) return operation.transition.promise;
  if (terminalOperation(operation)) return Promise.resolve(operation.result);
  if (operationAction(operation.status) !== "observe")
    return Promise.reject(new Error("operation_not_observable"));
  return beginTransition(operation, "observe", (owner) =>
    observeOwned({ operation, owner, observe, terminalize, ownsLane }),
  );
}

/**
 * One synchronous submission owner per operation. `signature` may be an async
 * attempt-owned preparation closure and can return `{ kind: "pending", result
 * }` or `{ kind: "terminal", status, result }` before send. Once send starts,
 * every owned failure is unresolved; before send, failures restore prepared.
 */
export function submitOnce({
  operation,
  signature,
  send,
  observe,
  terminalize,
  terminateWithoutSubmission,
  ownsLane = () => true,
}) {
  if (operation.transition?.promise) return operation.transition.promise;
  if (terminalOperation(operation)) return Promise.resolve(operation.result);
  if (operationAction(operation.status) !== "submit")
    return Promise.reject(new Error("operation_not_resubmittable"));

  return beginTransition(operation, "submit", async (owner) => {
    let sendStarted = false;
    try {
      const preparedSignature =
        typeof signature === "function" ? await signature() : { kind: "signature", signature };
      if (!ownsTransition(operation, owner, ownsLane)) return currentResult(operation);
      if (preparedSignature?.kind === "pending") return preparedSignature.result;
      if (preparedSignature?.kind === "terminal") {
        terminateWithoutSubmission?.(operation, preparedSignature);
        return operation.result;
      }
      const exactSignature =
        preparedSignature?.kind === "signature" ? preparedSignature.signature : preparedSignature;
      operation.status = "submitting";
      operation.submissionAttempted = true;
      sendStarted = true;
      const sent = await send(operation.prepared, exactSignature, (transactionHash) => {
        if (ownsTransition(operation, owner, ownsLane))
          captureOperationTransactionHash(operation, transactionHash);
      });
      if (!ownsTransition(operation, owner, ownsLane)) return currentResult(operation);
      const acceptance = validateBundlerAcceptance(
        operation.prepared.userOperationHash,
        sent.userOperationHash,
      );
      operation.acceptance = Object.freeze({ ...acceptance, acceptedAt: Date.now() });
      if (sent.transactionHash !== undefined)
        captureOperationTransactionHash(operation, sent.transactionHash);
      operation.status = "submitted";
      return await observeOwned({ operation, owner, observe, terminalize, ownsLane });
    } catch (error) {
      if (!ownsTransition(operation, owner, ownsLane)) return currentResult(operation);
      if (terminalOperation(operation)) return currentResult(operation);
      if (!sendStarted) {
        operation.status = "prepared";
        throw error;
      }
      operation.status = "unresolved";
      return unresolvedResult(operation);
    }
  });
}
