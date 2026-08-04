/*
 * Pure boundary/state helpers for the owner-phone demo. The process keeps one
 * in-memory lane per account/chain; reload discards it and therefore cannot
 * infer authority or resubmit anything.
 *
 * @author taek <leekt216@gmail.com>
 */

export const LIVE_RPC_MAX_REQUESTS = 48;
export const LIVE_TRANSPORT_CONFIG = Object.freeze({ retryCount: 0 });
export const LIVE_RECEIPT_POLL_ATTEMPTS = 4;
export const LIVE_RECEIPT_POLL_INTERVAL_MS = 1_000;
export const DOCUMENTED_LIVE_FLOW_REQUESTS =
  12 + // account binding and nonce reads
  3 + // sponsorship
  3 + // submission
  3 * (LIVE_RECEIPT_POLL_ATTEMPTS + 2); // receipt polls + tx/receipt evidence

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
