/** One-use wallet-owned presentation for an exact `wallet_sendCalls` execution. */

const CONFIRMATION_PREFIX = "wallet-call-confirmation:";
const TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const ORIGIN = /^https?:\/\//u;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const CHAIN_ID = /^0x[1-9a-f][0-9a-f]*$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const MAX_DATE_MILLISECONDS = 8_640_000_000_000_000n;

/** token -> the worker-memory-only decision authority for one open tab. */
const pending = new Map();

function exactKeys(value, keys) {
  try {
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).length === keys.length &&
      keys.every((key) => Object.hasOwn(value, key))
    );
  } catch {
    return false;
  }
}

function hasOwnField(value, key) {
  try {
    return value !== null && typeof value === "object" && Object.hasOwn(value, key);
  } catch {
    return false;
  }
}

function utcSeconds(value) {
  if (typeof value !== "string" || !DECIMAL.test(value)) return null;
  const milliseconds = BigInt(value) * 1_000n;
  if (milliseconds > MAX_DATE_MILLISECONDS) return null;
  try {
    return new Date(Number(milliseconds)).toISOString();
  } catch {
    return null;
  }
}

function capturePublicConfirmation(origin, confirmation) {
  const hasValidityTimeRange = hasOwnField(confirmation, "validityTimeRange");
  const hasConfirmationDeadline = hasOwnField(confirmation, "confirmationExpiresAt");
  const confirmationKeys = ["account", "chainId", "calls"];
  if (hasConfirmationDeadline) confirmationKeys.push("confirmationExpiresAt");
  if (hasValidityTimeRange) confirmationKeys.push("validityTimeRange");
  if (
    typeof origin !== "string" ||
    !ORIGIN.test(origin) ||
    !exactKeys(confirmation, confirmationKeys) ||
    typeof confirmation.account !== "string" ||
    !ADDRESS.test(confirmation.account) ||
    typeof confirmation.chainId !== "string" ||
    !CHAIN_ID.test(confirmation.chainId) ||
    !Array.isArray(confirmation.calls) ||
    confirmation.calls.length === 0 ||
    confirmation.calls.length > 64
  ) {
    throw new Error("wallet call confirmation is unavailable");
  }
  const confirmationExpiresAt = hasConfirmationDeadline
    ? confirmation.confirmationExpiresAt
    : undefined;
  if (
    confirmationExpiresAt !== undefined &&
    (!Number.isSafeInteger(confirmationExpiresAt) || confirmationExpiresAt < 1)
  ) {
    throw new Error("wallet call confirmation is unavailable");
  }
  const calls = confirmation.calls.map((call) => {
    if (
      !exactKeys(call, ["target", "value", "data"]) ||
      typeof call.target !== "string" ||
      !ADDRESS.test(call.target) ||
      typeof call.value !== "string" ||
      !DECIMAL.test(call.value) ||
      typeof call.data !== "string" ||
      !BYTES.test(call.data)
    ) {
      throw new Error("wallet call confirmation is unavailable");
    }
    return Object.freeze({ target: call.target, value: call.value, data: call.data });
  });
  let validityTimeRange;
  if (hasValidityTimeRange) {
    const range = confirmation.validityTimeRange;
    if (
      !exactKeys(range, [
        "validAfter",
        "validUntil",
        "validAfterUtc",
        "validUntilUtc",
        "inclusive",
      ]) ||
      typeof range.validAfter !== "string" ||
      !DECIMAL.test(range.validAfter) ||
      typeof range.validUntil !== "string" ||
      !DECIMAL.test(range.validUntil) ||
      BigInt(range.validAfter) >= BigInt(range.validUntil) ||
      range.validAfterUtc !== utcSeconds(range.validAfter) ||
      range.validUntilUtc !== utcSeconds(range.validUntil) ||
      range.inclusive !== true
    ) {
      throw new Error("wallet call confirmation is unavailable");
    }
    validityTimeRange = Object.freeze({
      validAfter: range.validAfter,
      validUntil: range.validUntil,
      validAfterUtc: range.validAfterUtc,
      validUntilUtc: range.validUntilUtc,
      inclusive: true,
    });
  }
  return Object.freeze({
    origin,
    account: confirmation.account,
    chainId: confirmation.chainId,
    calls: Object.freeze(calls),
    ...(confirmationExpiresAt === undefined ? {} : { confirmationExpiresAt }),
    ...(validityTimeRange === undefined ? {} : { validityTimeRange }),
  });
}

function storageKey(token) {
  return `${CONFIRMATION_PREFIX}${token}`;
}

/**
 * Opens one wallet-owned confirmation tab and waits for its exact decision.
 * Only public display data reaches session storage; the resolver and tab
 * binding stay in this worker instance, so a restarted worker cannot approve.
 */
export async function confirmWalletCalls(extension, origin, confirmation) {
  const token = crypto.randomUUID();
  const key = storageKey(token);
  const display = capturePublicConfirmation(origin, confirmation);
  if (
    display.confirmationExpiresAt !== undefined &&
    Date.now() >= display.confirmationExpiresAt * 1_000
  ) {
    return "rejected";
  }
  let resolveDecision;
  const decision = new Promise((resolve) => {
    resolveDecision = resolve;
  });
  const state = {
    tabId: null,
    resolve: resolveDecision,
    confirmationExpiresAt: display.confirmationExpiresAt ?? null,
    timeoutId: null,
  };
  pending.set(token, state);
  if (state.confirmationExpiresAt !== null) {
    state.timeoutId = setTimeout(
      () => {
        void settleWalletCallConfirmation(extension, token, "rejected");
      },
      Math.max(0, state.confirmationExpiresAt * 1_000 - Date.now()),
    );
  }
  try {
    await extension.storage.session.set({ [key]: display });
    if (pending.get(token) !== state) {
      await extension.storage.session.remove(key).catch(() => undefined);
      return await decision;
    }
    const tab = await extension.tabs.create({
      active: true,
      url: extension.runtime.getURL(`transaction-confirmation.html#${encodeURIComponent(token)}`),
    });
    if (!Number.isSafeInteger(tab?.id) || tab.id < 0) {
      throw new Error("wallet call confirmation tab is unavailable");
    }
    const retained = pending.get(token);
    if (retained !== undefined) retained.tabId = tab.id;
    return await decision;
  } catch (error) {
    pending.delete(token);
    if (state.timeoutId !== null) clearTimeout(state.timeoutId);
    await extension.storage.session.remove(key).catch(() => undefined);
    throw error;
  }
}

async function settleWalletCallConfirmation(extension, token, decision) {
  const state = pending.get(token);
  if (state === undefined) {
    await extension.storage.session.remove(storageKey(token)).catch(() => undefined);
    return false;
  }
  pending.delete(token);
  if (state.timeoutId !== null) clearTimeout(state.timeoutId);
  state.resolve(decision);
  await extension.storage.session.remove(storageKey(token)).catch(() => undefined);
  return true;
}

/** Settles an extension-page decision exactly once; `false` means orphaned. */
export async function decideWalletCallConfirmation(extension, token, decision) {
  if (!TOKEN.test(token) || (decision !== "approved" && decision !== "rejected")) {
    throw new Error("wallet call confirmation decision is invalid");
  }
  const state = pending.get(token);
  if (state === undefined) {
    await extension.storage.session.remove(storageKey(token)).catch(() => undefined);
    return false;
  }
  if (
    decision === "approved" &&
    state.confirmationExpiresAt !== null &&
    Date.now() >= state.confirmationExpiresAt * 1_000
  ) {
    await settleWalletCallConfirmation(extension, token, "rejected");
    return false;
  }
  return settleWalletCallConfirmation(extension, token, decision);
}

/** Closing the wallet-owned tab is an explicit rejection, never an approval. */
export async function rejectClosedWalletCallConfirmation(extension, tabId) {
  for (const [token, state] of pending) {
    if (state.tabId !== tabId) continue;
    return settleWalletCallConfirmation(extension, token, "rejected");
  }
  return false;
}

/** Validates and formats only the public model captured by the worker. */
export function formatWalletCallConfirmation(record) {
  const hasValidityTimeRange = hasOwnField(record, "validityTimeRange");
  const hasConfirmationDeadline = hasOwnField(record, "confirmationExpiresAt");
  const recordKeys = ["origin", "account", "chainId", "calls"];
  if (hasConfirmationDeadline) recordKeys.push("confirmationExpiresAt");
  if (hasValidityTimeRange) recordKeys.push("validityTimeRange");
  if (!exactKeys(record, recordKeys)) {
    throw new Error("wallet call confirmation is unavailable");
  }
  const exact = capturePublicConfirmation(record.origin, {
    account: record.account,
    chainId: record.chainId,
    calls: record.calls,
    ...(hasConfirmationDeadline ? { confirmationExpiresAt: record.confirmationExpiresAt } : {}),
    ...(hasValidityTimeRange ? { validityTimeRange: record.validityTimeRange } : {}),
  });
  const lines = [
    `origin   ${exact.origin}`,
    `account  ${exact.account}`,
    `chain    ${exact.chainId}`,
    `calls    ${exact.calls.length}`,
  ];
  if (exact.confirmationExpiresAt !== undefined) {
    lines.push(
      `approve before ${exact.confirmationExpiresAt} seconds (${utcSeconds(String(exact.confirmationExpiresAt))})`,
    );
  }
  if (exact.validityTimeRange !== undefined) {
    lines.push(
      "",
      "validity (inclusive)",
      `after    ${exact.validityTimeRange.validAfter} seconds (${exact.validityTimeRange.validAfterUtc})`,
      `until    ${exact.validityTimeRange.validUntil} seconds (${exact.validityTimeRange.validUntilUtc})`,
    );
  }
  exact.calls.forEach((call, index) => {
    lines.push(
      "",
      `call ${index + 1}`,
      `target   ${call.target}`,
      `value    ${call.value} wei`,
      `data     ${call.data}`,
    );
  });
  return lines.join("\n");
}
