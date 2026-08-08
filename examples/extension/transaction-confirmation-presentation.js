/** One-use wallet-owned presentation for an exact `wallet_sendCalls` execution. */

const CONFIRMATION_PREFIX = "wallet-call-confirmation:";
const TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const ORIGIN = /^https?:\/\//u;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const CHAIN_ID = /^0x[1-9a-f][0-9a-f]*$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;

/** token -> the worker-memory-only decision authority for one open tab. */
const pending = new Map();

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function capturePublicConfirmation(origin, confirmation) {
  if (
    typeof origin !== "string" ||
    !ORIGIN.test(origin) ||
    !exactKeys(confirmation, ["account", "chainId", "calls"]) ||
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
  return Object.freeze({
    origin,
    account: confirmation.account,
    chainId: confirmation.chainId,
    calls: Object.freeze(calls),
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
  let resolveDecision;
  const decision = new Promise((resolve) => {
    resolveDecision = resolve;
  });
  const state = { tabId: null, resolve: resolveDecision };
  pending.set(token, state);
  try {
    await extension.storage.session.set({ [key]: display });
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
    await extension.storage.session.remove(key).catch(() => undefined);
    throw error;
  }
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
  pending.delete(token);
  state.resolve(decision);
  await extension.storage.session.remove(storageKey(token)).catch(() => undefined);
  return true;
}

/** Closing the wallet-owned tab is an explicit rejection, never an approval. */
export async function rejectClosedWalletCallConfirmation(extension, tabId) {
  for (const [token, state] of pending) {
    if (state.tabId !== tabId) continue;
    pending.delete(token);
    state.resolve("rejected");
    await extension.storage.session.remove(storageKey(token)).catch(() => undefined);
    return true;
  }
  return false;
}

/** Validates and formats only the public model captured by the worker. */
export function formatWalletCallConfirmation(record) {
  if (!exactKeys(record, ["origin", "account", "chainId", "calls"])) {
    throw new Error("wallet call confirmation is unavailable");
  }
  const exact = capturePublicConfirmation(record.origin, {
    account: record.account,
    chainId: record.chainId,
    calls: record.calls,
  });
  const lines = [
    `origin   ${exact.origin}`,
    `account  ${exact.account}`,
    `chain    ${exact.chainId}`,
    `calls    ${exact.calls.length}`,
  ];
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
