/** One-use, read-only presentation for wallet_showCallsStatus. */
import { formatWalletCallStatus } from "./status-presentation.js";

const output = document.getElementById("status");
const badge = document.getElementById("badge");
const detail = document.getElementById("detail");
const token = decodeURIComponent(window.location.hash.slice(1));
const key = `wallet-call-status:${token}`;

// Keyed by the EIP-5792 status code the formatter has already validated.
const HEADLINES = {
  100: [
    "Pending",
    "warn",
    "The calls were submitted and are waiting for inclusion. A missing receipt does not mean they failed.",
  ],
  200: ["Confirmed", "ok", "The calls were included onchain."],
  400: ["Failed", "danger", "The calls failed before inclusion. Nothing was executed onchain."],
  500: ["Reverted", "danger", "The calls were included but reverted onchain."],
};

try {
  if (!/^[0-9a-f-]{36}$/iu.test(token)) throw new Error("wallet call status is unavailable");
  const stored = await chrome.storage.session.get(key);
  output.textContent = formatWalletCallStatus(stored[key]);
  const [label, tone, text] = HEADLINES[stored[key].status.status];
  badge.textContent = label;
  badge.dataset.tone = tone;
  badge.hidden = false;
  detail.textContent = `Requested by ${stored[key].origin}. ${text}`;
} catch (error) {
  output.textContent = error instanceof Error ? error.message : "wallet call status is unavailable";
  detail.textContent =
    "This view is shown once. Ask the site to show the call status again to see the latest result.";
} finally {
  await chrome.storage.session.remove(key).catch(() => undefined);
}
