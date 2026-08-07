/** One-use, read-only presentation for wallet_showCallsStatus. */
import { formatWalletCallStatus } from "./status-presentation.js";

const output = document.getElementById("status");
const token = decodeURIComponent(window.location.hash.slice(1));
const key = `wallet-call-status:${token}`;

try {
  if (!/^[0-9a-f-]{36}$/iu.test(token)) throw new Error("wallet call status is unavailable");
  const stored = await chrome.storage.session.get(key);
  output.textContent = formatWalletCallStatus(stored[key]);
} catch (error) {
  output.textContent = error instanceof Error ? error.message : "wallet call status is unavailable";
} finally {
  await chrome.storage.session.remove(key).catch(() => undefined);
}
