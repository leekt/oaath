/** Wallet-owned decision page for one worker-memory-bound call confirmation. */
import { formatWalletCallConfirmation } from "./transaction-confirmation-presentation.js";

const confirmation = document.getElementById("confirmation");
const result = document.getElementById("result");
const approve = document.getElementById("approve");
const reject = document.getElementById("reject");
const token = decodeURIComponent(window.location.hash.slice(1));
const key = `wallet-call-confirmation:${token}`;

function disable() {
  approve.disabled = true;
  reject.disabled = true;
}

async function decide(decision) {
  disable();
  try {
    const response = await chrome.runtime.sendMessage({
      type: "transaction-confirmation",
      token,
      decision,
    });
    if (response?.ok !== true) throw new Error("wallet call confirmation is unavailable");
    window.close();
  } catch {
    result.textContent = "wallet call confirmation is unavailable";
  }
}

try {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(token)) {
    throw new Error("wallet call confirmation is unavailable");
  }
  const stored = await chrome.storage.session.get(key);
  confirmation.textContent = formatWalletCallConfirmation(stored[key]);
  approve.disabled = false;
  reject.disabled = false;
  approve.addEventListener("click", () => void decide("approved"));
  reject.addEventListener("click", () => void decide("rejected"));
} catch (error) {
  confirmation.textContent =
    error instanceof Error ? error.message : "wallet call confirmation is unavailable";
  disable();
}
