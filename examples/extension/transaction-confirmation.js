/** Wallet-owned decision page for one worker-memory-bound call confirmation. */
import {
  formatWalletCallConfirmation,
  summarizeWalletCallConfirmation,
} from "./transaction-confirmation-presentation.js";

const confirmation = document.getElementById("confirmation");
const summary = document.getElementById("summary");
const result = document.getElementById("result");
const deadline = document.getElementById("deadline");
const approve = document.getElementById("approve");
const reject = document.getElementById("reject");
const token = decodeURIComponent(window.location.hash.slice(1));
const key = `wallet-call-confirmation:${token}`;
let expiryTimer = null;
let countdownTimer = null;

function stopTimers() {
  if (expiryTimer !== null) clearTimeout(expiryTimer);
  if (countdownTimer !== null) clearInterval(countdownTimer);
  expiryTimer = null;
  countdownTimer = null;
}

function disable() {
  approve.disabled = true;
  reject.disabled = true;
}

function unavailable(text) {
  stopTimers();
  disable();
  deadline.textContent = "";
  result.dataset.tone = "danger";
  result.textContent = text;
}

function expired() {
  unavailable("This confirmation expired and was rejected. The site can send the request again.");
}

async function decide(decision) {
  disable();
  stopTimers();
  const button = decision === "approved" ? approve : reject;
  button.setAttribute("aria-busy", "true");
  button.textContent = decision === "approved" ? "Sending…" : "Rejecting…";
  try {
    const response = await chrome.runtime.sendMessage({
      type: "transaction-confirmation",
      token,
      decision,
    });
    if (response?.ok !== true) throw new Error("wallet call confirmation is unavailable");
    window.close();
  } catch {
    button.removeAttribute("aria-busy");
    unavailable(
      "This request is no longer waiting for a decision, so nothing was sent. Close this tab; the site can send the request again.",
    );
  }
}

function showCountdown(expiresAtMs) {
  const tick = () => {
    const seconds = Math.max(0, Math.ceil((expiresAtMs - Date.now()) / 1_000));
    const minutes = Math.floor(seconds / 60);
    deadline.textContent = `Expires in ${minutes}:${String(seconds % 60).padStart(2, "0")}`;
  };
  tick();
  countdownTimer = setInterval(tick, 1_000);
}

function renderSummary(facts) {
  const calls = facts.calls === 1 ? "1 call" : `${facts.calls} calls`;
  const value = facts.totalValue === "0" ? "no native value" : `${facts.totalValue} wei in total`;
  summary.replaceChildren(
    document.createElement("strong"),
    ` wants to send ${calls} from your account on chain ${facts.chain}, moving ${value}. Check every call below; closing this tab rejects the request.`,
  );
  summary.firstChild.textContent = facts.origin;
}

try {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(token)) {
    throw new Error("wallet call confirmation is unavailable");
  }
  const stored = await chrome.storage.session.get(key);
  const record = stored[key];
  confirmation.textContent = formatWalletCallConfirmation(record);
  renderSummary(summarizeWalletCallConfirmation(record));
  const expiresAt = record.confirmationExpiresAt;
  const remaining = expiresAt === undefined ? null : Math.max(0, expiresAt * 1_000 - Date.now());
  if (remaining === 0) {
    expired();
  } else {
    approve.disabled = false;
    reject.disabled = false;
    if (remaining !== null) {
      showCountdown(expiresAt * 1_000);
      expiryTimer = setTimeout(expired, remaining);
    }
  }
  approve.addEventListener("click", () => void decide("approved"));
  reject.addEventListener("click", () => void decide("rejected"));
} catch {
  summary.textContent = "";
  confirmation.textContent = "wallet call confirmation is unavailable";
  confirmation.hidden = true;
  document.getElementById("exact-heading").hidden = true;
  unavailable(
    "This confirmation cannot be shown. It may already be decided or expired. Close this tab; nothing was sent.",
  );
}
