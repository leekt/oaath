/**
 * Pairing UI for the active tab's origin: request one scoped Grant, show its
 * state, revoke it. The owner still approves on their own device through the
 * service's authorization flow — this popup never sees owner authority.
 *
 * @author taek <leekt216@gmail.com>
 */
const $ = (id) => document.getElementById(id);
const DEFAULTS = Object.freeze({ url: "http://127.0.0.1:8787", chain: 421_614 });

const STATES = Object.freeze({
  unpaired: {
    title: "Not paired",
    badge: "No permission",
    tone: "neutral",
    detail: "This site cannot send calls through OAAth until the owner approves a permission.",
  },
  requested: {
    title: "Waiting for the owner",
    badge: "Pending",
    tone: "warn",
    detail: "Approve the request on the owner device. This popup updates when it is decided.",
  },
  active: {
    title: "Paired",
    badge: "Active",
    tone: "ok",
    detail:
      "This site can send calls inside the approved scope. Each send still asks you to confirm.",
  },
  revoking: {
    title: "Revocation in progress",
    badge: "Revoking",
    tone: "warn",
    detail:
      "The site can no longer send calls. The owner must remove the permission on each chain; check again after they do.",
  },
  revoked: {
    title: "Revoked",
    badge: "Revoked",
    tone: "neutral",
    detail: "The permission is removed on every chain. You can request a new one.",
  },
  expired: {
    title: "Expired",
    badge: "Expired",
    tone: "neutral",
    detail: "The permission reached its expiry. You can request a new one.",
  },
  rejected: {
    title: "Rejected",
    badge: "Rejected",
    tone: "danger",
    detail: "The owner rejected the last request. You can request a new one.",
  },
});

let origin = null;
let busy = false;
let pollTimer = null;
let currentState = null;

function setMessage(text, tone = "neutral") {
  const box = $("status");
  box.hidden = text === "";
  box.textContent = text;
  box.dataset.tone = tone;
}

function setBusy(button, label) {
  busy = label !== null;
  for (const control of document.querySelectorAll("button")) control.disabled = busy;
  if (label === null) {
    button.removeAttribute("aria-busy");
    if (button.dataset.label) button.textContent = button.dataset.label;
    return;
  }
  button.dataset.label ??= button.textContent;
  button.setAttribute("aria-busy", "true");
  button.textContent = label;
}

async function activeOrigin() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:\/\//u.test(tab.url)) return null;
  return new URL(tab.url).origin;
}

async function command(message) {
  const response = await chrome.runtime.sendMessage({ type: "popup", ...message });
  if (!response?.ok) throw new Error(response?.error?.message ?? "the extension did not answer");
  return response.result;
}

function formatExpiry(seconds) {
  const date = new Date(seconds * 1_000);
  const minutes = Math.round((date.getTime() - Date.now()) / 60_000);
  const relative =
    minutes <= 0 ? "now" : minutes < 90 ? `in ${minutes} min` : `in ${Math.round(minutes / 60)} h`;
  return `${date.toLocaleString()} (${relative})`;
}

function renderFacts(status) {
  const facts = $("facts");
  const rows = [];
  if (status.account) rows.push(["Account", status.account]);
  if (status.expiresAt) rows.push(["Expires", formatExpiry(status.expiresAt)]);
  rows.push(["Service", status.url], ["Chain", String(status.chain)]);
  facts.replaceChildren(
    ...rows.flatMap(([label, value]) => {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value;
      return [dt, dd];
    }),
  );
  facts.hidden = false;
}

function renderState(state) {
  currentState = state;
  const view = STATES[state] ?? {
    title: "Unknown state",
    badge: state,
    tone: "neutral",
    detail: "The extension reported a state this popup does not recognize.",
  };
  $("state-title").textContent = view.title;
  $("state-badge").textContent = view.badge;
  $("state-badge").dataset.tone = view.tone;
  $("state-detail").textContent = view.detail;
  const canRequest = !["active", "revoking", "requested"].includes(state);
  $("pair-section").hidden = !canRequest;
  $("revoke-section").hidden = state !== "active" && state !== "revoking";
  $("revoke").textContent = state === "revoking" ? "Check revocation" : "Revoke permission";
  $("revoke").dataset.label = $("revoke").textContent;
  $("revoke").className = state === "revoking" ? "" : "danger";
  hideRevokeConfirm();
  // A request pending on another popup instance resolves in the worker; poll
  // until it settles so reopening the popup shows the owner's decision.
  if (pollTimer !== null) clearTimeout(pollTimer);
  pollTimer = state === "requested" ? setTimeout(refresh, 2_000) : null;
}

async function refresh() {
  if (origin === null) {
    $("origin").textContent = "No web page";
    $("state-title").textContent = "Open a web page";
    $("state-badge").textContent = "Unavailable";
    $("state-detail").textContent =
      "OAAth pairs one site at a time. Switch to an http or https tab, then reopen this popup.";
    $("pair-section").hidden = true;
    $("revoke-section").hidden = true;
    return;
  }
  try {
    const status = await command({ command: "status", origin });
    renderState(status.state);
    renderFacts(status);
  } catch (error) {
    $("state-title").textContent = "Status unavailable";
    $("state-badge").textContent = "Error";
    $("state-badge").dataset.tone = "danger";
    $("state-detail").textContent = "Check the service URL and that the service is running.";
    setMessage(error.message, "danger");
  }
}

/* Validation: name the problem next to the field before sending anything. */
const RULES = {
  target: [/^0x[0-9a-fA-F]{40}$/u, "Enter a 20-byte address: 0x followed by 40 hex digits."],
  selector: [/^0x[0-9a-fA-F]{8}$/u, "Enter 0x followed by 8 hex digits."],
  valueLimit: [/^(?:0|[1-9][0-9]*)$/u, "Whole wei, 0 or more."],
  expiresIn: [/^[1-9][0-9]*$/u, "Whole seconds, at least 1."],
  operationLimit: [/^[1-9][0-9]*$/u, "Whole number, at least 1."],
  url: [/^https?:\/\/[^\s/]+/u, "Enter an http:// or https:// URL."],
  chain: [/^[1-9][0-9]*$/u, "Enter a positive chain ID."],
};

function validate(ids, { allowEmpty = false } = {}) {
  let first = null;
  for (const id of ids) {
    const input = $(id);
    const value = input.value.trim();
    const [pattern, message] = RULES[id];
    const ok = (allowEmpty && value === "") || pattern.test(value);
    input.setAttribute("aria-invalid", String(!ok));
    const error = $(`${id}-error`);
    error.textContent = ok ? "" : message;
    error.hidden = ok;
    if (ok) input.removeAttribute("aria-describedby");
    else input.setAttribute("aria-describedby", error.id);
    if (!ok && first === null) first = input;
  }
  first?.focus();
  return first === null;
}

$("pair-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || origin === null) return;
  if (!validate(["target", "selector", "valueLimit", "expiresIn", "operationLimit"])) return;
  const button = $("pair");
  setBusy(button, "Waiting for the owner…");
  setMessage("");
  renderState("requested");
  try {
    const result = await command({
      command: "pair",
      origin,
      scope: {
        target: $("target").value.trim(),
        selector: $("selector").value.trim().toLowerCase(),
        valueLimit: $("valueLimit").value.trim(),
        expiresIn: Number($("expiresIn").value.trim()),
        perChainOperationLimit: Number($("operationLimit").value.trim()),
      },
    });
    setMessage(
      result.state === "active" ? "Permission approved." : `Request ended: ${result.state}.`,
      result.state === "active" ? "ok" : "neutral",
    );
  } catch (error) {
    setMessage(`Permission request failed: ${error.message}`, "danger");
  } finally {
    setBusy(button, null);
  }
  await refresh();
});

function hideRevokeConfirm() {
  $("revoke-confirm").hidden = true;
  $("revoke-actions").hidden = false;
}

async function runRevoke(button) {
  setBusy(button, "Revoking…");
  setMessage("");
  try {
    const result = await command({ command: "revoke", origin });
    setMessage(
      result.state === "revoked"
        ? "Permission revoked on every chain."
        : "The site can no longer send calls. Removal is waiting for the owner on each chain.",
      result.state === "revoked" ? "ok" : "neutral",
    );
  } catch (error) {
    setMessage(`Revoke failed: ${error.message}`, "danger");
  } finally {
    setBusy(button, null);
  }
  await refresh();
}

$("revoke").addEventListener("click", () => {
  if (busy || origin === null) return;
  // Checking an in-progress revocation is safe to repeat; starting one asks first.
  if (currentState === "revoking") {
    void runRevoke($("revoke"));
    return;
  }
  $("revoke-actions").hidden = true;
  $("revoke-confirm").hidden = false;
  $("revoke-cancel").focus();
});
$("revoke-cancel").addEventListener("click", () => {
  hideRevokeConfirm();
  $("revoke").focus();
});
$("revoke-confirm-button").addEventListener("click", () => {
  if (busy || origin === null) return;
  void runRevoke($("revoke-confirm-button"));
});

$("service-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || !validate(["url", "chain"], { allowEmpty: true })) return;
  const url = $("url").value.trim();
  const chain = $("chain").value.trim();
  // An empty field restores its default instead of silently keeping the old value.
  await chrome.storage.local.set({
    url: url === "" ? DEFAULTS.url : url,
    chain: chain === "" ? DEFAULTS.chain : Number(chain),
  });
  setMessage("Service saved.", "ok");
  await refresh();
});

chrome.storage.local.get({ url: "", chain: "" }).then((stored) => {
  if (stored.url) $("url").value = stored.url;
  if (stored.chain) $("chain").value = String(stored.chain);
});

activeOrigin().then(
  (value) => {
    origin = value;
    if (value !== null) {
      $("origin").textContent = value;
      $("origin").title = value;
    }
    return refresh();
  },
  () => refresh(),
);
