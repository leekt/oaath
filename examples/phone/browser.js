import { createOAAth } from "@oaath/sdk";

const $ = (id) => document.getElementById(id);
const status = $("status");
const account = $("account");
const pairingPanel = $("pairing");
const pairingQr = $("pairing-qr");
const pairingLink = $("pairing-link");
const activity = $("activity");
const activityTitle = $("activity-title");
const activityDetail = $("activity-detail");
const statusLines = status.textContent.trim() ? [status.textContent.trim()] : [];
const say = (text) => {
  statusLines.push(`[${new Date().toLocaleTimeString()}] ${text}`);
  if (statusLines.length > 80) statusLines.splice(0, statusLines.length - 80);
  status.textContent = statusLines.join("\n\n");
  status.scrollTop = status.scrollHeight;
};
let activityGeneration = 0;
const buttonActivities = new WeakMap();
const beginActivity = (button, title, detail) => {
  const token = ++activityGeneration;
  buttonActivities.set(button, token);
  button.disabled = true;
  if (typeof button.setAttribute === "function") button.setAttribute("aria-busy", "true");
  else button.ariaBusy = "true";
  if (activity) activity.hidden = false;
  if (activityTitle) activityTitle.textContent = title;
  if (activityDetail) activityDetail.textContent = detail;
  say(`${title}\n${detail}`);
  return token;
};
const updateActivity = (token, title, detail) => {
  if (token !== activityGeneration) return;
  if (activityTitle) activityTitle.textContent = title;
  if (activityDetail) activityDetail.textContent = detail;
};
const finishActivity = (button, token) => {
  if (buttonActivities.get(button) !== token) return;
  buttonActivities.delete(button);
  button.disabled = false;
  if (typeof button.removeAttribute === "function") button.removeAttribute("aria-busy");
  else button.ariaBusy = "false";
  if (token === activityGeneration && activity) activity.hidden = true;
  render();
};
/** A failed demo route carries only its structured `error.code`. */
class DemoRouteError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
const json = async (path, options) => {
  const response = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json" },
  });
  const body = await response.json();
  if (!response.ok) throw new DemoRouteError(body.error?.code ?? `http_${response.status}`);
  return body;
};

// Page state. Every value is derived from a server read or an SDK handle;
// the page renders it but never treats it as authority.
const page = {
  /** null until the first /demo/account read answers. */
  paired: null,
  chains: [],
  connected: false,
  busy: false,
};

let pairingExpiryTimer = null;
let pairingStatusTimer = null;
let pairingRequestGeneration = 0;
const clearPairingSecret = () => {
  if (pairingExpiryTimer !== null) clearTimeout(pairingExpiryTimer);
  if (pairingStatusTimer !== null) clearInterval(pairingStatusTimer);
  pairingExpiryTimer = null;
  pairingStatusTimer = null;
  pairingQr.removeAttribute("src");
  pairingLink.value = "";
  pairingPanel.hidden = true;
};
const exactPairingSecret = (value) => {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== "expiresAt,pairingLink,qrDataUrl,version" ||
    value.version !== "oaath.demo-pairing-secret/v1" ||
    typeof value.pairingLink !== "string" ||
    !value.pairingLink.startsWith("oaath-demo://pair?") ||
    typeof value.qrDataUrl !== "string" ||
    !value.qrDataUrl.startsWith("data:image/png;base64,") ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= Date.now()
  )
    throw new Error("pairing_secret_invalid");
  return value;
};
$("pair").onclick = async () => {
  const button = $("pair");
  const activityToken = beginActivity(
    button,
    "Creating a one-time pairing code",
    "The code is available only on this Mac's loopback page.",
  );
  const generation = ++pairingRequestGeneration;
  clearPairingSecret();
  try {
    const secret = exactPairingSecret(
      await json("/demo/pairing-secret", { method: "POST", body: "{}" }),
    );
    if (generation !== pairingRequestGeneration) {
      finishActivity(button, activityToken);
      return;
    }
    pairingQr.src = secret.qrDataUrl;
    pairingLink.value = secret.pairingLink;
    pairingPanel.hidden = false;
    updateActivity(
      activityToken,
      "Waiting for your phone",
      "Scan the QR code, then tap Pair in the app.",
    );
    say("Pairing code shown on this page only. Scan or copy it before it expires.");
    pairingExpiryTimer = setTimeout(
      () => {
        if (generation !== pairingRequestGeneration) return;
        pairingRequestGeneration += 1;
        clearPairingSecret();
        finishActivity(button, activityToken);
        say("The pairing code expired. Restart the example for a fresh code.");
      },
      Math.min(secret.expiresAt - Date.now(), 2_147_483_647),
    );
    pairingStatusTimer = setInterval(async () => {
      if (generation !== pairingRequestGeneration) return;
      try {
        const response = await fetch("/demo/account");
        if (!response.ok || generation !== pairingRequestGeneration) return;
        pairingRequestGeneration += 1;
        clearPairingSecret();
        page.paired = true;
        finishActivity(button, activityToken);
        say("Phone paired. The pairing code is now hidden. Next: connect the account.");
        refreshAccount().catch(() => {});
      } catch {
        // A bounded status check has no authority and reveals no diagnostics.
      }
    }, 1_000);
  } catch (error) {
    if (generation !== pairingRequestGeneration) {
      finishActivity(button, activityToken);
      return;
    }
    pairingRequestGeneration += 1;
    clearPairingSecret();
    finishActivity(button, activityToken);
    if (error?.code === "pairing_secret_unavailable" && page.paired) {
      say("This service already has a paired phone. Continue with Connect account.");
      return;
    }
    const port = globalThis.location?.port ? `:${globalThis.location.port}` : "";
    say(
      error?.code === "pairing_secret_unavailable"
        ? "The pairing code was already used or has expired. Restart the example for a fresh code."
        : `Pairing code unavailable. Open http://127.0.0.1${port}/ on this Mac; other addresses can't show it.`,
    );
  }
};
const copyLink = document.querySelector?.("[data-copy-link]");
if (copyLink) {
  copyLink.onclick = async () => {
    try {
      await navigator.clipboard.writeText(pairingLink.value);
      copyLink.textContent = "Copied";
    } catch {
      pairingLink.select?.();
      copyLink.textContent = "Press ⌘C to copy";
    }
    setTimeout(() => {
      copyLink.textContent = "Copy link";
    }, 2_000);
  };
}

// The SDK owns session custody and operation state in IndexedDB. The page saves
// only the exact returned handle identity, never a session key or signature.
const operationKey = "oaath.phone-demo-operation/v1";
const chainChoice = $("chain");
const target = `0x${"71".repeat(20)}`;
let client;
let connection;
let grant;
const clientFetch = (request) => {
  const headers = new Headers(request.headers);
  headers.set("authorization", "Bearer demo-client-token");
  return fetch(new Request(request, { headers }));
};
/** Terminal grants authorize nothing; the owner may request a new permission. */
const grantIsTerminal = (value) =>
  value === undefined ||
  value === null ||
  value.state === "revoked" ||
  value.state === "expired" ||
  value.state === "rejected";

async function refreshAccount() {
  const paired = await json("/demo/account");
  page.paired = true;
  if (!Array.isArray(paired.chains) || paired.chains.length === 0) {
    throw new DemoRouteError("account_chains_unavailable");
  }
  page.chains = paired.chains;
  account.textContent = paired.account;
  const selected = chainChoice.value;
  if (typeof chainChoice.replaceChildren === "function") {
    chainChoice.replaceChildren(
      ...paired.chains.map(({ chainId, name }) => {
        const option = document.createElement("option");
        option.value = String(chainId);
        option.textContent = name;
        return option;
      }),
    );
  }
  chainChoice.value = paired.chains.some(({ chainId }) => String(chainId) === selected)
    ? selected
    : String(paired.chains[0].chainId);
  render();
  return paired;
}
async function connectAccount() {
  if (!connection) {
    client ??= createOAAth({
      approvals: { kind: "service", url: location.origin, fetch: clientFetch },
    });
    connection = await client.connect();
    grant = await connection.resume();
  }
  page.connected = true;
  await refreshAccount();
  return connection;
}
async function currentGrant() {
  await connectAccount();
  if (!grant) throw new DemoRouteError("grant_missing");
  return grant;
}
function saveOperation(id, chain) {
  localStorage.setItem(operationKey, JSON.stringify({ version: operationKey, chain, id }));
}
function savedOperation() {
  const text = localStorage.getItem(operationKey);
  if (text === null) return null;
  const value = JSON.parse(text);
  if (
    value?.version !== operationKey ||
    !Number.isSafeInteger(value.chain) ||
    value.chain < 1 ||
    typeof value.id !== "string" ||
    !/^0x[0-9a-f]{64}$/.test(value.id) ||
    Object.keys(value).sort().join(",") !== "chain,id,version"
  ) {
    throw new DemoRouteError("saved_job_unreadable");
  }
  return { chain: value.chain, id: value.id };
}
const readSaved = () => {
  try {
    return { saved: savedOperation(), unreadable: false };
  } catch {
    return { saved: null, unreadable: true };
  }
};

const failureText = {
  phone_not_paired: "Pair your phone first.",
  grant_missing: "Request a permission first.",
  saved_job_unreadable: "The saved job record can't be read. It was kept, not replaced.",
  oaath_client_permission_rejected: "The phone rejected the permission request.",
  oaath_client_decision_unavailable:
    "No decision arrived from the phone. The request may have expired; request it again.",
  oaath_client_grant_inactive: "The permission isn't active, so no job was sent.",
  oaath_client_scope_denied: "That job is outside the approved permission, so it wasn't sent.",
  oaath_client_issuer_unavailable: "The service can't be reached right now. Try again.",
  oaath_client_issuer_rejected: "The service refused the request.",
  oaath_client_observation_unavailable:
    "The chain couldn't be read. The job is kept; check it again.",
  oaath_client_route_unavailable: "No submission route is available for that chain right now.",
  oaath_client_submission_uncertain:
    "The job's submission couldn't be confirmed. It is kept and will not be sent again; check it.",
  oaath_client_state_conflict: "That action conflicts with the current state of this permission.",
  oaath_client_store_unavailable: "Browser storage is unavailable. Allow site data and reload.",
};
const describeFailure = (error) => {
  const code = typeof error?.code === "string" ? error.code : "action_unavailable";
  return `${failureText[code] ?? "The action couldn't finish."} (${code})`;
};

const grantText = (value) => {
  if (!value) return "None";
  switch (value.state) {
    case "active":
      return "Active: up to three jobs per chain, 5 wei per call";
    case "revoking":
      return "Revoking: approve each chain's removal on the phone, then check again";
    case "revoked":
      return "Revoked on every configured chain";
    case "expired":
      return "Expired";
    case "rejected":
      return "Rejected on the phone";
    default:
      return value.state;
  }
};
const setText = (id, text) => {
  const node = $(id);
  if (node) node.textContent = text;
};
const setStep = (id, state, tag) => {
  const node = $(id);
  if (!node || typeof node.setAttribute !== "function") return;
  node.setAttribute("data-state", state);
  const label = node.querySelector?.("[data-tag]");
  if (label) {
    label.hidden = !tag;
    label.textContent = tag ?? "";
    label.className = state === "done" ? "tag done" : "tag";
  }
};
const shortId = (id) => `${id.slice(0, 10)}…${id.slice(-6)}`;

/** Enables only the next valid actions and describes the current state. */
function render() {
  const { saved, unreadable } = readSaved();
  const active = grant?.state === "active";
  const revoking = grant?.state === "revoking";
  const terminal = grantIsTerminal(grant);
  const paired = page.paired === true;
  const needsObservation = saved !== null || unreadable;
  const enable = (id, on) => {
    const node = $(id);
    if (!node || buttonActivities.has(node)) return;
    node.disabled = page.busy || !on;
  };
  enable("pair", page.paired === false);
  enable("unlock", paired && !page.connected);
  enable("permission", paired && terminal && !needsObservation);
  enable("session", paired && active && !saved && !unreadable);
  enable("observe", paired && (saved !== null || unreadable));
  enable("revoke", paired && (active || revoking));
  const recovery = $("permission-recovery");
  if (recovery) {
    recovery.hidden = !paired || !terminal || !needsObservation;
    recovery.textContent = unreadable
      ? "The saved job record can't be read. Its permission is kept so the job isn't lost."
      : "Check the saved job before requesting another permission. Its current permission is still needed to find the result.";
  }
  if (chainChoice) chainChoice.disabled = page.busy || !active || saved !== null;
  const chainField = $("chain-field");
  if (chainField) chainField.hidden = page.chains.length === 0;
  const revoke = $("revoke");
  if (revoke && !buttonActivities.has(revoke)) {
    revoke.textContent = revoking ? "Check revocation" : "Revoke permission";
  }

  setStep("step-pair", paired ? "done" : "next", paired ? "Paired" : null);
  setStep(
    "step-connect",
    page.connected ? "done" : paired ? "next" : "locked",
    page.connected ? "Connected" : null,
  );
  setStep(
    "step-permission",
    active || revoking
      ? "done"
      : page.connected && terminal && !needsObservation
        ? "next"
        : paired && needsObservation
          ? "available"
          : "locked",
    grant ? grantText(grant).split(":")[0] : null,
  );
  setStep(
    "step-job",
    active && !saved ? "next" : saved ? "available" : "locked",
    saved ? "Saved job waiting" : null,
  );
  setStep("step-observe", saved || unreadable ? "next" : "locked", null);
  setStep(
    "step-revoke",
    grant?.state === "revoked" ? "done" : revoking ? "next" : active ? "available" : "locked",
    grant?.state === "revoked" ? "Revoked" : revoking ? "Pending" : null,
  );

  setText("fact-phone", page.paired === null ? "Checking…" : paired ? "Paired" : "Not paired yet");
  setText("fact-permission", page.connected ? grantText(grant) : "Connect to see it");
  setText(
    "fact-job",
    unreadable
      ? "Saved job record unreadable"
      : saved
        ? `Chain ${saved.chain} · ${shortId(saved.id)}`
        : "None",
  );
  if (page.chains.length > 0) {
    setText(
      "network",
      `Local Anvil · chains ${page.chains.map(({ chainId }) => chainId).join(", ")}`,
    );
  }
}

const actions = {
  unlock: [
    "Connecting the account",
    async () => {
      await connectAccount();
      say(
        grant
          ? `Connected. Permission restored: ${grantText(grant)}.`
          : "Connected. Next: request permission.",
      );
    },
  ],
  permission: [
    "Waiting for approval on your phone",
    async (token) => {
      await connectAccount();
      const { saved, unreadable } = readSaved();
      if (unreadable) throw new DemoRouteError("saved_job_unreadable");
      if (saved) {
        say(
          "Check the saved job before requesting another permission. Its permission is kept for recovery.",
        );
        return;
      }
      if (!grantIsTerminal(grant)) {
        say(`A permission already exists: ${grantText(grant)}.`);
        return;
      }
      updateActivity(
        token,
        "Waiting for approval on your phone",
        "Open Requests in the iOS app, review the request, and tap Approve.",
      );
      say("Review the request in the phone's Requests tab and approve it.");
      const matchPanel = $("permission-match");
      const matchCodeText = $("permission-match-code");
      try {
        grant = await connection.requestPermission({
          chainScope: "all",
          permissions: [{ calls: [{ target, selectors: ["0x12345678"], valueLimit: "5" }] }],
          expiresIn: 1800,
          perChainOperationLimit: 3,
          onPending: ({ matchCode }) => {
            matchCodeText.textContent = `${matchCode.slice(0, 4)} ${matchCode.slice(4)}`;
            matchPanel.hidden = false;
          },
        });
      } finally {
        matchPanel.hidden = true;
        matchCodeText.textContent = "";
      }
      say("Permission active: up to three jobs per configured chain for 30 minutes.");
    },
  ],
  session: [
    "Running a new job",
    async () => {
      const current = await currentGrant();
      // A saved unresolved job is an observation action, never another send.
      if (savedOperation()) {
        say("Check the saved job before starting another.");
        return;
      }
      const operation = await current.sendCalls({
        chain: Number(chainChoice.value),
        calls: [{ target, value: "5", data: "0x12345678" }],
      });
      saveOperation(operation.id, operation.chainId);
      say(
        `Job submitted on chain ${operation.chainId}. Next: check it.\nOperation: ${operation.id}`,
      );
    },
  ],
  revoke: [
    "Revoking the permission",
    async (token) => {
      const current = await currentGrant();
      updateActivity(
        token,
        "Revoking the permission",
        "Approve each chain's removal in the iOS app. This check waits for chain evidence.",
      );
      await current.revoke();
      say(
        current.state === "revoked"
          ? "Permission revoked on every configured chain. Saved jobs can still be checked."
          : "Revocation pending. Approve each request in the phone's Requests tab, then choose Check revocation.",
      );
    },
  ],
  observe: [
    "Checking the saved job",
    async () => {
      const saved = savedOperation();
      if (!saved) {
        say("There is no saved job to check.");
        return;
      }
      const current = await currentGrant();
      const operation = await current.getOperation(saved);
      if (!operation) {
        say("The saved job isn't available yet. Its identity is kept; check again.");
        return;
      }
      const outcome = await operation.observe();
      if (outcome.status === "finalized") {
        localStorage.removeItem(operationKey);
        say(
          `Job finalized: ${outcome.outcome}.\nOperation: ${operation.id}\nTransaction: ${outcome.transactionHash}`,
        );
      } else if (outcome.status === "superseded") {
        localStorage.removeItem(operationKey);
        say(`Job superseded. Operation: ${operation.id}`);
      } else
        say(`Job is still ${outcome.status}. Check again shortly.\nOperation: ${operation.id}`);
    },
  ],
};
for (const [id, [title, action]] of Object.entries(actions)) {
  $(id).onclick = async () => {
    if (page.busy) return;
    page.busy = true;
    render();
    const token = beginActivity($(id), title, "Working on it.");
    try {
      await action(token);
    } catch (error) {
      say(describeFailure(error));
    } finally {
      page.busy = false;
      finishActivity($(id), token);
      render();
    }
  };
}

// Recover what this page can prove after a reload: pairing from the service,
// the Grant from the SDK, and the saved job pointer from localStorage.
(async () => {
  try {
    await refreshAccount();
  } catch {
    page.paired = false;
    render();
    return;
  }
  if (typeof location?.origin !== "string" || page.busy) return;
  page.busy = true;
  render();
  try {
    await connectAccount();
    say(
      grant
        ? `Recovered this session. Permission: ${grantText(grant)}.`
        : "Phone paired. Account connected. Next: request permission.",
    );
  } catch (error) {
    say(`Couldn't reconnect automatically. ${describeFailure(error)}`);
  } finally {
    page.busy = false;
    render();
  }
})();
