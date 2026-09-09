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
};
const json = async (path, options) => {
  const response = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json" },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error?.code ?? `HTTP ${response.status}`);
  return body;
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
    "Creating one-time pairing link",
    "The secret is requested only from this Mac loopback page.",
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
      "Waiting for iPhone pairing",
      "Scan the QR code and confirm pairing in the app.",
    );
    say("Pairing secret shown only in this loopback page. Scan or copy it before it expires.");
    pairingExpiryTimer = setTimeout(
      () => {
        if (generation !== pairingRequestGeneration) return;
        pairingRequestGeneration += 1;
        clearPairingSecret();
        finishActivity(button, activityToken);
        say("The one-time pairing secret expired. Restart the example for a fresh code.");
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
        finishActivity(button, activityToken);
        say("Phone paired. The one-time pairing secret is now hidden.");
      } catch {
        // A bounded status check has no authority and reveals no diagnostics.
      }
    }, 1_000);
  } catch {
    if (generation !== pairingRequestGeneration) {
      finishActivity(button, activityToken);
      return;
    }
    pairingRequestGeneration += 1;
    clearPairingSecret();
    finishActivity(button, activityToken);
    const port = globalThis.location?.port ? `:${globalThis.location.port}` : "";
    say(
      `Pairing secret unavailable. Open http://127.0.0.1${port}/ on this Mac; LAN pages cannot disclose it.`,
    );
  }
};

// The SDK owns session custody and operation state in IndexedDB. The page saves
// only the exact returned handle identity, never a session key or signature.
const operationKey = "oaath.phone-demo-operation/v1";
const chainId = 421614;
const target = `0x${"71".repeat(20)}`;
let client;
let connection;
let grant;
let busy = false;
const clientFetch = (request) => {
  const headers = new Headers(request.headers);
  headers.set("authorization", "Bearer demo-client-token");
  return fetch(new Request(request, { headers }));
};
async function connectAccount() {
  if (!connection) {
    client ??= createOAAth({ url: location.origin, fetch: clientFetch });
    connection = await client.connect();
    grant = await connection.resume();
  }
  const paired = await json("/demo/account");
  account.textContent = `Account: ${paired.account}`;
  return connection;
}
async function currentGrant() {
  await connectAccount();
  if (!grant) throw new Error("Request permission first.");
  return grant;
}
function saveOperation(id) {
  localStorage.setItem(operationKey, JSON.stringify({ version: operationKey, chain: chainId, id }));
}
function savedOperation() {
  const text = localStorage.getItem(operationKey);
  if (text === null) return null;
  const value = JSON.parse(text);
  if (
    value?.version !== operationKey ||
    value.chain !== chainId ||
    typeof value.id !== "string" ||
    !/^0x[0-9a-f]{64}$/.test(value.id) ||
    Object.keys(value).sort().join(",") !== "chain,id,version"
  ) {
    throw new Error("Saved operation cannot be read.");
  }
  return { chain: value.chain, id: value.id };
}
const actions = {
  unlock: [
    "Connecting account",
    async () => {
      await connectAccount();
      say(
        grant
          ? `Permission restored (${grant.state}).`
          : "Connected. Request permission to run jobs.",
      );
    },
  ],
  permission: [
    "Waiting for phone approval",
    async () => {
      await connectAccount();
      if (grant) {
        say(`Permission already exists (${grant.state}).`);
        return;
      }
      say("Review the request in the phone inbox and approve it.");
      grant = await connection.requestPermission({
        chainScope: "all",
        permissions: [{ calls: [{ target, selectors: ["0x12345678"], valueLimit: "5" }] }],
        expiresIn: 1800,
        perChainOperationLimit: 3,
      });
      say("Permission active: up to three jobs on this chain, for 30 minutes.");
    },
  ],
  session: [
    "Running a new job",
    async () => {
      const current = await currentGrant();
      // A saved unresolved job is an observation action, never another send.
      if (savedOperation()) {
        say("Observe the saved job before starting another.");
        return;
      }
      const operation = await current.sendCalls({
        chain: chainId,
        calls: [{ target, value: "5", data: "0x12345678" }],
      });
      saveOperation(operation.id);
      say(
        `Job submitted. Choose Observe saved job to check its outcome.\nOperation: ${operation.id}`,
      );
    },
  ],
  revoke: [
    "Checking permission revocation",
    async () => {
      const current = await currentGrant();
      await current.revoke();
      say(
        current.state === "revoked"
          ? "Permission revoked on the configured chain. Saved jobs can still be observed."
          : "Revocation pending. Review any request in the phone inbox, then choose Revoke / check again.",
      );
    },
  ],
  observe: [
    "Observing saved job",
    async () => {
      const saved = savedOperation();
      if (!saved) {
        say("No saved job to observe.");
        return;
      }
      const current = await currentGrant();
      const operation = await current.getOperation(saved);
      if (!operation) {
        say("The saved job is unavailable. Its identity is retained.");
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
        say(
          `Job remains ${outcome.status}. Observation can be retried.\nOperation: ${operation.id}`,
        );
    },
  ],
};
for (const [id, [title, action]] of Object.entries(actions)) {
  $(id).onclick = async () => {
    if (busy) return;
    busy = true;
    const token = beginActivity($(id), title, "Waiting for the current action.");
    for (const actionId of Object.keys(actions)) $(actionId).disabled = true;
    try {
      await action();
    } catch (error) {
      say(`Action unavailable: ${error?.code ?? "check pairing, permission, or the saved job"}.`);
    } finally {
      busy = false;
      finishActivity($(id), token);
      for (const actionId of Object.keys(actions)) $(actionId).disabled = false;
    }
  };
}
