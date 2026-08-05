import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const $ = (id) => document.getElementById(id);
const status = $("status");
const account = $("account");
const pairingPanel = $("pairing");
const pairingQr = $("pairing-qr");
const pairingLink = $("pairing-link");
const activity = $("activity");
const activityTitle = $("activity-title");
const activityDetail = $("activity-detail");
const keyName = "oaath-demo-session-private-key-v1";
const permissionRequestKey = "oaath-demo-permission-request-v1";
const sessionOperationKey = "oaath-demo-session-operation-v1";
const ownerRequestKey = "oaath-demo-owner-request-v1";
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
const remember = (key, value) => localStorage.setItem(key, value);
const forget = (key) => localStorage.removeItem(key);
const sessionKey = () => {
  let hex = localStorage.getItem(keyName);
  if (hex === null || !/^[0-9a-f]{64}$/.test(hex)) {
    hex = bytesToHex(secp256k1.utils.randomPrivateKey());
    localStorage.setItem(keyName, hex);
  }
  return hexToBytes(hex);
};
const sessionIdentity = () => {
  const key = sessionKey();
  const publicKey = secp256k1.getPublicKey(key, false);
  return {
    key,
    publicKey: `0x${bytesToHex(publicKey)}`,
    address: `0x${bytesToHex(keccak_256(publicKey.slice(1)).slice(-20))}`,
  };
};
const sign = (hash, key) => {
  const signature = secp256k1.sign(hexToBytes(hash.slice(2)), key, {
    lowS: true,
    prehash: false,
  });
  const recovery = signature.recovery;
  if (recovery === undefined) throw new Error("session signature has no recovery id");
  return `0x${signature.toCompactHex()}${(27 + recovery).toString(16).padStart(2, "0")}`;
};
let pairingExpiryTimer = null;
let pairingStatusTimer = null;
let pairingRequestGeneration = 0;
let sessionActionPending = false;
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
const poll = async (path, label, id, activityToken) => {
  let currentRequestId = id;
  say(`${label}\nWaiting without creating another request or operation.\nExact id: ${id}`);
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const answer = await json(path);
    if (answer.status !== "pending") return answer;
    if (answer.requestId && answer.requestId !== currentRequestId) {
      currentRequestId = answer.requestId;
      say(`Sponsorship completed. Approve the final phone request.\nExact id: ${currentRequestId}`);
    }
    updateActivity(
      activityToken,
      label,
      `Waiting for iPhone approval (${attempt + 1}s). Exact id: ${currentRequestId}`,
    );
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("phone decision timed out");
};
const finishSession = (answer) => {
  if (answer.status === "unresolved") {
    say(
      `Session operation remains unresolved (${answer.code ?? "evidence_unavailable"}). Observation retried without resubmission. Permission remains unmaterialized.\nUserOperation: ${answer.userOperationHash}${answer.transactionHash ? `\nDiscovered transaction: ${answer.transactionHash}` : ""}`,
    );
    return;
  }
  forget(sessionOperationKey);
  say(
    `Session operation ${answer.status}.\nUserOperation: ${answer.userOperationHash}\nTransaction: ${answer.transactionHash}`,
  );
};
const observeSession = async (operationId) => {
  remember(sessionOperationKey, operationId);
  finishSession(await json(`/demo/operations/${operationId}`));
};
const sponsorSession = async (prepared, identity, activityToken) => {
  updateActivity(
    activityToken,
    "Signing paymaster simulation",
    `Signing retained hash ${prepared.userOperationHash}; this signature is not submitted.`,
  );
  const signature = sign(prepared.userOperationHash, identity.key);
  updateActivity(
    activityToken,
    "Requesting ZeroDev sponsorship",
    `Core SDK preparation is hash-binding paymaster fields for ${prepared.operationId}.`,
  );
  return json("/demo/session/sponsor", {
    method: "POST",
    body: JSON.stringify({ operationId: prepared.operationId, signature }),
  });
};
const submitSession = async (prepared, identity, activityToken) => {
  updateActivity(
    activityToken,
    "Signing final session operation",
    `Signing final hash ${prepared.userOperationHash} only in this browser.`,
  );
  const signature = sign(prepared.userOperationHash, identity.key);
  updateActivity(
    activityToken,
    "Submitting session operation",
    `Submitting exact operation ${prepared.operationId}, then waiting for chain evidence.`,
  );
  finishSession(
    await json("/demo/session/submit", {
      method: "POST",
      body: JSON.stringify({ operationId: prepared.operationId, signature }),
    }),
  );
};

$("unlock").onclick = async () => {
  const button = $("unlock");
  const activityToken = beginActivity(
    button,
    "Reading paired account",
    "Binding the phone owner to the Arbitrum Sepolia profile (chain 421614).",
  );
  try {
    const unlocked = await json("/demo/account");
    account.textContent = `Account: ${unlocked.account}`;
    say(
      `Unlocked ${unlocked.account}.\nNetwork: Arbitrum Sepolia (${unlocked.chainId}); mode: ${unlocked.mode}.\nNo owner authorization was requested.`,
    );
  } catch (error) {
    say(`Unlock failed: ${error.message}`);
  } finally {
    finishActivity(button, activityToken);
  }
};
$("permission").onclick = async () => {
  const button = $("permission");
  const activityToken = beginActivity(
    button,
    "Checking permission state",
    "Reading the current Arbitrum Sepolia session binding before creating anything.",
  );
  try {
    const identity = sessionIdentity();
    const state = await json("/demo/state");
    if (state.permission?.sessionAddress === identity.address) {
      if (!state.permission.requestId) {
        say("The matching permission reservation is still occupied; no duplicate was created.");
        return;
      }
      remember(permissionRequestKey, state.permission.requestId);
      updateActivity(
        activityToken,
        "Resuming iPhone permission approval",
        `Exact request: ${state.permission.requestId}`,
      );
      const resumed = await poll(
        `/demo/permission/${state.permission.requestId}`,
        "Resuming the existing permission request.",
        state.permission.requestId,
        activityToken,
      );
      if (resumed.status === "rejected") forget(permissionRequestKey);
      say(
        resumed.status === "rejected"
          ? "Permission rejected on the phone. No signature or permission was created."
          : `Permission signature approved for ${resumed.account}.\nThe phone signed ${resumed.digest}. Onchain permission is not materialized yet.`,
      );
      return;
    }
    updateActivity(
      activityToken,
      "Preparing permission approval",
      "Binding the browser session key and creating one phone signature request.",
    );
    const created = await json("/demo/permission", {
      method: "POST",
      body: JSON.stringify({
        sessionAddress: identity.address,
        sessionPublicKey: identity.publicKey,
      }),
    });
    // Persist as soon as the API reveals the owner request id, before polling.
    remember(permissionRequestKey, created.requestId);
    updateActivity(
      activityToken,
      "Waiting for iPhone permission approval",
      `Open the request in the app. Exact request: ${created.requestId}`,
    );
    const approved = await poll(
      `/demo/permission/${created.requestId}`,
      "Permission request created.",
      created.requestId,
      activityToken,
    );
    if (approved.status === "rejected") {
      forget(permissionRequestKey);
      say("Permission rejected on the phone. No signature or permission was created.");
      return;
    }
    say(
      `Permission signature approved for ${approved.account}.\nThe phone signed ${approved.digest}. Onchain permission is not materialized yet.`,
    );
  } catch (error) {
    say(`Permission failed: ${error.message}`);
  } finally {
    finishActivity(button, activityToken);
  }
};
$("session").onclick = async () => {
  if (sessionActionPending) {
    say("Session operation preparation is still in progress; no duplicate was started.");
    return;
  }
  sessionActionPending = true;
  const button = $("session");
  const activityToken = beginActivity(
    button,
    "Checking session operation lane",
    "Reading the exact retained operation before preparing or submitting anything.",
  );
  try {
    const identity = sessionIdentity();
    const state = await json("/demo/state");
    const existing = state.operations?.session;
    if (existing?.status === "preparing") {
      say("Session operation preparation is still in progress; no duplicate was started.");
      return;
    }
    if (existing) {
      remember(sessionOperationKey, existing.operationId);
      if (existing.status === "awaiting-sponsorship-signature") {
        await submitSession(
          await sponsorSession(existing, identity, activityToken),
          identity,
          activityToken,
        );
      } else if (existing.status === "sponsoring") {
        say("Sponsorship is already in progress; no duplicate request was started.");
      } else if (existing.status === "sponsorship-unresolved") {
        say("Sponsorship outcome is unresolved; no retry or transaction submission was started.");
      } else if (existing.status === "prepared") {
        await submitSession(existing, identity, activityToken);
      } else if (existing.status === "unresolved") {
        updateActivity(
          activityToken,
          "Checking the next session nonce",
          "A new operation is prepared only if EntryPoint proves the retained nonce was consumed.",
        );
        try {
          const prepared = await json("/demo/session/prepare", {
            method: "POST",
            body: JSON.stringify({ sessionAddress: identity.address }),
          });
          remember(sessionOperationKey, prepared.operationId);
          const finalPrepared = prepared.sponsorshipRequired
            ? await sponsorSession(prepared, identity, activityToken)
            : prepared;
          await submitSession(finalPrepared, identity, activityToken);
        } catch (error) {
          if (error.message !== "session_sequence_unresolved") throw error;
          updateActivity(
            activityToken,
            "Observing occupied session nonce",
            `Observing exact operation ${existing.operationId} without resubmitting.`,
          );
          await observeSession(existing.operationId);
        }
      } else {
        updateActivity(
          activityToken,
          "Observing existing session operation",
          `Observing exact operation ${existing.operationId} without resubmitting.`,
        );
        await observeSession(existing.operationId);
      }
      return;
    }
    const remembered = localStorage.getItem(sessionOperationKey);
    if (remembered !== null) {
      updateActivity(
        activityToken,
        "Recovering retained session operation",
        `Observing exact operation ${remembered} without resubmitting.`,
      );
      await observeSession(remembered);
      return;
    }
    updateActivity(
      activityToken,
      "Preparing session operation",
      "Reading the EntryPoint nonce and building the Arbitrum Sepolia UserOperation.",
    );
    const prepared = await json("/demo/session/prepare", {
      method: "POST",
      body: JSON.stringify({ sessionAddress: identity.address }),
    });
    // The prepared hash/id is known before submit. Retain it across response
    // loss and reload so every later click observes this exact occupied lane.
    remember(sessionOperationKey, prepared.operationId);
    const finalPrepared = prepared.sponsorshipRequired
      ? await sponsorSession(prepared, identity, activityToken)
      : prepared;
    await submitSession(finalPrepared, identity, activityToken);
  } catch (error) {
    if (error.message === "operation_not_found") {
      forget(sessionOperationKey);
      say(
        "The retained session operation belongs to a previous relay process. Its local pointer was cleared; no operation was prepared or submitted. Click again to start a new operation explicitly.",
      );
    } else say(`Session transaction failed: ${error.message}`);
  } finally {
    sessionActionPending = false;
    finishActivity(button, activityToken);
  }
};
$("owner").onclick = async () => {
  const button = $("owner");
  const activityToken = beginActivity(
    button,
    "Checking owner operation lane",
    "Reading the exact retained request before preparing or submitting anything.",
  );
  try {
    const state = await json("/demo/state");
    const ownerOperation = state.operations?.owner;
    let requestId =
      ownerOperation && ownerOperation.status !== "awaiting-request"
        ? ownerOperation.operationId
        : state.signatureRequest?.purpose === "owner-operation"
          ? state.signatureRequest.requestId
          : localStorage.getItem(ownerRequestKey);
    if (!requestId && (ownerOperation || state.signatureRequest)) {
      say("The owner request lane is occupied and possibly submitted; no duplicate was created.");
      return;
    }
    if (!requestId) {
      updateActivity(
        activityToken,
        "Preparing owner operation",
        "Reading the EntryPoint nonce and creating one iPhone signature request.",
      );
      const prepared = await json("/demo/owner/prepare", { method: "POST", body: "{}" });
      requestId = prepared.requestId;
    }
    // Persist immediately when the API reveals the signature request id.
    remember(ownerRequestKey, requestId);
    updateActivity(
      activityToken,
      "Waiting for iPhone owner approval",
      `Approve in the app; the exact request is ${requestId}. Submission follows approval.`,
    );
    const sent = await poll(
      `/demo/owner/${requestId}`,
      "Resuming the exact owner signature request.",
      requestId,
      activityToken,
    );
    if (sent.status === "rejected") {
      forget(ownerRequestKey);
      say("Owner operation rejected on the phone. No signature or operation was submitted.");
      return;
    }
    forget(ownerRequestKey);
    say(
      sent.status === "unresolved"
        ? `Owner operation remains unresolved (${sent.code ?? "evidence_unavailable"}) after phone approval. Observation is same-hash only.\nUserOperation: ${sent.userOperationHash}${sent.transactionHash ? `\nDiscovered transaction: ${sent.transactionHash}` : ""}`
        : `Owner operation ${sent.status} after phone approval.\nUserOperation: ${sent.userOperationHash}\nTransaction: ${sent.transactionHash}`,
    );
  } catch (error) {
    if (error.message === "operation_not_found") {
      forget(ownerRequestKey);
      say(
        "The retained owner request belongs to a previous relay process. Its local pointer was cleared; no operation was prepared or submitted. Click again to start a new request explicitly.",
      );
    } else say(`Owner transaction failed: ${error.message}`);
  } finally {
    finishActivity(button, activityToken);
  }
};
