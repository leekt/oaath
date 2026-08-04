import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const $ = (id) => document.getElementById(id);
const status = $("status");
const account = $("account");
const keyName = "oaath-demo-session-private-key-v1";
const permissionRequestKey = "oaath-demo-permission-request-v1";
const sessionOperationKey = "oaath-demo-session-operation-v1";
const ownerRequestKey = "oaath-demo-owner-request-v1";
const say = (text) => {
  status.textContent = text;
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
const poll = async (path, label, id) => {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const answer = await json(path);
    if (answer.status !== "pending") return answer;
    say(`${label}\nWaiting without creating another request or operation…\nExact id: ${id}`);
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

$("unlock").onclick = async () => {
  try {
    const unlocked = await json("/demo/account");
    account.textContent = `Account: ${unlocked.account}`;
    say(`Unlocked ${unlocked.account}. No owner authorization was requested.`);
  } catch (error) {
    say(`Unlock failed: ${error.message}`);
  }
};
$("permission").onclick = async () => {
  try {
    const identity = sessionIdentity();
    const state = await json("/demo/state");
    if (state.permission?.sessionAddress === identity.address) {
      if (!state.permission.requestId) {
        say("The matching permission reservation is still occupied; no duplicate was created.");
        return;
      }
      remember(permissionRequestKey, state.permission.requestId);
      const resumed = await poll(
        `/demo/permission/${state.permission.requestId}`,
        "Resuming the existing permission request.",
        state.permission.requestId,
      );
      if (resumed.status === "rejected") forget(permissionRequestKey);
      say(
        resumed.status === "rejected"
          ? "Permission rejected on the phone. No signature or permission was created."
          : `Permission signature approved for ${resumed.account}.\nThe phone signed ${resumed.digest}. Onchain permission is not materialized yet.`,
      );
      return;
    }
    const created = await json("/demo/permission", {
      method: "POST",
      body: JSON.stringify({
        sessionAddress: identity.address,
        sessionPublicKey: identity.publicKey,
      }),
    });
    // Persist as soon as the API reveals the owner request id, before polling.
    remember(permissionRequestKey, created.requestId);
    const approved = await poll(
      `/demo/permission/${created.requestId}`,
      "Permission request created.",
      created.requestId,
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
  }
};
$("session").onclick = async () => {
  try {
    const identity = sessionIdentity();
    const state = await json("/demo/state");
    if (state.operation?.kind === "session") {
      const existing = state.operation;
      remember(sessionOperationKey, existing.operationId);
      if (existing.status === "prepared") {
        const signature = sign(existing.userOperationHash, identity.key);
        finishSession(
          await json("/demo/session/submit", {
            method: "POST",
            body: JSON.stringify({ operationId: existing.operationId, signature }),
          }),
        );
      } else await observeSession(existing.operationId);
      return;
    }
    const remembered = localStorage.getItem(sessionOperationKey);
    if (remembered !== null) {
      await observeSession(remembered);
      return;
    }
    const prepared = await json("/demo/session/prepare", {
      method: "POST",
      body: JSON.stringify({ sessionAddress: identity.address }),
    });
    // The prepared hash/id is known before submit. Retain it across response
    // loss and reload so every later click observes this exact occupied lane.
    remember(sessionOperationKey, prepared.operationId);
    const signature = sign(prepared.userOperationHash, identity.key);
    finishSession(
      await json("/demo/session/submit", {
        method: "POST",
        body: JSON.stringify({ operationId: prepared.operationId, signature }),
      }),
    );
  } catch (error) {
    say(`Session transaction failed: ${error.message}`);
  }
};
$("owner").onclick = async () => {
  try {
    const state = await json("/demo/state");
    let requestId =
      state.operation?.kind === "owner" && state.operation.status !== "awaiting-request"
        ? state.operation.operationId
        : state.signatureRequest?.purpose === "owner-operation"
          ? state.signatureRequest.requestId
          : localStorage.getItem(ownerRequestKey);
    if (!requestId && (state.operation?.kind === "owner" || state.signatureRequest)) {
      say("The owner request lane is occupied and possibly submitted; no duplicate was created.");
      return;
    }
    if (!requestId) {
      const prepared = await json("/demo/owner/prepare", { method: "POST", body: "{}" });
      requestId = prepared.requestId;
    }
    // Persist immediately when the API reveals the signature request id.
    remember(ownerRequestKey, requestId);
    const sent = await poll(
      `/demo/owner/${requestId}`,
      "Resuming the exact owner signature request.",
      requestId,
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
    say(`Owner transaction failed: ${error.message}`);
  }
};
