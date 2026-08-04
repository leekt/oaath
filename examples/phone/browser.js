import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const $ = (id) => document.getElementById(id);
const status = $("status");
const account = $("account");
const keyName = "oaath-demo-session-private-key-v1";
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
  const signature = secp256k1.sign(hexToBytes(hash), key, { lowS: true, prehash: false });
  const recovery = signature.recovery;
  if (recovery === undefined) throw new Error("session signature has no recovery id");
  return `0x${signature.toCompactHex()}${(27 + recovery).toString(16).padStart(2, "0")}`;
};
const poll = async (path, label) => {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const answer = await json(path);
    if (answer.status !== "pending" && answer.status !== "unresolved") return answer;
    say(
      `${label}\nWaiting for explicit Approve/Reject on the phone…\nOperation id: ${answer.requestId}`,
    );
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("phone decision timed out");
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
    const created = await json("/demo/permission", {
      method: "POST",
      body: JSON.stringify({
        sessionAddress: identity.address,
        sessionPublicKey: identity.publicKey,
      }),
    });
    say(
      `Permission request created.\nOperation id: ${created.requestId}\nThe session private key remains in this browser.`,
    );
    const approved = await poll(
      `/demo/permission/${created.requestId}`,
      "Permission request created.",
    );
    if (approved.status === "rejected") {
      say("Permission rejected on the phone. No signature or permission was created.");
      return;
    }
    say(`Permission approved for ${approved.account}.\nThe phone signed ${approved.digest}.`);
  } catch (error) {
    say(`Permission failed: ${error.message}`);
  }
};
const unresolvedOperationKey = "oaath-demo-unresolved-session-operation-v1";
let unresolvedSessionOperationId = localStorage.getItem(unresolvedOperationKey);
$("session").onclick = async () => {
  try {
    if (unresolvedSessionOperationId !== null) {
      const observed = await json(`/demo/operations/${unresolvedSessionOperationId}`);
      if (observed.status === "unresolved") {
        say(
          `Session operation remains unresolved. Observation retried without resubmission.\nUserOperation: ${observed.userOperationHash}`,
        );
        return;
      }
      unresolvedSessionOperationId = null;
      localStorage.removeItem(unresolvedOperationKey);
      say(
        `Session operation ${observed.status}.\nUserOperation: ${observed.userOperationHash}\nTransaction: ${observed.transactionHash}`,
      );
      return;
    }
    const identity = sessionIdentity();
    const prepared = await json("/demo/session/prepare", {
      method: "POST",
      body: JSON.stringify({ sessionAddress: identity.address }),
    });
    const signature = sign(prepared.userOperationHash, identity.key);
    const sent = await json("/demo/session/submit", {
      method: "POST",
      body: JSON.stringify({ operationId: prepared.operationId, signature }),
    });
    if (sent.status === "unresolved") {
      unresolvedSessionOperationId = sent.operationId;
      localStorage.setItem(unresolvedOperationKey, sent.operationId);
      say(
        `Session operation unresolved. Click again to observe the same hash without resubmitting.\nUserOperation: ${sent.userOperationHash}`,
      );
      return;
    }
    say(
      `Session operation ${sent.status}.\nUserOperation: ${sent.userOperationHash}\nTransaction: ${sent.transactionHash}`,
    );
  } catch (error) {
    say(`Session transaction failed: ${error.message}`);
  }
};
$("owner").onclick = async () => {
  try {
    const prepared = await json("/demo/owner/prepare", { method: "POST", body: "{}" });
    say(
      `Owner signature request created.\nOperation id: ${prepared.requestId}\nThe phone shows the full UserOperation JSON.`,
    );
    const sent = await poll(
      `/demo/owner/${prepared.requestId}`,
      "Owner signature request created.",
    );
    if (sent.status === "rejected") {
      say("Owner operation rejected on the phone. No signature or operation was submitted.");
      return;
    }
    say(
      `Owner operation ${sent.status} after phone approval.\nUserOperation: ${sent.userOperationHash}\nTransaction: ${sent.transactionHash}`,
    );
  } catch (error) {
    say(`Owner transaction failed: ${error.message}`);
  }
};
