/*
 * Owner-phone integration demo. The invariant owners are deliberately narrow:
 * the relay owns one-shot requests/artifacts, the phone owns the P-256 owner
 * key and explicit consent, this page owns the session private key, and the SDK
 * owns the exact Kernel operation hash. A missing receipt or transport error
 * leaves an operation unresolved and never authorizes resubmission.
 *
 * @author taek <leekt216@gmail.com>
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:http2";
import { networkInterfaces } from "node:os";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { p256 } from "@noble/curves/nist.js";
import { deriveCodeChallenge, OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import {
  approveKernelPermissionAllChain,
  asViemUserOperation,
  createKernelRuntime,
  createKernelV4Reads,
  ecdsaKey,
  encodeKernelV4NonceKey,
  encodeKernelV4NonceRead,
  kernelV4Deployment,
  materializeKernelPermission,
  ownerOperator,
  p256Key,
  sessionOperator,
} from "@oaath/sdk";
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";
import { createApnsSender, sendApnsNotification } from "@oaath/server/apns";
import { OAATH_SIGNATURE_REQUEST_SCOPE_VERSION } from "@oaath/server/native";
import { build } from "esbuild";
import qrcode from "qrcode-terminal";
import { createPublicClient, custom, hexToBytes, keccak256, parseEther, toHex } from "viem";
import { deployKernelStack, startAnvil } from "../support/anvil.mjs";
import {
  cacheImmutableKernelReads,
  canonicalDisplay,
  captureCanonicalDisplay,
  captureSponsorship,
  DOCUMENTED_LIVE_FLOW_REQUESTS,
  exactKeys,
  LIVE_RECEIPT_POLL_ATTEMPTS,
  LIVE_RECEIPT_POLL_INTERVAL_MS,
  LIVE_RPC_MAX_REQUESTS,
  LIVE_TRANSPORT_CONFIG,
  LiveRequestBudget,
  OneShotPairing,
  OperationLane,
  operationAction,
  pairingSecretMayRender,
  permissionMaterializedAfter,
  submitOnce,
  validateFinalizedUserOperation,
  withFreshSequence,
} from "./operation.mjs";

const SIMULATE = process.env.OAATH_PHONE_SIMULATE === "1";
const LIVE = process.env.OAATH_ZERODEV_LIVE === "1";
const CHAIN_ID = 421_614;
const GAS = Object.freeze({
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
});
const CLIENT_TOKEN = "demo-client-token";
const OWNER_TOKEN = "demo-owner-token";
const CLIENT_ID = "demo-web-app";
const SUBJECT = "demo-owner-subject";
const PAIRING_TTL_MS = 600_000;
const WAIT_MS = Number(process.env.OAATH_PHONE_WAIT_MS ?? 300_000);
const HOST = process.env.OAATH_HOST ?? (SIMULATE ? "127.0.0.1" : "0.0.0.0");
const PORT = Number(process.env.OAATH_PORT ?? 8787);
const HERE = fileURLToPath(new URL(".", import.meta.url));
const ENV_FILE = fileURLToPath(new URL("../.env", import.meta.url));
for (const key of ["INFURA_API_KEY", "ALCHEMY_API_KEY", "PARITY_RPC_URL"]) {
  if (!LIVE) delete process.env[key];
}
if (existsSync(ENV_FILE)) {
  for (const [name, value] of Object.entries(parseEnv(readFileSync(ENV_FILE, "utf8")))) {
    if (process.env[name] === undefined) process.env[name] = value;
  }
}
if (LIVE && !process.env.ZERODEV_PROJECT_ID)
  throw new Error("OAATH_ZERODEV_LIVE=1 requires ZERODEV_PROJECT_ID");
const MODE = LIVE ? "zerodev-sponsored" : "anvil";
const say = (...parts) => console.log(...parts);
const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};
const lower = (text) => text.toLowerCase();
const jsonResponse = (outgoing, status, body) => {
  outgoing.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  outgoing.end(JSON.stringify(body));
};
const refusal = (outgoing, status, code) => jsonResponse(outgoing, status, { error: { code } });
const lanIp = () => {
  for (const addresses of Object.values(networkInterfaces()))
    for (const address of addresses ?? []) {
      if (address.family === "IPv4" && !address.internal) return address.address;
    }
  return null;
};
const sha256 = (text) => createHash("sha256").update(text).digest("base64url");
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const PAIRING_CODE = [...randomBytes(10)]
  .map((byte) => codeAlphabet[byte % codeAlphabet.length])
  .join("");
const pairing = new OneShotPairing({
  hash: sha256(PAIRING_CODE),
  expiresAt: Date.now() + PAIRING_TTL_MS,
});
const pairedDevices = new Map();
let activeDevice = null;
let redirectUri = "";
let relayPort = 0;
let activeRequestId = null;
const signatureRequests = new Map();
const operations = new Map();
const operationLane = new OperationLane();
let permission = null;
let ownerRuntime = null;
let accountDescriptor = null;
let chain = null;
let stack = null;
let simulatedOwnerSecret = null;
const target = `0x${"71".repeat(20)}`;
// Immutable successful binding reads are cached; account state is refreshed
// once after deployment. The 45-request worst case leaves nine hard headroom.
expect(DOCUMENTED_LIVE_FLOW_REQUESTS === 45, "live request model drifted");
const LIVE_RPC_TIMEOUT_MS = 10_000;
const liveRequestBudget = new LiveRequestBudget();

await build({
  entryPoints: [`${HERE}/browser.js`],
  outfile: `${HERE}/.demo-browser.js`,
  bundle: true,
  format: "esm",
  platform: "browser",
  logLevel: "silent",
});
const PAGE = readFileSync(`${HERE}/page.html`);
const BROWSER = readFileSync(`${HERE}/.demo-browser.js`);

const store = createMemoryRelayStore();
const kms = {
  async encrypt(plaintext) {
    return `demo-not-encrypted:v1:${Buffer.from(plaintext).toString("base64")}`;
  },
  async decrypt(reference) {
    const prefix = "demo-not-encrypted:v1:";
    if (!reference.startsWith(prefix)) throw new Error("unknown ciphertext");
    return Buffer.from(reference.slice(prefix.length), "base64").toString();
  },
};
const authentication = {
  async authenticate(request) {
    const header = request.headers.get("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (token === CLIENT_TOKEN)
      return { role: "client", clientId: CLIENT_ID, subject: SUBJECT, redirectUris: [redirectUri] };
    if (token === OWNER_TOKEN || pairedDevices.has(token))
      return { role: "owner", clientId: "demo-owner-phone", subject: SUBJECT, redirectUris: [] };
    return null;
  },
};
const relayHandler = createRelayHandler({
  store,
  authentication,
  kms,
  clock: { now: () => Date.now() },
});

async function relayCall(method, path, token, body) {
  const response = await fetch(`http://127.0.0.1:${relayPort}${path}`, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.code ?? `relay_${response.status}`);
  return payload;
}
function p256Profile(publicMaterial, sign) {
  return p256Key({
    credential: {
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "p256",
      publicKey: `0x04${publicMaterial.slice(2)}`,
    },
    sign,
  });
}
async function bindOwner(publicMaterial) {
  ownerRuntime = createKernelRuntime({
    deployment: kernelV4Deployment(CHAIN_ID),
    operator: ownerOperator({
      key: p256Profile(publicMaterial, async ({ hash }) => {
        const current = signatureRequests.get(activeRequestId);
        if (!current || current.digest !== hash || current.artifact === null)
          throw new Error("owner signature unavailable");
        return current.artifact;
      }),
    }),
    reads: stack.reads,
  });
  accountDescriptor = await ownerRuntime.bindAccount({
    accountIndex: "0",
    initialPackages: ownerRuntime.packages,
  });
  if (!LIVE) await stack.fund(accountDescriptor.account, parseEther("2"));
  return accountDescriptor.account;
}
async function handlePairing(body, outgoing) {
  let value;
  try {
    value = JSON.parse(body.toString());
  } catch {
    return refusal(outgoing, 400, "pairing_request_invalid");
  }
  if (
    !exactKeys(value, ["pairingCode", "deviceToken", "publicKey"]) ||
    typeof value.pairingCode !== "string" ||
    !/^[0-9a-fA-F]{64,200}$/.test(value.deviceToken) ||
    !/^0x[0-9a-f]{128}$/.test(value.publicKey)
  )
    return refusal(outgoing, 400, "pairing_request_invalid");
  try {
    // reserve() mutates the one-shot state synchronously. No bind/read await can
    // let a concurrent request authenticate with the same code.
    pairing.reserve({
      hash: sha256(value.pairingCode.replace(/[\s-]/g, "").toUpperCase()),
      now: Date.now(),
    });
  } catch {
    return refusal(outgoing, 401, "pairing_invalid");
  }
  const account = await bindOwner(value.publicKey);
  const credential = randomBytes(32).toString("base64url");
  activeDevice = {
    credential,
    deviceToken: value.deviceToken.toLowerCase(),
    publicMaterial: value.publicKey,
    account,
  };
  pairedDevices.set(credential, activeDevice);
  say(`paired account   ${account}`);
  jsonResponse(outgoing, 200, { deviceCredential: credential, account });
}

async function maybePush(projection) {
  if (SIMULATE || activeDevice === null) return;
  const pem =
    process.env.APNS_KEY_PEM ??
    (process.env.APNS_KEY_PEM_PATH ? readFileSync(process.env.APNS_KEY_PEM_PATH, "utf8") : "");
  if (!pem || !process.env.APNS_KEY_ID || !process.env.APPLE_TEAM_ID || !process.env.APNS_TOPIC)
    return;
  const sender = createApnsSender({
    credentials: {
      privateKeyPem: pem,
      keyId: process.env.APNS_KEY_ID,
      teamId: process.env.APPLE_TEAM_ID,
      topic: process.env.APNS_TOPIC,
    },
    clock: { now: () => Date.now() },
  });
  const notification = sender.notification({
    deviceToken: activeDevice.deviceToken,
    projection: {
      operationId: projection.operationId,
      displayPayload: projection.displayPayload,
      expiresAt: projection.expiresAt,
    },
  });
  const session = connect("https://api.sandbox.push.apple.com:443");
  try {
    await sendApnsNotification({ session, notification, timeoutMs: 10_000 });
  } finally {
    session.close();
  }
}
async function createSignatureRequest(digest, display, purpose, simulationCommand = "approve") {
  if (activeRequestId !== null) throw new Error("signature_request_lane_occupied");
  const verifier = randomBytes(32).toString("base64url");
  const created = await relayCall("POST", "/authorization/requests", CLIENT_TOKEN, {
    redirectUri,
    codeChallenge: deriveCodeChallenge(verifier),
    requestedScope: JSON.stringify({
      version: OAATH_SIGNATURE_REQUEST_SCOPE_VERSION,
      kind: "signature-request",
      digest,
      display: captureCanonicalDisplay(display, digest),
    }),
  });
  const record = {
    requestId: created.requestId,
    digest,
    verifier,
    purpose,
    artifact: null,
    code: null,
    outcome: null,
    consumed: false,
  };
  signatureRequests.set(created.requestId, record);
  activeRequestId = created.requestId;
  const projection = await relayCall(
    "GET",
    `/native/projections/${created.requestId}`,
    activeDevice.credential,
  );
  maybePush(projection).catch(() => {});
  say(`signature request ${created.requestId} (${purpose}); phone must explicitly Approve/Reject`);
  if (SIMULATE) {
    expect(projection.scope?.kind === "signature-request", "simulation projection was not signed");
    expect(projection.scope.digest === digest, "simulation projection digest drifted");
    expect(projection.scope.display === display, "simulation projection display bytes drifted");
    if (simulationCommand === "reject") {
      await relayCall("POST", `/native/decisions/${created.requestId}`, activeDevice.credential, {
        command: "reject",
      });
    } else {
      const signature = `0x${p256.sign(hexToBytes(digest), simulatedOwnerSecret, { lowS: true, prehash: false }).toCompactHex()}`;
      const decision = await relayCall(
        "POST",
        `/native/decisions/${created.requestId}`,
        activeDevice.credential,
        { command: "approve", artifact: signature },
      );
      record.code = decision.release.code;
    }
  }
  return record;
}
async function resolveSignature(record) {
  if (record.artifact !== null) return record.artifact;
  if (record.outcome === "rejected") return null;
  if (record.code === null) {
    const state = await relayCall(
      "GET",
      `/authorization/requests/${record.requestId}`,
      OWNER_TOKEN,
    );
    if (state.decision?.outcome === "rejected") {
      record.outcome = "rejected";
      activeRequestId = null;
    }
    return null;
  }
  if (record.consumed) throw new Error("signature_artifact_already_consumed");
  record.consumed = true;
  const consumed = await relayCall("POST", "/authorization/codes/consume", CLIENT_TOKEN, {
    code: record.code,
    codeVerifier: record.verifier,
    redirectUri,
  });
  expect(consumed.requestId === record.requestId, "released another signature request");
  const claimed = await relayCall(
    "POST",
    `/authorization/artifacts/${consumed.artifactId}/claim`,
    CLIENT_TOKEN,
  );
  record.artifact = claimed.artifact;
  record.outcome = "approved";
  activeRequestId = null;
  return record.artifact;
}
async function sequence(runtime, mode) {
  const key = encodeKernelV4NonceKey({ mode, validation: runtime.validation, nonceKey: "0" });
  const result = await stack.rpc("eth_call", [
    {
      to: ownerRuntime.deployment.entryPoint.address,
      data: encodeKernelV4NonceRead({ account: accountDescriptor.account, key }),
    },
    "latest",
  ]);
  return (BigInt(result) & ((1n << 64n) - 1n)).toString();
}
function sessionRuntimeFor(sessionAddress, supplied) {
  return createKernelRuntime({
    deployment: kernelV4Deployment(CHAIN_ID),
    operator: sessionOperator({
      key: ecdsaKey({
        account: {
          address: sessionAddress,
          sign: async ({ hash }) => {
            if (!supplied.value || supplied.hash !== hash)
              throw new Error("browser signature unavailable");
            return supplied.value;
          },
        },
        validator: stack.validator,
      }),
      policies: [
        { kind: "call", calls: [{ target, selectors: ["0x00000000"] }] },
        { kind: "value", maximumValue: "10" },
      ],
    }),
    reads: stack.reads,
  });
}
const rpcUserOperation = (prepared, signature = "0x") => {
  const value = { ...asViemUserOperation(prepared.userOperation), signature };
  return Object.fromEntries(
    Object.entries(value).map(([key, field]) => [
      key,
      typeof field === "bigint" ? toHex(field) : field,
    ]),
  );
};
async function sponsoredPrepare(runtime, input) {
  const unsigned = runtime.prepareOperation(input);
  if (!LIVE) return unsigned;
  const result = await stack.rpc("zd_sponsorUserOperation", [
    { ...rpcUserOperation(unsigned), signature: runtime.dummySignature },
    unsigned.entryPoint.address,
    { sponsorshipPolicyData: { policyId: "oaath-owner-phone-demo" } },
  ]);
  const sponsorship = captureSponsorship(result);
  return runtime.prepareOperation({
    ...input,
    gas: {
      ...input.gas,
      callGasLimit: sponsorship.callGasLimit,
      verificationGasLimit: sponsorship.verificationGasLimit,
      preVerificationGas: sponsorship.preVerificationGas,
    },
    paymaster: {
      address: sponsorship.paymaster,
      verificationGasLimit: sponsorship.paymasterVerificationGasLimit,
      postOpGasLimit: sponsorship.paymasterPostOpGasLimit,
      data: sponsorship.paymasterData,
    },
  });
}
const operationInput = (input, prepared) => ({
  ...input,
  gas: {
    callGasLimit: prepared.userOperation.callGasLimit,
    verificationGasLimit: prepared.userOperation.verificationGasLimit,
    preVerificationGas: prepared.userOperation.preVerificationGas,
    maxFeePerGas: prepared.userOperation.maxFeePerGas,
    maxPriorityFeePerGas: prepared.userOperation.maxPriorityFeePerGas,
  },
  paymaster: prepared.userOperation.paymaster,
});
const displayOperation = (prepared, kind) =>
  canonicalDisplay({
    kind,
    chainId: CHAIN_ID,
    account: prepared.userOperation.sender,
    digest: prepared.userOperationHash,
    userOperationHash: prepared.userOperationHash,
    userOperation: prepared.userOperation,
  });

function terminalize(operation, evidence) {
  expect(evidence.chainId === CHAIN_ID, "observation chain mismatch");
  expect(
    evidence.account === operation.prepared.userOperation.sender,
    "observation account mismatch",
  );
  expect(
    evidence.userOperationHash === operation.prepared.userOperationHash,
    "observation operation mismatch",
  );
  expect(/^0x[0-9a-f]{64}$/.test(evidence.transactionHash), "observation transaction invalid");
  expect(evidence.status === "included" || evidence.status === "reverted", "observation invalid");
  operation.status = evidence.status;
  operation.observation = Object.freeze({ ...evidence });
  if (operation.installsPermission)
    permission.materialized = permissionMaterializedAfter({
      current: permission.materialized,
      installsPermission: true,
      status: evidence.status,
    });
  operationLane.release(operation.operationId, evidence.status);
  operation.result = {
    status: evidence.status,
    operationId: operation.operationId,
    userOperationHash: evidence.userOperationHash,
    transactionHash: evidence.transactionHash,
  };
  return operation.result;
}

async function observeOperation(operation) {
  const action = operationAction(operation.status);
  if (action === "return") return operation.result;
  if (action !== "observe") throw new Error("operation_not_observable");
  try {
    const evidence = await stack.observe(operation);
    if (evidence !== null) return terminalize(operation, evidence);
  } catch {
    // Unreadable/missing/provider evidence is not inclusion and never permits a
    // second submission. The exact prepared hash and acceptance stay in memory.
  }
  operation.status = "unresolved";
  return {
    status: "unresolved",
    operationId: operation.operationId,
    userOperationHash: operation.prepared.userOperationHash,
  };
}

async function submitOperation(operation, signature) {
  return submitOnce({
    operation,
    signature,
    send: (prepared, exactSignature, onTransactionHash) =>
      stack.sendSigned(prepared, exactSignature, onTransactionHash),
    observe: observeOperation,
    terminalize,
  });
}

async function handleDemo(method, path, body, outgoing) {
  if (method === "GET" && path === "/demo/account") {
    if (!activeDevice) return refusal(outgoing, 409, "phone_not_paired");
    return jsonResponse(outgoing, 200, {
      account: activeDevice.account,
      chainId: CHAIN_ID,
      mode: MODE,
    });
  }
  let value = {};
  if (body.length > 0) {
    try {
      value = JSON.parse(body.toString());
    } catch {
      return refusal(outgoing, 400, "demo_request_invalid");
    }
  }
  if (method === "POST" && path === "/demo/permission") {
    if (!activeDevice) return refusal(outgoing, 409, "phone_not_paired");
    if (permission) return refusal(outgoing, 409, "permission_already_requested");
    if (
      !exactKeys(value, ["sessionAddress", "sessionPublicKey"]) ||
      !/^0x[0-9a-f]{40}$/.test(value.sessionAddress) ||
      !/^0x04[0-9a-f]{128}$/.test(value.sessionPublicKey) ||
      lower(`0x${keccak256(`0x${value.sessionPublicKey.slice(4)}`).slice(-40)}`) !==
        value.sessionAddress
    )
      return refusal(outgoing, 400, "session_identity_invalid");
    const supplied = { hash: null, value: null };
    const runtime = sessionRuntimeFor(value.sessionAddress, supplied);
    const descriptor = await runtime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    expect(descriptor.account === accountDescriptor.account, "session bound another account");
    // Derive without signing; the SDK owner is authoritative for the digest formula.
    const { kernelV4ReplayableInstallDigest } = await import("@oaath/sdk");
    const exactDigest = kernelV4ReplayableInstallDigest({
      account: descriptor.account,
      nonce: "0",
      packages: runtime.packages,
    });
    const request = await createSignatureRequest(
      exactDigest,
      canonicalDisplay({
        kind: "kernel-enable-digest",
        chainScope: "all",
        account: descriptor.account,
        digest: exactDigest,
        installNonce: "0",
        sessionAddress: value.sessionAddress,
        policies: runtime.operator?.policy ?? { call: { target, maximumValue: "10" } },
      }),
      "permission",
    );
    permission = {
      runtime,
      descriptor,
      supplied,
      request,
      approval: null,
      materialized: false,
      sessionAddress: value.sessionAddress,
    };
    return jsonResponse(outgoing, 201, {
      requestId: request.requestId,
      digest: exactDigest,
      account: descriptor.account,
    });
  }
  const permissionMatch = path.match(/^\/demo\/permission\/([^/]+)$/);
  if (method === "GET" && permissionMatch) {
    if (!permission || permission.request.requestId !== permissionMatch[1])
      return refusal(outgoing, 404, "signature_request_not_found");
    const artifact = await resolveSignature(permission.request);
    if (artifact === null) {
      if (permission.request.outcome === "rejected") {
        permission = null;
        return jsonResponse(outgoing, 200, {
          status: "rejected",
          requestId: permissionMatch[1],
        });
      }
      return jsonResponse(outgoing, 200, {
        status: "pending",
        requestId: permission.request.requestId,
      });
    }
    if (!permission.approval)
      permission.approval = await approveKernelPermissionAllChain({
        owner: p256Profile(activeDevice.publicMaterial, async ({ hash }) => {
          expect(hash === permission.request.digest, "approval digest drifted");
          return artifact;
        }),
        account: permission.descriptor.account,
        installNonce: "0",
        packages: permission.runtime.packages,
      });
    return jsonResponse(outgoing, 200, {
      status: "approved",
      account: permission.descriptor.account,
      digest: permission.approval.digest,
    });
  }
  if (method === "POST" && path === "/demo/session/prepare") {
    if (!permission?.approval) return refusal(outgoing, 409, "permission_not_approved");
    if (!exactKeys(value, ["sessionAddress"]) || value.sessionAddress !== permission.sessionAddress)
      return refusal(outgoing, 400, "session_identity_invalid");
    if (operationLane.active !== null) return refusal(outgoing, 409, "operation_lane_occupied");
    const operationId = randomBytes(18).toString("base64url");
    operationLane.claim(operationId);
    const mode = permission.materialized ? "standard" : "enable-replayable";
    let input;
    let prepared;
    try {
      if (permission.materialized && permission.descriptor.state !== "deployed") {
        const refreshed = await permission.runtime.bindAccount({
          accountIndex: "0",
          initialPackages: ownerRuntime.packages,
        });
        expect(refreshed.account === accountDescriptor.account, "refreshed another account");
        permission.descriptor = refreshed;
        accountDescriptor = refreshed;
      }
      input = await withFreshSequence(
        {
          kind: "execution",
          mode,
          grantId: `phone-session-${Date.now()}`,
          account: permission.descriptor,
          nonceKey: "0",
          calls: [{ target, value: "1", data: "0x" }],
          gas: GAS,
        },
        // A failed UserOperationEvent still consumes its sequence. Read the
        // EntryPoint immediately before every preparation, including enable.
        () => sequence(permission.runtime, mode),
      );
      prepared = await sponsoredPrepare(permission.runtime, input);
    } catch (error) {
      operationLane.cancel(operationId);
      throw error;
    }
    operations.set(operationId, {
      operationId,
      chainId: CHAIN_ID,
      kind: "session",
      status: "prepared",
      prepared,
      installsPermission: !permission.materialized,
      input: operationInput(input, prepared),
    });
    return jsonResponse(outgoing, 201, {
      operationId,
      userOperationHash: prepared.userOperationHash,
    });
  }
  if (method === "POST" && path === "/demo/session/submit") {
    if (
      !exactKeys(value, ["operationId", "signature"]) ||
      !/^0x[0-9a-f]{130}$/.test(value.signature)
    )
      return refusal(outgoing, 400, "session_submission_invalid");
    const operation = operations.get(value.operationId);
    if (operation?.kind !== "session") return refusal(outgoing, 404, "operation_not_found");
    if (operation.status !== "prepared")
      return refusal(outgoing, 409, "operation_not_resubmittable");
    permission.supplied.hash = operation.prepared.userOperationHash;
    permission.supplied.value = value.signature;
    try {
      const prepared = operation.prepared;
      let signature;
      if (!permission.materialized) {
        const materialized = await materializeKernelPermission({
          approval: permission.approval,
          runtime: permission.runtime,
          grantId: operation.input.grantId,
          account: operation.input.account,
          nonceKey: "0",
          sequence: operation.input.sequence,
          calls: operation.input.calls,
          gas: operation.input.gas,
          paymaster: operation.input.paymaster,
        });
        expect(
          materialized.prepared.userOperationHash === prepared.userOperationHash,
          "materialization changed operation identity",
        );
        signature = materialized.signature;
      } else signature = await permission.runtime.signOperation(prepared);
      const result = await submitOperation(operation, signature);
      return jsonResponse(outgoing, 200, result);
    } catch (error) {
      if (operation.status !== "prepared") operation.status = "unresolved";
      throw error;
    }
  }
  const operationMatch = path.match(/^\/demo\/operations\/([^/]+)$/);
  if (method === "GET" && operationMatch) {
    const operation = operations.get(operationMatch[1]);
    if (!operation) return refusal(outgoing, 404, "operation_not_found");
    return jsonResponse(outgoing, 200, await observeOperation(operation));
  }
  if (method === "POST" && path === "/demo/owner/prepare") {
    if (!activeDevice || !exactKeys(value, []))
      return refusal(outgoing, 400, "owner_request_invalid");
    if (operationLane.active !== null) return refusal(outgoing, 409, "operation_lane_occupied");
    const preparingId = randomBytes(18).toString("base64url");
    operationLane.claim(preparingId);
    try {
      const input = await withFreshSequence(
        {
          kind: "execution",
          grantId: `phone-owner-${Date.now()}`,
          account: accountDescriptor,
          nonceKey: "0",
          calls: [{ target, value: "2", data: "0x" }],
          gas: GAS,
        },
        () => sequence(ownerRuntime, "standard"),
      );
      const prepared = await sponsoredPrepare(ownerRuntime, input);
      const request = await createSignatureRequest(
        prepared.userOperationHash,
        displayOperation(prepared, "owner-user-operation"),
        "owner-operation",
      );
      operationLane.replace(preparingId, request.requestId);
      operations.set(request.requestId, {
        operationId: request.requestId,
        chainId: CHAIN_ID,
        kind: "owner",
        status: "prepared",
        prepared,
        installsPermission: false,
        request,
      });
      return jsonResponse(outgoing, 201, {
        requestId: request.requestId,
        userOperationHash: prepared.userOperationHash,
      });
    } catch (error) {
      if (operationLane.active === preparingId) operationLane.cancel(preparingId);
      throw error;
    }
  }
  const ownerMatch = path.match(/^\/demo\/owner\/([^/]+)$/);
  if (method === "GET" && ownerMatch) {
    const operation = operations.get(ownerMatch[1]);
    if (operation?.kind !== "owner") return refusal(outgoing, 404, "operation_not_found");
    if (
      operation.status === "included" ||
      operation.status === "reverted" ||
      operation.status === "rejected"
    )
      return jsonResponse(outgoing, 200, operation.result);
    if (operation.status === "submitted" || operation.status === "unresolved")
      return jsonResponse(outgoing, 200, await observeOperation(operation));
    if (operation.status !== "prepared")
      return refusal(outgoing, 409, "operation_not_resubmittable");
    const artifact = await resolveSignature(operation.request);
    if (artifact === null) {
      if (operation.request.outcome === "rejected") {
        operation.status = "rejected";
        operationLane.cancel(operation.operationId);
        operation.result = {
          status: "rejected",
          requestId: operation.request.requestId,
        };
        return jsonResponse(outgoing, 200, operation.result);
      }
      return jsonResponse(outgoing, 200, {
        status: "pending",
        requestId: operation.request.requestId,
      });
    }
    try {
      activeRequestId = operation.request.requestId;
      const signature = await ownerRuntime.signOperation(operation.prepared);
      activeRequestId = null;
      return jsonResponse(outgoing, 200, await submitOperation(operation, signature));
    } catch (error) {
      activeRequestId = null;
      if (operation.status !== "prepared") operation.status = "unresolved";
      throw error;
    }
  }
  return refusal(outgoing, 404, "demo_route_not_found");
}

function listener(incoming, outgoing) {
  const chunks = [];
  incoming.on("data", (chunk) => chunks.push(chunk));
  incoming.on("end", async () => {
    const url = new URL(incoming.url, `http://${incoming.headers.host ?? "127.0.0.1"}`);
    const body = Buffer.concat(chunks);
    try {
      if (incoming.method === "GET" && url.pathname === "/") {
        outgoing.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
        });
        return outgoing.end(PAGE);
      }
      if (incoming.method === "GET" && url.pathname === "/demo.js") {
        outgoing.writeHead(200, {
          "content-type": "text/javascript; charset=utf-8",
          "cache-control": "no-store",
        });
        return outgoing.end(BROWSER);
      }
      if (
        incoming.method === "GET" &&
        url.pathname === "/demo/callback" &&
        url.searchParams.has("code")
      ) {
        const record = signatureRequests.get(activeRequestId);
        if (record) record.code = url.searchParams.get("code");
        outgoing.writeHead(200, { "content-type": "text/plain" });
        return outgoing.end("Signature delivered. Return to the web page.\n");
      }
      if (url.pathname === "/native/pairings") {
        if (incoming.method !== "POST") return refusal(outgoing, 405, "pairing_request_invalid");
        return await handlePairing(body, outgoing);
      }
      if (url.pathname.startsWith("/demo/"))
        return await handleDemo(incoming.method, url.pathname, body, outgoing);
      const headers = [];
      for (let index = 0; index < incoming.rawHeaders.length; index += 2)
        headers.push([incoming.rawHeaders[index], incoming.rawHeaders[index + 1]]);
      const response = await relayHandler(
        new Request(url, { method: incoming.method, headers, ...(body.length ? { body } : {}) }),
      );
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      say("request failed", "demo_failed");
      if (!outgoing.headersSent) refusal(outgoing, 500, "demo_failed");
      else outgoing.end();
    }
  });
}

if (LIVE) {
  const endpoint = `https://rpc.zerodev.app/api/v3/${encodeURIComponent(process.env.ZERODEV_PROJECT_ID)}/chain/${CHAIN_ID}`;
  const budgetedRpc = async (method, params) => {
    const requestId = liveRequestBudget.take(method);
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }),
      signal: AbortSignal.timeout(LIVE_RPC_TIMEOUT_MS),
    });
    const body = await response.json();
    if (!response.ok || body.error || !("result" in body)) throw new Error("zerodev_rpc_failed");
    return body.result;
  };
  const publicClient = createPublicClient({
    transport: custom(
      { request: ({ method, params }) => budgetedRpc(method, params ?? []) },
      LIVE_TRANSPORT_CONFIG,
    ),
  });
  stack = {
    reads: cacheImmutableKernelReads(createKernelV4Reads(publicClient)),
    // Session authority resolves the pinned ECDSA signer; this syntactically
    // valid placeholder is never installed or used as an owner validator.
    validator: `0x${"01".repeat(20)}`,
    rpc: budgetedRpc,
    fund: async () => {},
    observe: async (operation) => {
      for (let attempt = 0; attempt < LIVE_RECEIPT_POLL_ATTEMPTS; attempt += 1) {
        const observed = await budgetedRpc("eth_getUserOperationReceipt", [
          operation.prepared.userOperationHash,
        ]);
        if (observed !== null) {
          const transactionHash = lower(observed.receipt?.transactionHash ?? "");
          return validateFinalizedUserOperation({ operation, transactionHash, rpc: budgetedRpc });
        }
        if (attempt + 1 < LIVE_RECEIPT_POLL_ATTEMPTS)
          await new Promise((resolve) => setTimeout(resolve, LIVE_RECEIPT_POLL_INTERVAL_MS));
      }
      return null;
    },
    sendSigned: async (prepared, signature) => {
      const userOperationHash = await budgetedRpc("eth_sendUserOperation", [
        rpcUserOperation(prepared, signature),
        prepared.entryPoint.address,
      ]);
      if (typeof userOperationHash !== "string" || !/^0x[0-9a-f]{64}$/.test(userOperationHash))
        throw new Error("zerodev_submission_response_invalid");
      if (userOperationHash !== prepared.userOperationHash)
        throw new Error("zerodev_submission_hash_mismatch");
      return { userOperationHash };
    },
  };
} else {
  chain = await startAnvil(CHAIN_ID, "osaka");
  stack = await deployKernelStack(chain, { p256: true });
  stack.rpc = chain.rpc;
  stack.observe = async (operation) => {
    if (!operation.transactionHash) return null;
    // Let Anvil's real finalized tag advance beyond the inclusion block.
    await chain.rpc("anvil_mine", ["0x3"]);
    return validateFinalizedUserOperation({
      operation,
      transactionHash: operation.transactionHash,
      rpc: chain.rpc,
    });
  };
}
const server = createServer(listener);
await new Promise((resolve) => server.listen(PORT, HOST, resolve));
relayPort = server.address().port;
const phoneHost = SIMULATE ? "127.0.0.1" : lanIp();
if (!phoneHost)
  throw new Error("No LAN IPv4 address found; set OAATH_HOST and use a reachable relay URL");
const relayUrl = `http://${phoneHost}:${relayPort}`;
redirectUri = `${relayUrl}/demo/callback`;
const pairingLink = `oaath-demo://pair?relay=${encodeURIComponent(relayUrl)}&code=${encodeURIComponent(PAIRING_CODE)}`;
say("\nOAAth owner-phone demo");
say(`mode             ${MODE}`);
say(`web + relay      ${relayUrl}`);
if (pairingSecretMayRender({ simulate: SIMULATE, isTTY: process.stdout.isTTY })) {
  // This is transient interactive UI, never a log/captured-output path.
  process.stdout.write(`pairing link     ${pairingLink}\n`);
  qrcode.generate(pairingLink, { small: true }, (qr) => process.stdout.write(`${qr}\n`));
}
if (process.env.ZERODEV_PROJECT_ID && !LIVE)
  say("ZeroDev project   present but NOT consent: ignored unless OAATH_ZERODEV_LIVE=1");

async function simulate() {
  simulatedOwnerSecret = p256.utils.randomPrivateKey();
  const publicMaterial = `0x${Buffer.from(p256.getPublicKey(simulatedOwnerSecret, false).slice(1)).toString("hex")}`;
  const pair = await relayCall("POST", "/native/pairings", null, {
    pairingCode: PAIRING_CODE,
    deviceToken: "ab".repeat(32),
    publicKey: publicMaterial,
  });
  const replay = await fetch(`http://127.0.0.1:${relayPort}/native/pairings`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      pairingCode: PAIRING_CODE,
      deviceToken: "ab".repeat(32),
      publicKey: publicMaterial,
    }),
  });
  expect(replay.status === 401, "pairing was not one-shot");
  expect(
    (await relayCall("GET", "/demo/account", null)).account === pair.account,
    "unlock changed the account",
  );
  const rejectedDigest = `0x${"5a".repeat(32)}`;
  const rejectedRequest = await createSignatureRequest(
    rejectedDigest,
    canonicalDisplay({ digest: rejectedDigest, kind: "reject-regression" }),
    "reject-regression",
    "reject",
  );
  const rejectedAt = Date.now();
  expect((await resolveSignature(rejectedRequest)) === null, "reject produced an artifact");
  expect(rejectedRequest.outcome === "rejected", "reject was not terminal");
  expect(activeRequestId === null, "reject did not clear the signature lane");
  expect(Date.now() - rejectedAt < 1_000, "reject did not terminate promptly");

  const { secp256k1 } = await import("@noble/curves/secp256k1.js");
  const sessionSecret = secp256k1.utils.randomPrivateKey();
  const sessionPublic = secp256k1.getPublicKey(sessionSecret, false);
  const sessionAddress = lower(
    `0x${keccak256(`0x${Buffer.from(sessionPublic.slice(1)).toString("hex")}`).slice(-40)}`,
  );
  const requested = await relayCall("POST", "/demo/permission", null, {
    sessionAddress,
    sessionPublicKey: `0x${Buffer.from(sessionPublic).toString("hex")}`,
  });
  const approved = await relayCall("GET", `/demo/permission/${requested.requestId}`, null);
  expect(approved.status === "approved", "permission did not approve");
  for (let index = 0; index < 2; index += 1) {
    const prepared = await relayCall("POST", "/demo/session/prepare", null, { sessionAddress });
    if (index === 0) {
      const concurrent = await fetch(`http://127.0.0.1:${relayPort}/demo/session/prepare`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sessionAddress }),
      });
      expect(concurrent.status === 409, "concurrent operation lane was not blocked");
    }
    const signed = secp256k1.sign(hexToBytes(prepared.userOperationHash), sessionSecret, {
      lowS: true,
      prehash: false,
    });
    const signature = `0x${signed.toCompactHex()}${(27 + signed.recovery).toString(16)}`;
    const sent = await relayCall("POST", "/demo/session/submit", null, {
      operationId: prepared.operationId,
      signature,
    });
    expect(sent.status === "included", `session operation ${sent.status}`);
    if (index === 0) expect(permission.materialized, "included install did not materialize");
  }
  const owner = await relayCall("POST", "/demo/owner/prepare", null, {});
  const ownerSent = await relayCall("GET", `/demo/owner/${owner.requestId}`, null);
  expect(ownerSent.status === "included", `owner operation ${ownerSent.status}`);
  say(
    "simulate         all four buttons passed; session send repeated with getNonce-driven sequences",
  );
}

try {
  if (SIMULATE) await simulate();
  else await new Promise((resolve) => setTimeout(resolve, WAIT_MS));
} finally {
  if (LIVE) {
    const observed = liveRequestBudget.snapshot();
    const methods = observed.methods.map(([method, count]) => `${method}:${count}`).join(",");
    say(`live RPC requests ${observed.count}/${LIVE_RPC_MAX_REQUESTS} (${methods})`);
  }
  await new Promise((resolve) => server.close(resolve));
  await store.close();
  chain?.stop();
  try {
    await (await import("node:fs/promises")).unlink(`${HERE}/.demo-browser.js`);
  } catch {}
}
