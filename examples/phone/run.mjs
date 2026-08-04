/**
 * The owner-phone approval demo, web half: a relay your iPhone can reach, a
 * one-shot pairing code, a real APNs push (opt-in), and a tiny "web app"
 * waiting for its authorization code.
 *
 *   1. relay on the LAN     `createRelayHandler` over `node:http`, plus the
 *                           preview phone routes it now serves, plus one
 *                           example-owned pairing route
 *   2. pairing              a printed one-shot code; the phone trades it (with
 *                           its APNs device token) for a device-scoped owner
 *                           credential
 *   3. authorization        a PKCE request whose consent scope the phone
 *                           renders in full before the owner decides
 *   4. push (optional)      the merged APNs sender + settle-once transport,
 *                           one send, Apple SANDBOX host
 *   5. delivery             the phone GETs the redirect URI with the released
 *                           one-time code; this file consumes + claims it and
 *                           proves the one-shot semantics
 *
 * SECURITY HONESTY: this is a demo. It binds 0.0.0.0 and uses fixed demo
 * tokens, so anyone on your network could hit the relay — run it on a trusted
 * network only. The pairing code printed to this terminal is the demo's trust
 * root; a production deployment owns pairing UX (QR, attestation) through its
 * authentication port. Every line a deployment must replace says `REPLACE`.
 *
 * `OAATH_PHONE_SIMULATE=1` drives the phone's half over HTTP itself so
 * `examples:check` covers the whole loop unattended (no Apple contact).
 *
 * @author taek <leekt216@gmail.com>
 */

import { randomBytes, webcrypto } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:http2";
import { networkInterfaces } from "node:os";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { deriveCodeChallenge } from "@oaath/protocol";
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";
import { createApnsSender, sendApnsNotification } from "@oaath/server/apns";

const SIMULATE = process.env.OAATH_PHONE_SIMULATE === "1";

/**
 * Opt-in variables may live in `examples/.env` (never committed; see the root
 * .gitignore). The real environment wins over the file. These are credentials:
 * only their NAMES are ever narrated, never their values. They are scrubbed
 * from every test/gate environment on purpose — this example reads them at
 * runtime only, and it is not a gate.
 */
const ENV_FILE = fileURLToPath(new URL("../.env", import.meta.url));
const OPT_IN_VARS = [
  "APNS_KEY_PEM",
  "APNS_KEY_PEM_PATH",
  "APNS_KEY_ID",
  "APPLE_TEAM_ID",
  "APNS_TOPIC",
  "ZERODEV_PROJECT_ID", // consumed by a later phase; loaded here so the file is wired once
];
if (existsSync(ENV_FILE)) {
  const fromFile = parseEnv(readFileSync(ENV_FILE, "utf8"));
  for (const [name, value] of Object.entries(fromFile)) {
    if (process.env[name] === undefined) process.env[name] = value;
  }
}

const HOST = process.env.OAATH_HOST ?? (SIMULATE ? "127.0.0.1" : "0.0.0.0");
const PORT = Number(process.env.OAATH_PORT ?? 8787);
const CALLBACK_PORT = Number(process.env.OAATH_CALLBACK_PORT ?? 8788);
/** How long the demo waits for the phone before giving up. */
const WAIT_MS = Number(process.env.OAATH_PHONE_WAIT_MS ?? 300_000);
const PAIRING_TTL_MS = 600_000;

/** REPLACE: real deployments authenticate clients and owners, not fixed strings. */
const CLIENT_TOKEN = "demo-client-token";
const OWNER_TOKEN = "demo-owner-token";
const CLIENT_ID = "demo-web-app";
const SUBJECT = "demo-owner-subject";
/** PKCE: the client keeps the verifier and sends only the challenge. */
const CODE_VERIFIER = "demo-code-verifier-that-is-long-enough-0123456789";

const say = (...parts) => console.log(...parts);
const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};
const sha256Base64Url = async (text) => {
  const digest = await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Buffer.from(digest).toString("base64url");
};

/** First non-internal IPv4 — the address the phone must dial. */
function lanIp() {
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family === "IPv4" && !address.internal) return address.address;
    }
  }
  return null;
}

/**
 * Pairing state, in memory and example-owned ON PURPOSE: the relay store
 * contract is not widened for a preview. A module-level Map is the honest
 * shape of "this demo process knows its paired devices"; restarting the
 * example forgets them, and the phone re-pairs with a fresh code.
 */
const DEVICE_TOKEN_SHAPE = /^[0-9a-fA-F]{64,200}$/u; // the APNs sender's rule
const pairing = {
  codeHash: "",
  expiresAt: 0,
  consumed: false,
};
/** deviceCredential -> hex APNs device token. */
const pairedDevices = new Map();

function newPairingCode() {
  // 10 characters from an unambiguous alphabet: typed by hand on a phone.
  const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(10);
  let code = "";
  for (const byte of bytes) code += alphabet[byte % alphabet.length];
  return code;
}

const PAIRING_CODE = newPairingCode();
pairing.codeHash = await sha256Base64Url(PAIRING_CODE);
pairing.expiresAt = Date.now() + PAIRING_TTL_MS;

/**
 * REPLACE: the deployment owns authentication. Here: two fixed demo tokens,
 * plus every device credential the pairing route issued — each an owner-role
 * caller bound to the demo subject.
 */
const authentication = {
  async authenticate(request) {
    const header = request.headers.get("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
    if (token === CLIENT_TOKEN) {
      return {
        role: "client",
        clientId: CLIENT_ID,
        subject: SUBJECT,
        redirectUris: [REDIRECT_URI],
      };
    }
    if (token === OWNER_TOKEN) {
      return { role: "owner", clientId: "demo-owner-console", subject: SUBJECT, redirectUris: [] };
    }
    if (pairedDevices.has(token)) {
      return { role: "owner", clientId: "demo-paired-phone", subject: SUBJECT, redirectUris: [] };
    }
    return null;
  },
};

/** REPLACE: this is NOT encryption; a deployment injects KMS/HSM sealing. */
const KMS_PREFIX = "demo-not-encrypted:v1:";
const kms = {
  async encrypt(plaintext) {
    return KMS_PREFIX + Buffer.from(plaintext, "utf8").toString("base64");
  },
  async decrypt(reference) {
    if (!reference.startsWith(KMS_PREFIX)) throw new Error("unknown ciphertext reference");
    return Buffer.from(reference.slice(KMS_PREFIX.length), "base64").toString("utf8");
  },
};

const refusal = (outgoing, status, code) => {
  outgoing.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  outgoing.end(JSON.stringify({ error: { code } }));
};

/**
 * POST /native/pairings {pairingCode, deviceToken} — the pairing code IS the
 * authentication for this one call. One-shot: consumed on success; a second
 * use, an unknown code, and an expired code are indistinguishable refusals.
 */
async function handlePairing(body, outgoing) {
  let parsed;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    return refusal(outgoing, 400, "pairing_request_invalid");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Object.keys(parsed).sort().join(",") !== "deviceToken,pairingCode" ||
    typeof parsed.pairingCode !== "string" ||
    typeof parsed.deviceToken !== "string" ||
    !DEVICE_TOKEN_SHAPE.test(parsed.deviceToken)
  ) {
    return refusal(outgoing, 400, "pairing_request_invalid");
  }
  const normalized = parsed.pairingCode.replace(/[\s-]/gu, "").toUpperCase();
  const hash = await sha256Base64Url(normalized);
  if (hash !== pairing.codeHash || pairing.consumed || Date.now() >= pairing.expiresAt) {
    return refusal(outgoing, 401, "pairing_invalid");
  }
  pairing.consumed = true;
  const deviceCredential = randomBytes(32).toString("base64url");
  pairedDevices.set(deviceCredential, parsed.deviceToken.toLowerCase());
  say("  pairing          phone paired; device-scoped owner credential issued");
  outgoing.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
  outgoing.end(JSON.stringify({ deviceCredential }));
}

/** node:http request/response ↔ Fetch Request/Response, plus the pairing route. */
function listener(handler) {
  return (incoming, outgoing) => {
    const chunks = [];
    incoming.on("data", (chunk) => chunks.push(chunk));
    incoming.on("end", () => {
      const url = new URL(incoming.url, `http://${incoming.headers.host ?? "127.0.0.1"}`);
      const body = chunks.length === 0 ? null : Buffer.concat(chunks);
      if (url.pathname === "/native/pairings") {
        if (incoming.method !== "POST") return refusal(outgoing, 405, "pairing_request_invalid");
        handlePairing(body ?? Buffer.alloc(0), outgoing).catch(() =>
          refusal(outgoing, 500, "pairing_failed"),
        );
        return;
      }
      const headers = [];
      for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
        headers.push([incoming.rawHeaders[index], incoming.rawHeaders[index + 1]]);
      }
      handler(new Request(url, { method: incoming.method, headers, ...(body ? { body } : {}) }))
        .then(async (response) => {
          outgoing.writeHead(response.status, Object.fromEntries(response.headers));
          outgoing.end(Buffer.from(await response.arrayBuffer()));
        })
        .catch(() => refusal(outgoing, 500, "adapter_failed"));
    });
  };
}

// ---------------------------------------------------------------------------
// Start the relay and the "web app" callback listener.
// ---------------------------------------------------------------------------

const store = createMemoryRelayStore();
const handler = createRelayHandler({
  store,
  authentication,
  kms,
  clock: { now: () => Date.now() },
});
const relayServer = createServer(listener(handler));
await new Promise((resolve) => relayServer.listen(PORT, HOST, resolve));
const relayPort = relayServer.address().port;

let resolveCode;
const codeArrived = new Promise((resolve) => {
  resolveCode = resolve;
});
const callbackServer = createServer((incoming, outgoing) => {
  const url = new URL(incoming.url, `http://${incoming.headers.host ?? "127.0.0.1"}`);
  if (url.pathname === "/callback" && url.searchParams.has("code")) {
    outgoing.writeHead(200, { "content-type": "text/plain" });
    outgoing.end("Code received - return to the terminal.\n");
    resolveCode(url.searchParams.get("code"));
    return;
  }
  outgoing.writeHead(404, { "content-type": "text/plain" });
  outgoing.end("not found\n");
});
await new Promise((resolve) => callbackServer.listen(CALLBACK_PORT, HOST, resolve));
const callbackPort = callbackServer.address().port;

const phoneHost = SIMULATE ? "127.0.0.1" : (lanIp() ?? "127.0.0.1");
const RELAY_URL = `http://${phoneHost}:${relayPort}`;
const REDIRECT_URI = `http://${phoneHost}:${callbackPort}/callback`;

say("");
say("OAAth owner-phone demo (web half)");
say(`relay            ${RELAY_URL} (bound to ${HOST})`);
say(`web app callback ${REDIRECT_URI}`);
if (HOST === "0.0.0.0") {
  say("WARNING          demo binding on 0.0.0.0 with demo tokens: anyone on this");
  say("                 network can hit the relay. Trusted network only.");
}
const foundOptIn = OPT_IN_VARS.filter((name) => process.env[name] !== undefined);
if (foundOptIn.length > 0) {
  say(`opt-in env       found (names only): ${foundOptIn.join(", ")}`);
}
say("");

// ---------------------------------------------------------------------------
// The authorization request: PKCE + a real protocol permission scope, so the
// phone renders structured consent (client, calls, limits, expiry).
// ---------------------------------------------------------------------------

const call = async (label, method, path, token, body) => {
  const response = await fetch(`http://127.0.0.1:${relayPort}${path}`, {
    method,
    headers: {
      ...(token === null ? {} : { authorization: `Bearer ${token}` }),
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const payload = await response.json();
  say(`  ${label.padEnd(16)} ${response.status} ${JSON.stringify(payload).slice(0, 96)}`);
  return { status: response.status, payload };
};

const nowSeconds = Math.floor(Date.now() / 1000);
/** The scope the owner consents to: one ERC-20 transfer target, tight limits. */
const requestedScope = {
  version: "oaath.permission-request/v1",
  application: {
    applicationId: "oaath-phone-demo",
    clientId: CLIENT_ID,
    origin: "https://demo.oaath.example",
    deviceId: "demo-web-device",
  },
  chainScope: "all",
  logicalAccount: {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "1",
    kernelVersion: "0.4.0",
    factoryRoute: "meta_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"aa".repeat(20)}`,
    },
  },
  operatorCredential: {
    version: "oaath.operator-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"bb".repeat(20)}`,
  },
  policy: {
    version: "oaath.grant-policy/v1",
    calls: [
      {
        target: `0x${"11".repeat(20)}`,
        selector: "0xa9059cbb", // ERC-20 transfer(address,uint256)
        valueLimit: "0",
        argumentEquals: [],
      },
    ],
    validAfter: nowSeconds,
    validUntil: nowSeconds + 3_540,
    perChainOperationLimit: 3,
  },
  requestedAt: nowSeconds,
  expiresAt: nowSeconds + 3_600,
};

const created = await call("create request", "POST", "/authorization/requests", CLIENT_TOKEN, {
  redirectUri: REDIRECT_URI,
  codeChallenge: deriveCodeChallenge(CODE_VERIFIER),
  requestedScope: JSON.stringify(requestedScope),
});
expect(created.status === 201, "the client could not create an authorization request");
const { requestId } = created.payload;

// The expected display payload, computed the same way the phone will see it:
// through the preview projection route, with an owner credential.
const projected = await call(
  "project consent",
  "GET",
  `/native/projections/${requestId}`,
  OWNER_TOKEN,
);
expect(projected.status === 200, "the owner could not project the request");
const matchCode = projected.payload.displayPayload;
expect(
  projected.payload.scope.kind === "permission-request",
  "the phone would not receive structured consent",
);

say("");
say("================= HAND THIS TO YOUR PHONE =================");
say(`  pairing code      ${PAIRING_CODE}   (one-shot, expires in 10 minutes)`);
say(`  relay URL         ${RELAY_URL}`);
say(`  operation id      ${requestId}`);
say(`  match code        ${matchCode}`);
say("  What your phone must show: the match code above, split as");
say(`  "${matchCode.slice(0, 4)} ${matchCode.slice(4)}", plus this consent scope:`);
say(`    client          ${CLIENT_ID} -> ${REDIRECT_URI}`);
say("    chain scope     all chains");
say(`    permitted call  ${requestedScope.policy.calls[0].target}`);
say("                    selector 0xa9059cbb (ERC-20 transfer), value limit 0 wei");
say(`    operation limit ${requestedScope.policy.perChainOperationLimit} per chain`);
say("============================================================");
say("");
say("  On the iPhone (native/ios/Demo/README.md):");
say("    1. Pair: enter the relay URL and the pairing code.");
say("    2. Open the request: tap the push notification, or paste the");
say("       operation id under 'Open request'.");
say("    3. Compare the match code, review the consent, then Approve");
say("       or Reject - both are explicit buttons; nothing auto-decides.");
say("");

// ---------------------------------------------------------------------------
// Optional real APNs push, Apple SANDBOX host. Opt-in via env vars at runtime
// (never a gate; gates scrub APNS_*/APPLE_*). Exactly one send per request.
// ---------------------------------------------------------------------------

async function pushProjection() {
  const pem =
    process.env.APNS_KEY_PEM ??
    (process.env.APNS_KEY_PEM_PATH ? readFileSync(process.env.APNS_KEY_PEM_PATH, "utf8") : "");
  const keyId = process.env.APNS_KEY_ID ?? "";
  const teamId = process.env.APPLE_TEAM_ID ?? "";
  const topic = process.env.APNS_TOPIC ?? "";
  if (pem === "" || keyId === "" || teamId === "" || topic === "") {
    say("  push             skipped (set APNS_KEY_PEM or APNS_KEY_PEM_PATH, APNS_KEY_ID,");
    say("                   APPLE_TEAM_ID, APNS_TOPIC). Paste the operation id instead.");
    return;
  }
  say("  push             waiting for a paired device token...");
  const deadline = Date.now() + WAIT_MS;
  while (pairedDevices.size === 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  const deviceToken = [...pairedDevices.values()][0];
  if (deviceToken === undefined) {
    say("  push             no device paired in time; paste the operation id instead");
    return;
  }
  const sender = createApnsSender({
    credentials: { privateKeyPem: pem, keyId, teamId, topic },
    clock: { now: () => Date.now() },
  });
  // Only the opaque push subset may transit Apple - never client or scope.
  const notification = sender.notification({
    deviceToken,
    projection: {
      operationId: projected.payload.operationId,
      displayPayload: projected.payload.displayPayload,
      expiresAt: projected.payload.expiresAt,
    },
  });
  // SANDBOX on purpose: dev-signed apps receive SANDBOX device tokens. Using
  // api.push.apple.com (production) here is the classic silent failure.
  const session = connect("https://api.sandbox.push.apple.com:443");
  const outcome = await sendApnsNotification({ session, notification, timeoutMs: 10_000 });
  session.close();
  switch (outcome.kind) {
    case "delivered":
      say("  push             delivered - check the iPhone");
      break;
    case "rejected":
      say(`  push             rejected by Apple (${outcome.status} ${outcome.reason});`);
      say("                   check APNS_TOPIC = the app's bundle id, and the key/team ids");
      break;
    case "unavailable":
      say("  push             Apple unavailable; paste the operation id instead");
      break;
    default:
      say("  push             outcome unreadable (may still arrive); watch the iPhone");
  }
}

// ---------------------------------------------------------------------------
// Simulate mode: drive the phone's half over HTTP so the loop runs unattended.
// ---------------------------------------------------------------------------

async function simulatePhone() {
  say("  simulate         driving the phone's half over HTTP (no Apple contact)");
  const fakeDeviceToken = "ab".repeat(32);
  const paired = await call("pair", "POST", "/native/pairings", null, {
    pairingCode: PAIRING_CODE,
    deviceToken: fakeDeviceToken,
  });
  expect(paired.status === 200, "pairing must succeed once");
  const deviceCredential = paired.payload.deviceCredential;
  expect(typeof deviceCredential === "string" && deviceCredential.length > 0, "no credential");

  const replayedPairing = await call("pair replay", "POST", "/native/pairings", null, {
    pairingCode: PAIRING_CODE,
    deviceToken: fakeDeviceToken,
  });
  expect(replayedPairing.status === 401, "a pairing code must be one-shot");

  const projection = await call(
    "phone projects",
    "GET",
    `/native/projections/${requestId}`,
    deviceCredential,
  );
  expect(projection.status === 200, "the paired device could not project the request");
  expect(projection.payload.displayPayload === matchCode, "match codes must agree");

  const unpaired = await call(
    "stale credential",
    "GET",
    `/native/projections/${requestId}`,
    "nope",
  );
  expect(unpaired.status === 401, "an unknown credential must be refused");

  const decided = await call(
    "phone approves",
    "POST",
    `/native/decisions/${requestId}`,
    deviceCredential,
    {
      command: "approve",
      artifact: "demo-owner-phone-approval:v1:placeholder-artifact",
    },
  );
  expect(decided.status === 200 && decided.payload.settlement === "decided", "not decided");
  const release = decided.payload.release;
  expect(release !== null && typeof release.code === "string", "no one-time release");

  const replayedDecision = await call(
    "decide replay",
    "POST",
    `/native/decisions/${requestId}`,
    deviceCredential,
    { command: "reject" },
  );
  expect(
    replayedDecision.payload.settlement === "replayed" &&
      replayedDecision.payload.outcome === "approved" &&
      replayedDecision.payload.release === null,
    "a replay must answer the stored outcome and release nothing",
  );

  // The phone's delivery step: GET redirectUri?code=<released code>.
  const delivery = await fetch(`${release.redirectUri}?code=${release.code}`);
  expect(delivery.status === 200, "the web app did not accept the code");
}

if (SIMULATE) {
  await simulatePhone();
} else {
  await pushProjection();
  say(`  waiting          up to ${Math.round(WAIT_MS / 60_000)} minutes for the phone...`);
}

// ---------------------------------------------------------------------------
// The web app's half: receive the code, consume it (PKCE), claim the sealed
// artifact once, and prove the one-shot semantics.
// ---------------------------------------------------------------------------

let waitTimer;
const code = await Promise.race([
  codeArrived,
  new Promise((_, reject) => {
    waitTimer = setTimeout(
      () => reject(new Error("timed out waiting for the phone's approval")),
      WAIT_MS,
    );
  }),
]);
clearTimeout(waitTimer);
say("");
say("  code arrived     the phone delivered the one-time code");

const consumed = await call("consume code", "POST", "/authorization/codes/consume", CLIENT_TOKEN, {
  code,
  codeVerifier: CODE_VERIFIER,
  redirectUri: REDIRECT_URI,
});
expect(consumed.payload.requestId === requestId, "the code released another request");

const claimed = await call(
  "claim artifact",
  "POST",
  `/authorization/artifacts/${consumed.payload.artifactId}/claim`,
  CLIENT_TOKEN,
);
expect(typeof claimed.payload.artifact === "string", "the sealed artifact was not released");

const replayedClaim = await call(
  "replay claim",
  "POST",
  `/authorization/artifacts/${consumed.payload.artifactId}/claim`,
  CLIENT_TOKEN,
);
expect(replayedClaim.status >= 400, "a claimed artifact must never be released twice");
expect(
  typeof replayedClaim.payload.error?.code === "string",
  "a refusal must carry a structured code",
);

// The decision saga stays replay-only after the fact, on any owner credential.
const replayedDecision = await call(
  "decide replay",
  "POST",
  `/native/decisions/${requestId}`,
  OWNER_TOKEN,
  { command: "approve", artifact: "ignored-on-replay" },
);
expect(
  replayedDecision.payload.settlement === "replayed" && replayedDecision.payload.release === null,
  "a decision replay must answer the stored outcome and release nothing",
);

say("");
say("  success - the full loop held:");
say("    pairing was one-shot, the phone held its own credential,");
say("    the consent the phone displayed is exactly what was authorized,");
say("    the code and artifact released once, and every replay was refused.");

await new Promise((resolve) => callbackServer.close(resolve));
await new Promise((resolve) => relayServer.close(resolve));
await store.close();
