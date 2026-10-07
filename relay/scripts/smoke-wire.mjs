/**
 * Wire parity smoke: drives the same authorization journey, and the same
 * refusals, over real HTTP against the TypeScript reference relay
 * (`examples/server/run.mjs`) and the Rust `oaath-relay` binary, then asserts
 * that every step answers the same status, headers, and body shape.
 *
 * Run from the repository root:
 *
 *   node --import ./examples/support/workspace-typescript.mjs relay/scripts/smoke-wire.mjs
 *
 * Dynamic values (identifiers, codes, timestamps, hashes) are compared by type;
 * enums, error codes, and booleans are compared exactly. Both relays verify
 * the same real `@oaath/protocol` permission artifacts. Nothing secret is
 * printed.
 */

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const CARGO = process.env.CARGO ?? join(process.env.HOME, ".cargo/bin/cargo");
const { deriveCodeChallenge, hashPermissionRequest, parsePermissionRequest } = await import(
  pathToFileURL(join(ROOT, "packages/protocol/src/index.ts")).href
);

const CLIENT = "demo-client-token";
const OWNER = "demo-owner-token";
const REDIRECT_URI = "https://app.example/callback";
const CODE_VERIFIER = "demo-code-verifier-that-is-long-enough-0123456789";

function freePort() {
  return new Promise((done, fail) => {
    const server = createServer();
    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => done(port));
    });
  });
}

async function waitFor(origin, child) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`relay exited with ${child.exitCode}`);
    try {
      await fetch(`${origin}/`);
      return;
    } catch {
      await new Promise((done) => setTimeout(done, 100));
    }
  }
  throw new Error(`relay at ${origin} never answered`);
}

async function startTypeScript() {
  const port = await freePort();
  const child = spawn(
    process.execPath,
    ["--import", "./support/workspace-typescript.mjs", "server/run.mjs"],
    {
      cwd: join(ROOT, "examples"),
      env: { ...process.env, OAATH_PORT: String(port) },
      stdio: "ignore",
    },
  );
  const origin = `http://127.0.0.1:${port}`;
  await waitFor(origin, child);
  return { origin, child };
}

async function startRust() {
  const build = spawn(CARGO, ["build", "-q", "-p", "oaath-relay", "--bin", "oaath-relay"], {
    cwd: join(ROOT, "relay"),
    stdio: "inherit",
  });
  if ((await new Promise((done) => build.on("exit", done))) !== 0) throw new Error("build failed");
  const port = await freePort();
  const directory = mkdtempSync(join(tmpdir(), "oaath-relay-smoke-"));
  const config = join(directory, "config.json");
  // Mirrors examples/server/run.mjs: the same tokens, callers, and owner route.
  writeFileSync(
    config,
    JSON.stringify({
      tokens: {
        [CLIENT]: {
          role: "client",
          clientId: "demo-client",
          subject: "demo-subject",
          redirectUris: [REDIRECT_URI],
        },
        [OWNER]: {
          role: "owner",
          clientId: "demo-owner-console",
          subject: "demo-subject",
          redirectUris: [],
        },
      },
      ownerRoute: { ownerDeviceId: "demo-owner", ownerSubject: "demo-subject" },
    }),
  );
  const child = spawn(join(ROOT, "relay/target/debug/oaath-relay"), [], {
    env: {
      ...process.env,
      OAATH_LISTEN: `127.0.0.1:${port}`,
      OAATH_KMS_KEY: randomBytes(32).toString("hex"),
      OAATH_CONFIG: config,
      OAATH_POSTGRES_URL: "",
      RUST_LOG: "warn",
    },
    stdio: "ignore",
  });
  const origin = `http://127.0.0.1:${port}`;
  await waitFor(origin, child);
  return { origin, child };
}

/** Enums and structured codes keep their value; other leaves reduce to their type. */
const LITERAL_KEYS = new Set(["outcome", "state"]);
const STRUCTURED_CODE = /^(relay|grant)_[a-z_]+$/u;

function shape(value, key = "") {
  if (Array.isArray(value)) return value.map((item) => shape(item));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, shape(v, k)]));
  }
  if (LITERAL_KEYS.has(key) || typeof value === "boolean" || value === null) return value;
  if (key === "code" && STRUCTURED_CODE.test(value)) return value;
  return typeof value;
}

function scope() {
  const requestedAt = Math.floor(Date.now() / 1_000);
  return JSON.stringify({
    version: "oaath.permission-request/v2",
    context: {
      version: "oaath.workspace-account-context/v1",
      workspaceId: "personal-1",
      workspaceKind: "personal",
      accountId: "account-1",
    },
    application: {
      applicationId: "oaath-relay-demo",
      clientId: "demo-client",
      origin: "https://app.example",
      deviceId: "relay-demo-device",
    },
    chainScope: "all",
    logicalAccount: {
      version: "oaath.kernel-account-profile/v1",
      kind: "kernel",
      accountIndex: "0",
      kernelVersion: "0.4.0",
      factoryRoute: "meta_factory",
      entryPoint: { version: "0.9" },
      ownerCredential: {
        version: "oaath.owner-credential-profile/v1",
        kind: "ecdsa",
        address: `0x${"33".repeat(20)}`,
      },
    },
    operatorCredential: {
      version: "oaath.operator-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"44".repeat(20)}`,
    },
    policy: {
      version: "oaath.grant-policy/v2",
      calls: [
        {
          target: `0x${"11".repeat(20)}`,
          selector: "0x12345678",
          valueLimit: "0",
          argumentEquals: [],
        },
      ],
      validAfter: requestedAt,
      validUntil: requestedAt + 599,
      perChainOperationLimit: { count: 10, intervalSeconds: null },
    },
    requestedAt,
    expiresAt: requestedAt + 600,
    sessionSigner: null,
  });
}

function artifactFor(requestedScope, requestId) {
  const permission = parsePermissionRequest({ ...JSON.parse(requestedScope), requestId });
  return JSON.stringify({
    version: "oaath.permission-decision/v1",
    kind: "approve",
    requestId,
    requestHash: hashPermissionRequest(permission),
    decidedAt: Math.floor(Date.now() / 1_000),
    approvedPolicy: permission.policy,
    capabilityHash: `0x${"ab".repeat(32)}`,
  });
}

/** One journey; returns the observed steps and checks its own invariants. */
async function journey(origin) {
  const steps = [];
  const call = async (label, method, path, token, body, contentType = "application/json") => {
    const headers = {};
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined) headers["content-type"] = contentType;
    const response = await fetch(`${origin}${path}`, {
      method,
      headers,
      ...(body === undefined
        ? {}
        : { body: typeof body === "string" ? body : JSON.stringify(body) }),
    });
    const payload = await response.json();
    steps.push({
      label,
      status: response.status,
      contentType: response.headers.get("content-type"),
      cacheControl: response.headers.get("cache-control"),
      shape: shape(payload),
    });
    return payload;
  };
  const check = (condition, message) => {
    if (!condition) throw new Error(`${origin}: ${message}`);
  };
  const requestedScope = scope();
  const challenge = deriveCodeChallenge(CODE_VERIFIER);
  const createBody = { redirectUri: REDIRECT_URI, codeChallenge: challenge, requestedScope };
  const create = (label) => call(label, "POST", "/authorization/requests", CLIENT, createBody);

  await call("create unauthenticated", "POST", "/authorization/requests", null, createBody);
  await call("create as owner", "POST", "/authorization/requests", OWNER, createBody);
  await call("create unknown key", "POST", "/authorization/requests", CLIENT, {
    ...createBody,
    extra: 1,
  });
  await call("create foreign redirect", "POST", "/authorization/requests", CLIENT, {
    ...createBody,
    redirectUri: "https://attacker.example/callback",
  });
  await call("create not json", "POST", "/authorization/requests", CLIENT, "{not json");
  await call(
    "create text/plain",
    "POST",
    "/authorization/requests",
    CLIENT,
    createBody,
    "text/plain",
  );
  await call("create short challenge", "POST", "/authorization/requests", CLIENT, {
    ...createBody,
    codeChallenge: "short",
  });

  const { requestId } = await create("create");
  await call("owner fetch", "GET", `/authorization/requests/${requestId}`, OWNER);
  await call("client fetch", "GET", `/authorization/requests/${requestId}`, CLIENT);
  await call("fetch unknown", "GET", "/authorization/requests/unknown-id", OWNER);
  await call("fetch non-canonical", "GET", "/authorization/requests/not%20canonical", OWNER);
  await call("pickup pending", "GET", `/authorization/requests/${requestId}/code`, CLIENT);
  await call(
    "approve unbound artifact",
    "POST",
    `/authorization/requests/${requestId}/decision`,
    OWNER,
    {
      outcome: "approved",
      artifact: artifactFor(requestedScope, "another-request"),
    },
  );
  await call("decision bad shape", "POST", `/authorization/requests/${requestId}/decision`, OWNER, {
    outcome: "rejected",
    subject: "demo-subject",
  });
  const artifact = artifactFor(requestedScope, requestId);
  const approved = await call(
    "approve",
    "POST",
    `/authorization/requests/${requestId}/decision`,
    OWNER,
    {
      outcome: "approved",
      artifact,
    },
  );
  await call("decide again", "POST", `/authorization/requests/${requestId}/decision`, OWNER, {
    outcome: "rejected",
  });
  const picked = await call(
    "pickup approved",
    "GET",
    `/authorization/requests/${requestId}/code`,
    CLIENT,
  );
  check(picked.code === approved.code, "pickup released another code");
  const consumed = await call("consume", "POST", "/authorization/codes/consume", CLIENT, {
    code: approved.code,
    codeVerifier: CODE_VERIFIER,
    redirectUri: REDIRECT_URI,
  });
  check(consumed.requestId === requestId, "consume released another request");
  await call("consume again", "POST", "/authorization/codes/consume", CLIENT, {
    code: approved.code,
    codeVerifier: CODE_VERIFIER,
    redirectUri: REDIRECT_URI,
  });
  await call("consume guessed", "POST", "/authorization/codes/consume", CLIENT, {
    code: "unknown-code",
    codeVerifier: CODE_VERIFIER,
    redirectUri: REDIRECT_URI,
  });
  const claimed = await call(
    "claim",
    "POST",
    `/authorization/artifacts/${consumed.artifactId}/claim`,
    CLIENT,
  );
  check(claimed.artifact === artifact, "claim released another artifact");
  await call(
    "claim replay",
    "POST",
    `/authorization/artifacts/${consumed.artifactId}/claim`,
    CLIENT,
  );
  await call("resume", "POST", "/authorization/resume", CLIENT, { requestId });
  await call("resume unknown", "POST", "/authorization/resume", CLIENT, { requestId: "unknown" });
  await call(
    "withdraw approved",
    "POST",
    `/authorization/requests/${requestId}/withdraw`,
    CLIENT,
    {},
  );

  const burned = (await create("create burned")).requestId;
  const burnedDecision = await call(
    "approve burned",
    "POST",
    `/authorization/requests/${burned}/decision`,
    OWNER,
    {
      outcome: "approved",
      artifact: artifactFor(requestedScope, burned),
    },
  );
  await call("consume wrong verifier", "POST", "/authorization/codes/consume", CLIENT, {
    code: burnedDecision.code,
    codeVerifier: `${CODE_VERIFIER.slice(0, -1)}X`,
    redirectUri: REDIRECT_URI,
  });
  await call("consume burned", "POST", "/authorization/codes/consume", CLIENT, {
    code: burnedDecision.code,
    codeVerifier: CODE_VERIFIER,
    redirectUri: REDIRECT_URI,
  });
  await call(
    "claim voided",
    "POST",
    `/authorization/artifacts/${burnedDecision.artifactId}/claim`,
    CLIENT,
  );

  const rejected = (await create("create rejected")).requestId;
  await call("reject", "POST", `/authorization/requests/${rejected}/decision`, OWNER, {
    outcome: "rejected",
  });
  await call("pickup rejected", "GET", `/authorization/requests/${rejected}/code`, CLIENT);
  const withdrawn = (await create("create withdrawn")).requestId;
  await call("withdraw", "POST", `/authorization/requests/${withdrawn}/withdraw`, CLIENT, {});
  await call("pickup withdrawn", "GET", `/authorization/requests/${withdrawn}/code`, CLIENT);

  const invalidation = { grantId: "grant-1", capabilityHash: `0x${"ab".repeat(32)}` };
  const first = await call("invalidate", "POST", "/invalidations", CLIENT, invalidation);
  const replay = await call("invalidate replay", "POST", "/invalidations", CLIENT, invalidation);
  check(JSON.stringify(first) === JSON.stringify(replay), "invalidation replay changed evidence");
  await call("invalidate bad hash", "POST", "/invalidations", CLIENT, {
    ...invalidation,
    capabilityHash: "0x01",
  });
  await call("verify unknown grant", "POST", "/grants/verify", CLIENT, {
    grantId: "no-such-grant",
    revision: 1,
    subject: "demo-subject",
    clientId: "demo-client",
    organizationAudience: "org-1",
    requiredCallsDigest: `0x${"cd".repeat(32)}`,
  });
  await call("verify malformed", "POST", "/grants/verify", CLIENT, { grantId: requestId });
  const assertion = {
    grantId: requestId,
    revision: 1,
    subject: "demo-subject",
    clientId: "demo-client",
    organizationAudience: "org-1",
    requiredCallsDigest: `0x${"cd".repeat(32)}`,
  };
  // The demo deployment declares no audience, so the approved grant denies.
  await call("verify approved grant", "POST", "/grants/verify", CLIENT, assertion);
  await call("verify rejected grant", "POST", "/grants/verify", CLIENT, {
    ...assertion,
    grantId: rejected,
  });
  await call(
    "verify negative zero",
    "POST",
    "/grants/verify",
    CLIENT,
    JSON.stringify(assertion).replace('"revision":1', '"revision":-0'),
  );

  await call("unknown route", "GET", "/", OWNER);
  await call("wrong method", "GET", "/authorization/requests", CLIENT);
  await call("bootstrap unconfigured", "GET", "/bootstrap", CLIENT);
  // `/native/*` is always served by the TypeScript relay; the Rust relay answers
  // relay_not_found there until the owner-phone stage, so it is not compared.
  await call("chains wrong method", "GET", "/chains/1/reads", CLIENT);
  await call("chains unconfigured", "POST", "/chains/1/reads", CLIENT, { request: {} });
  return steps;
}

const relays = [];
try {
  relays.push(await startTypeScript());
  relays.push(await startRust());
  const [typescript, rust] = [await journey(relays[0].origin), await journey(relays[1].origin)];
  let mismatches = 0;
  for (const [index, expected] of typescript.entries()) {
    const actual = rust[index];
    const same = JSON.stringify(expected) === JSON.stringify(actual);
    if (!same) mismatches += 1;
    console.log(
      `  ${same ? "same" : "DIFF"}  ${String(expected.status).padEnd(4)} ${expected.label}`,
    );
    if (!same) {
      console.log(`        typescript ${JSON.stringify(expected)}`);
      console.log(`        rust       ${JSON.stringify(actual)}`);
    }
  }
  if (mismatches > 0 || typescript.length !== rust.length) {
    throw new Error(`${mismatches} wire mismatches`);
  }
  console.log(`\nsmoke-wire       ok — ${typescript.length} steps answered identically`);
} finally {
  for (const relay of relays) relay.child.kill("SIGTERM");
}
