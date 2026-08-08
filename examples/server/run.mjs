/**
 * A deployable OAAth authorization relay: Fetch handler, PostgreSQL boundary,
 * and the two ports every deployment owns.
 *
 * `createRelayHandler` is a `(Request) => Promise<Response>` function, so the
 * only server-specific code here is a ~25 line `node:http` adapter. The relay
 * itself owns the wire contract, the state machine, and the one-time release of
 * the encrypted artifact; this file owns the four things a deployment owns:
 *
 *   1. the durable store — memory by default, PostgreSQL with `OAATH_POSTGRES_URL`;
 *   2. the authentication port — who is a client and who is the owner;
 *   3. the KMS port — the artifact is sealed before it reaches the store;
 *   4. the clock.
 *
 * Both port implementations here are stubs. They are honest about being stubs:
 * every line a deployment must replace carries a `REPLACE` comment. See
 * ./README.md for the curl walkthrough.
 *
 * @author taek <leekt216@gmail.com>
 */

import { createServer } from "node:http";
import { deriveCodeChallenge } from "@oaath/protocol";
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";

const PORT = Number(process.env.OAATH_PORT ?? 8787);
const POSTGRES_URL = process.env.OAATH_POSTGRES_URL ?? "";
/** Smoke mode drives the whole round-trip against itself, then exits. */
const SMOKE = process.env.OAATH_SMOKE === "1";

/** REPLACE: real deployments authenticate clients and owners, not fixed strings. */
const CLIENT_TOKEN = "demo-client-token";
const OWNER_TOKEN = "demo-owner-token";
const CLIENT_ID = "demo-client";
const SUBJECT = "demo-subject";
const REDIRECT_URI = "https://app.example/callback";
/** PKCE: the client keeps the verifier and sends only the challenge. */
const CODE_VERIFIER = "demo-code-verifier-that-is-long-enough-0123456789";
const REQUESTED_AT = Math.floor(Date.now() / 1_000);
/** One exact protocol scope the shared decision owner can approve. */
const DEMO_PERMISSION_SCOPE = JSON.stringify({
  version: "oaath.permission-request/v1",
  application: {
    applicationId: "oaath-relay-demo",
    clientId: CLIENT_ID,
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
    entryPoint: { version: "0.7" },
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
    version: "oaath.grant-policy/v1",
    calls: [
      {
        target: `0x${"11".repeat(20)}`,
        selector: "0x12345678",
        valueLimit: "0",
        argumentEquals: [],
      },
    ],
    validAfter: REQUESTED_AT,
    validUntil: REQUESTED_AT + 599,
    perChainOperationLimit: 10,
  },
  requestedAt: REQUESTED_AT,
  expiresAt: REQUESTED_AT + 600,
});

const say = (...parts) => console.log(...parts);

async function openStore() {
  if (POSTGRES_URL === "") {
    say("store            memory (set OAATH_POSTGRES_URL for PostgreSQL)");
    return createMemoryRelayStore();
  }
  // The subpath is Node-only on purpose, so it is imported only on this branch.
  const {
    createPostgresRelaySchema,
    createPostgresRelayStore,
    OAATH_RELAY_POSTGRES_SCHEMA_VERSION,
  } = await import("@oaath/server/postgres");
  if (process.env.OAATH_POSTGRES_CREATE_SCHEMA === "1") {
    const pg = (await import("pg")).default;
    const pool = new pg.Pool({ connectionString: POSTGRES_URL });
    // Not a migration: it fails if the objects already exist.
    await createPostgresRelaySchema(pool);
    await pool.end();
    say(`schema           created, version ${OAATH_RELAY_POSTGRES_SCHEMA_VERSION}`);
  }
  say(`store            PostgreSQL, schema ${OAATH_RELAY_POSTGRES_SCHEMA_VERSION}`);
  // A production deployment passes `{ pool }` instead and owns TLS, limits, and
  // shutdown itself.
  return createPostgresRelayStore({ connectionString: POSTGRES_URL });
}

/**
 * REPLACE: the deployment owns client and owner authentication. A real port
 * verifies a client credential, an owner session, and the device binding, and
 * returns the redirect URIs registered for that client — the relay refuses any
 * redirect URI this port did not vouch for.
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
    // `null` is a refusal. The relay maps it to a structured 401.
    return null;
  },
};

/**
 * REPLACE: this is NOT encryption. It is a reversible encoding that proves the
 * port is wired: plaintext never reaches the store, and the store only ever
 * holds what this port returned. A deployment injects KMS/HSM envelope
 * encryption here and keeps the key outside the database's blast radius.
 */
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

/** node:http request/response ↔ Fetch Request/Response. */
function listener(handler) {
  return (incoming, outgoing) => {
    const chunks = [];
    incoming.on("data", (chunk) => chunks.push(chunk));
    incoming.on("end", () => {
      const headers = [];
      for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
        headers.push([incoming.rawHeaders[index], incoming.rawHeaders[index + 1]]);
      }
      const url = new URL(incoming.url, `http://${incoming.headers.host ?? "127.0.0.1"}`);
      const body = chunks.length === 0 ? null : Buffer.concat(chunks);
      handler(new Request(url, { method: incoming.method, headers, ...(body ? { body } : {}) }))
        .then(async (response) => {
          outgoing.writeHead(response.status, Object.fromEntries(response.headers));
          outgoing.end(Buffer.from(await response.arrayBuffer()));
        })
        .catch(() => {
          // The relay maps its own failures to structured responses, so reaching
          // here means the adapter itself failed. Disclose nothing.
          outgoing.writeHead(500, { "content-type": "application/json" });
          outgoing.end('{"error":{"code":"adapter_failed"}}');
        });
    });
  };
}

const store = await openStore();
const handler = createRelayHandler({
  store,
  authentication,
  kms,
  clock: { now: () => Date.now() },
  // No rate limiter is wired: there is no default one, and a deployment that
  // needs it injects `rateLimit` keyed on the authenticated clientId.
});

const server = createServer(listener(handler));
await new Promise((resolve) => server.listen(PORT, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

say("");
say(`OAAth relay      ${origin}`);
say(`client token     Bearer ${CLIENT_TOKEN}`);
say(`owner token      Bearer ${OWNER_TOKEN}`);
say(`code_challenge   ${deriveCodeChallenge(CODE_VERIFIER)}`);
say(`code_verifier    ${CODE_VERIFIER}`);
say(`requested scope  ${DEMO_PERMISSION_SCOPE}`);
say("");

if (!SMOKE) {
  say("Follow ./README.md for the curl walkthrough. Ctrl-C to stop.");
} else {
  /** One authorization journey over real HTTP, asserted at every step. */
  const call = async (label, method, path, token, body) => {
    const response = await fetch(`${origin}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const payload = await response.json();
    say(`  ${label.padEnd(16)} ${response.status} ${JSON.stringify(payload).slice(0, 96)}`);
    return { status: response.status, payload };
  };
  const expect = (condition, message) => {
    if (!condition) throw new Error(message);
  };

  const created = await call("create", "POST", "/authorization/requests", CLIENT_TOKEN, {
    redirectUri: REDIRECT_URI,
    codeChallenge: deriveCodeChallenge(CODE_VERIFIER),
    requestedScope: DEMO_PERMISSION_SCOPE,
  });
  expect(created.status === 201, "the client could not create an authorization request");
  const { requestId } = created.payload;

  const fetched = await call(
    "owner reads",
    "GET",
    `/authorization/requests/${requestId}`,
    OWNER_TOKEN,
  );
  expect(fetched.payload.decision === null, "an undecided request must carry no decision");

  const stolen = await call(
    "client reads",
    "GET",
    `/authorization/requests/${requestId}`,
    CLIENT_TOKEN,
  );
  expect(stolen.status === 403, "a client must not read the owner's review route");

  const approved = await call(
    "owner approves",
    "POST",
    `/authorization/requests/${requestId}/decision`,
    OWNER_TOKEN,
    { outcome: "approved", artifact: JSON.stringify({ approvedBy: "owner-console" }) },
  );
  expect(approved.payload.outcome === "approved", "the decision was not recorded as approved");

  const consumed = await call(
    "consume code",
    "POST",
    "/authorization/codes/consume",
    CLIENT_TOKEN,
    {
      code: approved.payload.code,
      codeVerifier: CODE_VERIFIER,
      redirectUri: REDIRECT_URI,
    },
  );
  expect(consumed.payload.requestId === requestId, "the code released another request");

  const claimed = await call(
    "claim artifact",
    "POST",
    `/authorization/artifacts/${consumed.payload.artifactId}/claim`,
    CLIENT_TOKEN,
  );
  expect(typeof claimed.payload.artifact === "string", "the sealed artifact was not released");

  const replayed = await call(
    "replay claim",
    "POST",
    `/authorization/artifacts/${consumed.payload.artifactId}/claim`,
    CLIENT_TOKEN,
  );
  expect(replayed.status >= 400, "a claimed artifact must never be released twice");
  expect(
    typeof replayed.payload.error?.code === "string",
    "a refusal must carry a structured code",
  );
  expect(
    !JSON.stringify(replayed.payload).includes("owner-console"),
    "a refusal must not leak the artifact",
  );

  say("");
  say(
    `smoke            ok — one-time claim refused the replay with ${replayed.payload.error.code}`,
  );
  await new Promise((resolve) => server.close(resolve));
  await store.close();
}
