/**
 * Owns: a clean tarball server consumer for the relay and PostgreSQL boundary.
 *
 * The consumer installs the packed `@oaath/server` and `@oaath/protocol` plus
 * `pg` from the registry, exactly as a deployment does, and drives the relay's
 * full wire round-trip over the in-memory store. Where the browser smoke proves
 * the platform-neutral root entry, this one proves the Node-only subpaths
 * resolve under the `node` condition without the root entry ever reaching them.
 *
 * Proven here:
 *
 *   - the root entry and the `./postgres`, `./native`, and `./apns` subpaths all
 *     resolve into `dist`, never `src`;
 *   - each subpath's packed runtime exports are exactly what the build produced;
 *   - one create, fetch, approve, consume, claim round-trip returns the sealed
 *     artifact, and a replayed claim fails closed with a structured code that
 *     leaks nothing;
 *   - `./postgres` loads the deployment's own `pg` driver and publishes its
 *     schema with no connection opened;
 *   - all four subpaths' types resolve under `nodenext` strict.
 *
 * No PostgreSQL server is contacted: `packages/server/test/postgres.test.ts`
 * owns that behind `OAATH_REQUIRE_POSTGRES`.
 *
 * @author taek <leekt216@gmail.com>
 */

import { assert, builtExports, createConsumer } from "./packed-consumer.mjs";

/** Every published entry, mapped to the built artifact it must deliver. */
const SUBPATHS = {
  "@oaath/server": "index.js",
  "@oaath/server/postgres": "postgres.js",
  "@oaath/server/native": "native.js",
  "@oaath/server/apns": "apns.js",
};

const PG_VERSION = "8.22.0";

const SMOKE = String.raw`
import { deriveCodeChallenge } from "@oaath/protocol";
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";
import { APNS_PAYLOAD_MAX_BYTES, createApnsSender } from "@oaath/server/apns";
import { NATIVE_DISPLAY_PAYLOAD_LENGTH, projectOwnerPhoneRequest } from "@oaath/server/native";
import {
  createPostgresRelaySchema,
  createPostgresRelayStore,
  OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS,
  OAATH_RELAY_POSTGRES_SCHEMA_VERSION,
} from "@oaath/server/postgres";
import pg from "pg";

function fail(message) {
  throw new Error(message);
}

const ENTRIES = [
  "@oaath/server",
  "@oaath/server/postgres",
  "@oaath/server/native",
  "@oaath/server/apns",
];
const ORIGIN = "https://relay.example";
const REDIRECT_URI = "https://app.example/callback";
const CLIENT_TOKEN = "client-token";
const OWNER_TOKEN = "owner-token";
const SUBJECT = "subject-1";
const CODE_VERIFIER = "smoke-code-verifier-that-is-long-enough-0123";
const ARTIFACT = JSON.stringify({ grant: "approved", smoke: true });
const KMS_PREFIX = "oaath-smoke-kms:v1:";

// Every entry, root and Node-only subpath alike, resolves to a built artifact.
const resolutions = {};
for (const specifier of ENTRIES) {
  const resolved = import.meta.resolve(specifier);
  if (!resolved.includes("/dist/")) fail(specifier + " did not resolve into dist: " + resolved);
  if (resolved.includes("/src/")) fail(specifier + " leaked a src path: " + resolved);
  if (!resolved.includes("/node_modules/")) fail(specifier + " escaped the consumer: " + resolved);
  resolutions[specifier] = resolved;
}

const exported = {};
for (const specifier of ENTRIES) {
  exported[specifier] = Object.keys(await import(specifier)).sort();
}

const clock = 1800000000000;

const callers = new Map([
  [
    CLIENT_TOKEN,
    { role: "client", clientId: "client-a", subject: SUBJECT, redirectUris: [REDIRECT_URI] },
  ],
  [OWNER_TOKEN, { role: "owner", clientId: "owner-console", subject: SUBJECT, redirectUris: [] }],
]);

const handler = createRelayHandler({
  store: createMemoryRelayStore(),
  authentication: {
    async authenticate(request) {
      const header = request.headers.get("authorization") ?? "";
      const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
      return callers.get(token) ?? null;
    },
  },
  kms: {
    async encrypt(plaintext) {
      return KMS_PREFIX + btoa(plaintext);
    },
    async decrypt(reference) {
      if (!reference.startsWith(KMS_PREFIX)) fail("unknown ciphertext reference");
      return atob(reference.slice(KMS_PREFIX.length));
    },
  },
  clock: { now: () => clock },
});

function request(method, path, token, body) {
  const headers = new Headers({ authorization: "Bearer " + token });
  if (body !== undefined) headers.set("content-type", "application/json");
  return new Request(ORIGIN + path, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function ok(response, status, label) {
  if (response.status !== status) {
    fail(label + " returned " + response.status + ": " + (await response.text()));
  }
  if (response.headers.get("cache-control") !== "no-store") {
    fail(label + " must not be cacheable");
  }
  return response.json();
}

// The relay's full wire round-trip: create, fetch, approve, consume, claim.
const created = await ok(
  await handler(
    request("POST", "/authorization/requests", CLIENT_TOKEN, {
      redirectUri: REDIRECT_URI,
      codeChallenge: deriveCodeChallenge(CODE_VERIFIER),
      requestedScope: JSON.stringify({ chainScope: "all" }),
    }),
  ),
  201,
  "create",
);
if (!/^[A-Za-z0-9_-]{43}$/.test(created.requestId)) fail("requestId is " + created.requestId);

const state = await ok(
  await handler(request("GET", "/authorization/requests/" + created.requestId, OWNER_TOKEN)),
  200,
  "owner fetch",
);
if (state.requestId !== created.requestId) fail("the owner read another request");
if (state.decision !== null) fail("an undecided request must carry no decision");

const approved = await ok(
  await handler(
    request("POST", "/authorization/requests/" + created.requestId + "/decision", OWNER_TOKEN, {
      outcome: "approved",
      artifact: ARTIFACT,
    }),
  ),
  200,
  "approve",
);
if (approved.outcome !== "approved") fail("decision outcome is " + approved.outcome);

const consumed = await ok(
  await handler(
    request("POST", "/authorization/codes/consume", CLIENT_TOKEN, {
      code: approved.code,
      codeVerifier: CODE_VERIFIER,
      redirectUri: REDIRECT_URI,
    }),
  ),
  200,
  "consume",
);
if (consumed.requestId !== created.requestId) fail("the code released another request");

const claimed = await ok(
  await handler(
    request("POST", "/authorization/artifacts/" + consumed.artifactId + "/claim", CLIENT_TOKEN),
  ),
  200,
  "claim",
);
if (claimed.artifact !== ARTIFACT) fail("the claimed artifact is not the sealed artifact");
if (claimed.requestId !== created.requestId) fail("the artifact belongs to another request");

// One-time claim: the replay must fail closed and disclose nothing.
const replayed = await handler(
  request("POST", "/authorization/artifacts/" + consumed.artifactId + "/claim", CLIENT_TOKEN),
);
if (replayed.status < 400) fail("a claimed artifact was released twice");
const replayBody = await replayed.json();
if (typeof replayBody.error?.code !== "string") fail("a failure must carry a structured code");
if (JSON.stringify(replayBody).includes("approved")) fail("a failure leaked the artifact");

// The PostgreSQL subpath owns the driver and the schema; nothing connects here.
if (typeof pg.Pool !== "function") fail("the consumer could not load the pg driver");
if (typeof createPostgresRelayStore !== "function") fail("createPostgresRelayStore is missing");
if (OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS.length < 1) fail("the relay schema is empty");
const statements = [];
await createPostgresRelaySchema({
  async query(statement) {
    statements.push(statement);
    return null;
  },
});
if (statements.join("\n") !== OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS.join("\n")) {
  fail("createPostgresRelaySchema did not execute its published statements");
}

// The experimental previews resolve and stay callable behind their own subpaths.
if (typeof NATIVE_DISPLAY_PAYLOAD_LENGTH !== "number") fail("the native preview is unusable");
if (typeof projectOwnerPhoneRequest !== "function") fail("projectOwnerPhoneRequest is missing");
if (typeof APNS_PAYLOAD_MAX_BYTES !== "number") fail("the apns preview is unusable");
if (typeof createApnsSender !== "function") fail("createApnsSender is missing");

process.stdout.write(
  JSON.stringify({
    resolutions,
    exported,
    replayCode: replayBody.error.code,
    replayStatus: replayed.status,
    schemaVersion: OAATH_RELAY_POSTGRES_SCHEMA_VERSION,
    schemaStatements: statements.length,
  }),
);
`;

/** All four subpaths must resolve and compose under `nodenext` strict. */
const TYPES = `import { deriveCodeChallenge } from "@oaath/protocol";
import {
  createMemoryRelayStore,
  createRelayHandler,
  type RelayClock,
  type RelayHandler,
  type RelayStore,
} from "@oaath/server";
import {
  APNS_PAYLOAD_MAX_BYTES,
  createApnsSender,
  createMemoryApnsOutbox,
} from "@oaath/server/apns";
import {
  NATIVE_DISPLAY_PAYLOAD_LENGTH,
  type OwnerPhoneRequestProjection,
} from "@oaath/server/native";
import {
  createPostgresRelayStore,
  OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS,
  type PostgresRelayStoreOptions,
} from "@oaath/server/postgres";
import type { Pool } from "pg";

export const challenge: string = deriveCodeChallenge("a".repeat(43));

export const clock: RelayClock = { now: () => 0 };

export const store: RelayStore = createMemoryRelayStore();

export function relay(): RelayHandler {
  return createRelayHandler({
    store,
    authentication: { authenticate: async () => null },
    kms: { encrypt: async (value: string) => value, decrypt: async (value: string) => value },
    clock,
  });
}

/** The driver type crosses the boundary, so a deployment injects its own pool. */
export function durable(pool: Pool): RelayStore {
  const options: PostgresRelayStoreOptions = { pool };
  return createPostgresRelayStore(options);
}

export const schema: readonly string[] = OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS;

export const previews: readonly number[] = [NATIVE_DISPLAY_PAYLOAD_LENGTH, APNS_PAYLOAD_MAX_BYTES];

export const outbox = createMemoryApnsOutbox();

export const sender = createApnsSender;

export type Projection = OwnerPhoneRequestProjection;
`;

const consumer = await createConsumer({
  label: "server",
  packages: ["@oaath/protocol", "@oaath/server"],
  // A deployment installs the driver itself; the subpath must find it there.
  dependencies: { pg: PG_VERSION, "@types/pg": "8.20.3", "@types/node": "22.13.0" },
  types: ["node"],
  skipLibCheck: true,
  files: { "smoke.mjs": SMOKE, "types.ts": TYPES },
});

try {
  consumer.typecheck();
  const report = JSON.parse(consumer.node("smoke.mjs"));

  for (const [specifier, entry] of Object.entries(SUBPATHS)) {
    const expected = await builtExports("server", entry);
    const actual = report.exported[specifier];
    assert(
      JSON.stringify(actual) === JSON.stringify(expected),
      `${specifier}: packed exports differ from the built surface\n    packed: ${actual.join(",")}\n    built:  ${expected.join(",")}`,
    );
    // A collapsed entry would satisfy the equality above vacuously.
    assert(actual.length > 2, `${specifier}: only ${actual.length} runtime exports`);
  }

  assert(
    report.replayCode === "relay_artifact_already_claimed",
    `a replayed claim failed with ${report.replayCode}`,
  );
  assert(report.schemaStatements > 0, "the relay schema executed no statements");

  console.log("smoke-packed-server: ok");
  for (const [specifier, resolved] of Object.entries(report.resolutions)) {
    console.log(
      `  ${specifier.padEnd(24)} ${resolved.slice(resolved.indexOf("node_modules"))} (${report.exported[specifier].length} exports)`,
    );
  }
  console.log("  relay            create, fetch, approve, consume, claim");
  console.log(
    `  one-time claim   replay refused ${report.replayStatus} ${report.replayCode}, nothing leaked`,
  );
  console.log(
    `  postgres         pg ${PG_VERSION} loaded, schema ${report.schemaVersion}, ${report.schemaStatements} statements, no connection`,
  );
  console.log("  types            nodenext strict under the node condition");
} catch (error) {
  console.error("smoke-packed-server: FAILED");
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
} finally {
  await consumer.cleanup();
}
