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
 *   - grant reference verification authorizes the approved exact revision with
 *     immutable evidence, denies a newer revision with a typed code, and
 *     replays identically, all through published package exports;
 *   - `./postgres` loads the deployment's own `pg` driver and publishes its
 *     schema with no connection opened;
 *   - all four subpaths' types resolve under `nodenext` strict.
 *
 * No PostgreSQL server is contacted: `packages/server/test/postgres.test.ts`
 * owns that behind `OAATH_REQUIRE_POSTGRES`.
 *
 * @author taek <leekt216@gmail.com>
 */

import { readFileSync } from "node:fs";
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
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import {
  deriveCodeChallenge,
  hashGrantPolicyCalls,
  OAATH_GRANT_POLICY_VERSION,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_PERMISSION_REQUEST_VERSION,
  parseGrantVerificationResult,
} from "@oaath/protocol";
import { createMemoryRelayStore, createMemoryServiceDirectoryStore, createRelayHandler, createServiceDirectory } from "@oaath/server";
import { APNS_PAYLOAD_MAX_BYTES, createApnsSender } from "@oaath/server/apns";
import { NATIVE_DISPLAY_PAYLOAD_LENGTH, projectOwnerPhoneRequest, projectOwnerPhoneRevocation } from "@oaath/server/native";
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
const TEAM_OWNER_TOKEN = "team-owner-token";
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
const requestedAt = clock / 1000;
const policyCalls = [
  {
    target: "0x" + "11".repeat(20),
    selector: "0x12345678",
    valueLimit: "0",
    argumentEquals: [],
  },
];
const requestedScope = JSON.stringify({
  version: OAATH_PERMISSION_REQUEST_VERSION,
  context: {
    version: "oaath.workspace-account-context/v1",
    workspaceId: "personal-1",
    workspaceKind: "personal",
    accountId: "account-1",
  },
  application: {
    applicationId: "oaath-packed-server-smoke",
    clientId: "client-a",
    origin: "https://app.example",
    deviceId: "packed-server-device",
  },
  chainScope: "all",
  logicalAccount: {
    version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "meta_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: "0x" + "33".repeat(20),
    },
  },
  operatorCredential: {
    version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
    kind: "ecdsa",
    address: "0x" + "44".repeat(20),
  },
  policy: {
    version: OAATH_GRANT_POLICY_VERSION,
    calls: policyCalls,
    validAfter: requestedAt,
    validUntil: requestedAt + 599,
    perChainOperationLimit: 1,
  },
  requestedAt,
  expiresAt: requestedAt + 600,
  sessionSigner: null,
});

const permission = JSON.parse(requestedScope);
const teamAccount = { ...structuredClone(permission.logicalAccount), accountIndex: "1" };
const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
await directory.replace({ expectedRevision: null, directory: {
  version: "oaath.service-directory/v1",
  applications: [{ clientId: "client-a", applicationId: permission.application.applicationId, applicationName: "Packed consumer" }],
  workspaces: [{ workspaceId: "personal-1", kind: "personal" }, { workspaceId: "team-1", kind: "team" }],
  memberships: ["personal-1", "team-1"].map((workspaceId) => ({ workspaceId, clientId: "client-a", subject: SUBJECT })),
  ownerDevices: [
    { workspaceId: "personal-1", ownerDeviceId: "owner-phone", subject: "phone-subject" },
    { workspaceId: "team-1", ownerDeviceId: "team-phone", subject: "team-phone-subject" },
  ],
  accounts: [
    { workspaceId: "personal-1", accountId: "account-1", ownerDeviceId: "owner-phone", account: permission.logicalAccount, ownerValidator: "0x" + "22".repeat(20), chainIds: [31337] },
    { workspaceId: "team-1", accountId: "treasury", ownerDeviceId: "team-phone", account: teamAccount, ownerValidator: "0x" + "22".repeat(20), chainIds: [31337] },
  ],
  selections: [{ clientId: "client-a", subject: SUBJECT, workspaceId: "personal-1", accountId: "account-1" }],
} });

const callers = new Map([
  [
    CLIENT_TOKEN,
    {
      role: "client",
      clientId: "client-a",
      subject: SUBJECT,
      redirectUris: [REDIRECT_URI],
      organizationAudience: "org-1",
    },
  ],
  // The owner caller keeps the pre-audience port shape on purpose: a
  // deployment that declares no audience must keep authenticating.
  [OWNER_TOKEN, { role: "owner", clientId: "owner-console", subject: "phone-subject", redirectUris: [] }],
  [TEAM_OWNER_TOKEN, { role: "owner", clientId: "owner-phone", subject: "team-phone-subject", redirectUris: [] }],
]);

const handler = createRelayHandler({
  ownerRouting: directory,
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

// A captured personal request retains its account even after the selection changes.
await directory.selectAccount(callers.get(CLIENT_TOKEN), { workspaceId: "team-1", accountId: "treasury" });
// The relay's full wire round-trip: create, fetch, approve, consume, claim.
const created = await ok(
  await handler(
    request("POST", "/authorization/requests", CLIENT_TOKEN, {
      redirectUri: REDIRECT_URI,
      codeChallenge: deriveCodeChallenge(CODE_VERIFIER),
      requestedScope,
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

const personalProjection = await ok(await handler(request("GET", "/native/projections/" + created.requestId, OWNER_TOKEN)), 200, "personal phone consent");
if (personalProjection.version !== "oaath.native-projection/v6" || JSON.stringify(personalProjection.scope.context) !== JSON.stringify(permission.context)) fail("personal phone lost requested account context");

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

// The same service routes a team account to its own phone, then keeps that
// admitted route when membership is removed. New requests are refused.
const teamScope = JSON.stringify({ ...permission,
  context: { ...permission.context, workspaceId: "team-1", workspaceKind: "team", accountId: "treasury" },
  logicalAccount: teamAccount,
});
const teamCreated = await ok(await handler(request("POST", "/authorization/requests", CLIENT_TOKEN, {
  redirectUri: REDIRECT_URI, codeChallenge: deriveCodeChallenge(CODE_VERIFIER), requestedScope: teamScope,
})), 201, "team create");
const wrongOwner = await handler(request("GET", "/authorization/requests/" + teamCreated.requestId, OWNER_TOKEN));
if (wrongOwner.status !== 404) fail("personal phone accessed the team request");
const teamProjection = await ok(await handler(request("GET", "/native/projections/" + teamCreated.requestId, TEAM_OWNER_TOKEN)), 200, "team phone consent");
if (JSON.stringify(teamProjection.scope.context) !== JSON.stringify(JSON.parse(teamScope).context)) fail("team phone lost requested account context");
const snapshot = await directory.read();
await directory.replace({ expectedRevision: snapshot.revision, directory: { ...snapshot.directory, memberships: [] } });
const refused = await handler(request("POST", "/authorization/requests", CLIENT_TOKEN, {
  redirectUri: REDIRECT_URI, codeChallenge: deriveCodeChallenge(CODE_VERIFIER), requestedScope: teamScope,
}));
if (refused.status !== 403 || (await refused.json()).error?.code !== "relay_forbidden") fail("removed member created a request");
const teamApproval = await ok(await handler(request("POST", "/authorization/requests/" + teamCreated.requestId + "/decision", TEAM_OWNER_TOKEN, {
  outcome: "approved", artifact: ARTIFACT,
})), 200, "team approve");
const teamConsumed = await ok(await handler(request("POST", "/authorization/codes/consume", CLIENT_TOKEN, {
  code: teamApproval.code, codeVerifier: CODE_VERIFIER, redirectUri: REDIRECT_URI,
})), 200, "team consume");
const teamClaimed = await ok(await handler(request("POST", "/authorization/artifacts/" + teamConsumed.artifactId + "/claim", CLIENT_TOKEN)), 200, "team claim");
if (teamClaimed.requestId !== teamCreated.requestId || teamClaimed.artifact !== ARTIFACT) fail("team artifact binding was lost");

// One-time claim: the replay must fail closed and disclose nothing.
const replayed = await handler(
  request("POST", "/authorization/artifacts/" + consumed.artifactId + "/claim", CLIENT_TOKEN),
);
if (replayed.status < 400) fail("a claimed artifact was released twice");
const replayBody = await replayed.json();
if (typeof replayBody.error?.code !== "string") fail("a failure must carry a structured code");
if (JSON.stringify(replayBody).includes("approved")) fail("a failure leaked the artifact");

// Grant reference verification over the published wire contract: an active
// exact revision authorizes with immutable evidence; a newer revision denies
// with a typed code; both parse through the published result parser.
const verifyAssertion = {
  grantId: created.requestId,
  revision: 1,
  subject: SUBJECT,
  clientId: "client-a",
  organizationAudience: "org-1",
  requiredCallsDigest: hashGrantPolicyCalls(policyCalls),
};
const verified = parseGrantVerificationResult(
  await ok(await handler(request("POST", "/grants/verify", CLIENT_TOKEN, verifyAssertion)), 200, "verify"),
);
if (verified.state !== "authorized") fail("verification answered " + verified.state);
if (verified.ref.grantId !== created.requestId) fail("the reference names another grant");
if (verified.ref.state !== "active") fail("the reference state is " + verified.ref.state);
if (!/^0x[0-9a-f]{64}$/.test(verified.ref.policyDigest)) fail("policyDigest is malformed");

const supersededResult = parseGrantVerificationResult(
  await ok(
    await handler(
      request("POST", "/grants/verify", CLIENT_TOKEN, { ...verifyAssertion, revision: 2 }),
    ),
    200,
    "verify newer revision",
  ),
);
if (supersededResult.state !== "denied" || supersededResult.code !== "grant_revision_mismatch") {
  fail("a newer revision must deny with grant_revision_mismatch");
}

// Replay safety: the same assertion answers the same evidence after denials.
const replayVerified = parseGrantVerificationResult(
  await ok(await handler(request("POST", "/grants/verify", CLIENT_TOKEN, verifyAssertion)), 200, "verify replay"),
);
if (JSON.stringify(replayVerified) !== JSON.stringify(verified)) {
  fail("a replayed verification answered different evidence");
}

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
const revocationSource = JSON.parse(readFileSync(new URL("./revocation-source.json", import.meta.url), "utf8"));
const revocationGolden = JSON.parse(readFileSync(new URL("./revocation-golden.json", import.meta.url), "utf8"));
for (const [index, { name, ...operation }] of revocationSource.valid.entries()) {
  const projection = await projectOwnerPhoneRevocation({
    operationId: "revoke-" + index, ownerSubject: "fixture-owner", expiresAt: 1800000060000,
    request: { version: "oaath.kernel-revocation-signing-request/v1", kind: "kernel-revocation",
      permissionRequest: revocationSource.permissionRequest, install: revocationSource.installProjection.scope.request, ...operation },
  });
  if (!isDeepStrictEqual(JSON.parse(JSON.stringify(projection)), revocationGolden[index])) fail("packed revocation projection differs from Swift vector");
}

if (typeof APNS_PAYLOAD_MAX_BYTES !== "number") fail("the apns preview is unusable");
if (typeof createApnsSender !== "function") fail("createApnsSender is missing");

process.stdout.write(
  JSON.stringify({
    resolutions,
    exported,
    replayCode: replayBody.error.code,
    replayStatus: replayed.status,
    verifyState: verified.state,
    verifyDenialCode: supersededResult.code,
    schemaVersion: OAATH_RELAY_POSTGRES_SCHEMA_VERSION,
    schemaStatements: statements.length,
  }),
);
`;

/** All four subpaths must resolve and compose under `nodenext` strict. */
const TYPES = `import {
  deriveCodeChallenge,
  type GrantVerificationResult,
  hashGrantPolicyCalls,
  type OaathGrantRef,
  parseGrantVerificationResult,
  type VerifyGrantRevisionInput,
} from "@oaath/protocol";
import {
  createMemoryRelayStore,
  createMemoryServiceDirectoryStore,
  createRelayHandler,
  createServiceDirectory,
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
  type OwnerPhoneRevocationDecision,
  projectOwnerPhoneRevocation,
} from "@oaath/server/native";
import {
  createPostgresRelayStore,
  OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS,
  type PostgresRelayStoreOptions,
  createPostgresServiceDirectoryStore,
} from "@oaath/server/postgres";
import type { Pool } from "pg";

export const revocationProjection: (input: Parameters<typeof projectOwnerPhoneRevocation>[0]) => Promise<OwnerPhoneRequestProjection> = projectOwnerPhoneRevocation;
export const revocationDecision: OwnerPhoneRevocationDecision = {
  version: "oaath.native-revocation-decision/v1", operationId: "revoke-1",
  outcome: "rejected", decidedAt: 1800000000000, settlement: "decided",
};

export const challenge: string = deriveCodeChallenge("a".repeat(43));

export const clock: RelayClock = { now: () => 0 };

export const store: RelayStore = createMemoryRelayStore();

export function relay(): RelayHandler {
  return createRelayHandler({
    ownerRouting: createServiceDirectory(createMemoryServiceDirectoryStore()),
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

export function durableDirectory(pool: Pool) {
  return createPostgresServiceDirectoryStore({ pool });
}

export const schema: readonly string[] = OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS;

export const previews: readonly number[] = [NATIVE_DISPLAY_PAYLOAD_LENGTH, APNS_PAYLOAD_MAX_BYTES];

export const outbox = createMemoryApnsOutbox();

export const sender = createApnsSender;

export type Projection = OwnerPhoneRequestProjection;

/** An adopter parses every verification response before acting on it. */
export function verified(body: unknown): OaathGrantRef | null {
  const result: GrantVerificationResult = parseGrantVerificationResult(body);
  return result.state === "authorized" ? result.ref : null;
}

export function assertion(grantId: string, digestCalls: unknown): VerifyGrantRevisionInput {
  return {
    grantId,
    revision: 1,
    subject: "subject-1",
    clientId: "client-a",
    organizationAudience: "org-1",
    requiredCallsDigest: hashGrantPolicyCalls(digestCalls),
  };
}
`;

const consumer = await createConsumer({
  label: "server",
  packages: ["@oaath/protocol", "@oaath/server"],
  // A deployment installs the driver itself; the subpath must find it there.
  dependencies: { pg: PG_VERSION, "@types/pg": "8.20.3", "@types/node": "22.13.0" },
  types: ["node"],
  skipLibCheck: true,
  files: {
    "smoke.mjs": SMOKE,
    "types.ts": TYPES,
    "revocation-source.json": readFileSync(
      new URL(
        "../packages/protocol/test/fixtures/kernel-revocation-operation.json",
        import.meta.url,
      ),
      "utf8",
    ),
    "revocation-golden.json": readFileSync(
      new URL("../packages/server/test/fixtures/phone-revocation-golden.json", import.meta.url),
      "utf8",
    ),
  },
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
  assert(report.verifyState === "authorized", `verification answered ${report.verifyState}`);
  assert(
    report.verifyDenialCode === "grant_revision_mismatch",
    `a newer revision denied with ${report.verifyDenialCode}`,
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
    "  directory        personal/team owner routes, selection independence, member removal",
  );
  console.log(
    `  verify           exact revision ${report.verifyState}, newer revision ${report.verifyDenialCode}, replay identical`,
  );
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
