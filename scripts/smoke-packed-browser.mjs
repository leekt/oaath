/**
 * Owns: a clean tarball browser consumer using public exports only, with full
 * realm recreation.
 *
 * The consumer runs under Node but imports root entries only — the same
 * platform-neutral surface a bundler hands a browser. It composes `createOAAth`
 * over the packed protocol with in-memory stores and drives one
 * `requestPermission` round-trip against the packed `@oaath/server` relay
 * handler, so the golden path is proven across three tarballs instead of inside
 * one workspace.
 *
 * Proven here:
 *
 *   - every root specifier resolves into `dist`, never `src`, inside the
 *     consumer's own `node_modules`;
 *   - the packed runtime exports are exactly what the workspace build produced;
 *   - `createOAAth` composes and `requestPermission` returns an active Grant
 *     while every chain port stays untouched;
 *   - a recreated realm resumes the Grant and observes the exact durable
 *     EIP-5792 bundle without another submission;
 *   - the public surface carries no protocol mechanics;
 *   - the published types resolve under `nodenext` strict with no `@types/node`.
 *
 * @author taek <leekt216@gmail.com>
 */

import { assert, builtExports, createConsumer } from "./packed-consumer.mjs";

/**
 * The consumer program. Trimmed from `packages/sdk/test/support/browser.ts`: the
 * relay is the real packed handler and the stores are the package's own
 * in-memory adapters. Chain ports reject access until consent completes, then
 * retain one pending Operation for reload-safe provider status recovery.
 */
const SMOKE = String.raw`
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";
import {
  createOAAth,
} from "@oaath/sdk";
import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  ecdsaKey,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  kernelAllChainCapabilityHash,
  kernelV4Deployment,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  sessionOperator,
} from "@oaath/sdk/kernel";
import {
  deriveSessionPolicyProfiles,
} from "@oaath/sdk/advanced";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  openOaathDatabase,
} from "@oaath/sdk/persistence";
import { oaathProvider } from "@oaath/sdk/viem";
import {
  hashPermissionRequest,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  parseGrantPolicy,
} from "@oaath/protocol";
import { keccak256, stringToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { IDBFactory } from "fake-indexeddb";

function fail(message) {
  throw new Error(message);
}

const ENTRIES = ["@oaath/protocol", "@oaath/sdk", "@oaath/server"];
const ISSUER_URL = "https://issuer.example";
const REDIRECT_URI = "https://app.example/callback";
const CLIENT_TOKEN = "client-token";
const OWNER_TOKEN = "owner-token";
const SUBJECT = "subject-1";
const CHAIN_ID = 421614;
const START = 1800000000;
const EXPIRES_IN = 1800;
const VALIDATOR = "0x" + "22".repeat(20);
const TARGET = "0x" + "44".repeat(20);
const ACCOUNT = "0x" + "66".repeat(20);
const KMS_PREFIX = "oaath-smoke-kms:v1:";
const deployment = kernelV4Deployment(CHAIN_ID);

// Every root specifier must resolve to a built artifact inside the consumer.
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

let clock = START;
const now = () => clock;

const ownerAccount = privateKeyToAccount("0x" + "11".repeat(32));
const sessionAccount = privateKeyToAccount("0x" + "12".repeat(32));

const ownerCredential = {
  version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  kind: "ecdsa",
  address: ownerAccount.address.toLowerCase(),
};
const operatorCredential = {
  version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  kind: "ecdsa",
  address: sessionAccount.address.toLowerCase(),
};

const callers = new Map([
  [
    CLIENT_TOKEN,
    { role: "client", clientId: "client-a", subject: SUBJECT, redirectUris: [REDIRECT_URI] },
  ],
  [OWNER_TOKEN, { role: "owner", clientId: "owner-console", subject: SUBJECT, redirectUris: [] }],
]);

const relay = createRelayHandler({
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
  // The relay clock is milliseconds; the protocol clock is seconds.
  clock: { now: () => clock * 1000 },
});

function authorized(request, token) {
  const headers = new Headers(request.headers);
  headers.set("authorization", "Bearer " + token);
  return new Request(request, { headers });
}

async function relayJson(path, token, init) {
  const response = await relay(authorized(new Request(ISSUER_URL + path, init), token));
  return response.json();
}

/** The owner console: reads the reviewed scope, posts the terminal decision. */
const ownerRequests = [];
const authorization = {
  async authorize(request) {
    ownerRequests.push(request.requestId);
    const state = await relayJson("/authorization/requests/" + request.requestId, OWNER_TOKEN);
    const scope = JSON.parse(state.requestedScope);
    // The owner device mints the replayable install approval itself, offline:
    // package derivation is pure and the account address is the owner's own
    // fact, so the smoke's throwing chain ports prove nothing was consulted.
    const sessionRuntime = createKernelRuntime({
      deployment: kernelV4Deployment(CHAIN_ID),
      operator: sessionOperator({
        key: ecdsaKey({ account: sessionAccount, validator: VALIDATOR }),
        policies: deriveSessionPolicyProfiles(parseGrantPolicy(scope.policy)),
      }),
      reads: chain.reads,
    });
    const installApproval = await approveKernelPermissionAllChain({
      owner: ecdsaKey({ account: ownerAccount, validator: VALIDATOR }),
      account: ACCOUNT,
      installNonce: "0",
      packages: [...sessionRuntime.packages],
    });
    const decision = {
      version: OAATH_PERMISSION_DECISION_VERSION,
      kind: "approve",
      requestId: request.requestId,
      requestHash: hashPermissionRequest({ ...scope, requestId: request.requestId }),
      decidedAt: now(),
      approvedPolicy: scope.policy,
      capabilityHash: kernelAllChainCapabilityHash(installApproval),
      installApproval,
    };
    const decided = await relayJson(
      "/authorization/requests/" + request.requestId + "/decision",
      OWNER_TOKEN,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ outcome: "approved", artifact: JSON.stringify(decision) }),
      },
    );
    if (typeof decided.code !== "string") {
      fail("owner decision failed: " + JSON.stringify(decided));
    }
    return { code: decided.code };
  },
};

// Consent remains chain-free. After approval the same packed composition is
// enabled for one exact provider send and observation-only reload recovery.
let chainEnabled = false;
let chainTouches = 0;
const sends = [];
function requireChain(port) {
  if (!chainEnabled) fail("requestPermission reached the chain " + port + " port");
  chainTouches += 1;
}

const chain = {
  chainId: CHAIN_ID,
  reads: {
    async read(request) {
      requireChain("reads");
      if (request.type === "chain_id") return CHAIN_ID;
      if (request.type === "code") return request.address === ACCOUNT ? "0x" : "0x01";
      if (request.type === "runtime_code_hash") {
        if (request.address === KERNEL_V4_ENTRY_POINT_V07) {
          return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
        }
        if (request.address === KERNEL_V4_FACTORY_V07) return KERNEL_V4_FACTORY_V07_CODE_HASH;
        if (request.address === KERNEL_V4_UUPS_IMPLEMENTATION_V07) {
          return deployment.implementationDeployment.runtimeCodeHash;
        }
      }
      if (request.type === "kernel_factory_implementation") {
        return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
      }
      if (request.type === "kernel_factory_account") return ACCOUNT;
      if (request.type === "kernel_account_implementation") {
        return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
      }
      fail("unexpected account read " + request.type);
    },
  },
  observation: {
    async read(request) {
      requireChain("observation");
      if (request.type === "chain_id") return CHAIN_ID;
      if (request.type === "user_operation_receipt") return null;
      if (request.type === "replacement_candidate") return null;
      if (request.type === "entry_point_nonce") return null;
      fail("unexpected pending observation " + request.type);
    },
    close: async () => {},
  },
  bundler: {
    async probe(request) {
      requireChain("bundler");
      return {
        accepting: true,
        chainId: request.chainId,
        supportedEntryPoints: [request.entryPoint],
      };
    },
  },
  submission: {
    async open(request) {
      requireChain("submission");
      sends.push(request.prepared);
      return {
        async send() {
          return { userOperationHash: request.prepared.userOperationHash };
        },
        close: async () => {},
      };
    },
  },
  async quote(request) {
    requireChain("quote");
    return {
      nonceKey: "0",
      sequence: String(sends.length),
      gas: {
        callGasLimit: "100000",
        verificationGasLimit: "200000",
        preVerificationGas: "50000",
        maxFeePerGas: "1000000000",
        maxPriorityFeePerGas: "100000000",
      },
    };
  },
  async usage(request) {
    requireChain("usage");
    return {
      version: "oaath.grant-policy-usage/v1",
      status: "complete",
      grantId: request.grantId,
      chainId: request.chainId,
      finalizedOperationCount: "0",
      through: { blockNumber: "1", blockHash: "0x" + "77".repeat(32), observedAt: now() },
    };
  },
  feePayer: null,
};

// A new database connection and new adapters are composed after the first realm
// closes; only IndexedDB state survives the recreation.
const indexedDb = new IDBFactory();
let database = await openOaathDatabase({ factory: indexedDb });
function durableStores() {
  return {
    grants: createIndexedDbGrantStoreAdapter(database),
    operations: createIndexedDbOperationStoreAdapter(database),
    walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
    keys: createIndexedDbKeyStore(database),
    cleanup: createIndexedDbCleanupStore(database),
    context: createIndexedDbContextStore(database),
  };
}
let stores = durableStores();

let signOuts = 0;
let invalidations = 0;

function createRealm() {
  return createOAAth({
    binding: {
      issuer: ISSUER_URL,
      applicationId: "app-a",
      applicationName: "OAAth Packed Smoke",
      clientId: "client-a",
      origin: "https://app.example",
      redirectUri: REDIRECT_URI,
      deviceId: "device-a",
      userHandle: "user-1",
      account: {
        version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
        kind: "kernel",
        accountIndex: "0",
        kernelVersion: "0.4.0",
        factoryRoute: "kernel_factory",
        entryPoint: { version: "0.7" },
        ownerCredential,
      },
      operatorCredential,
    },
    issuer: {
      url: ISSUER_URL,
      fetch: (request) => relay(authorized(request, CLIENT_TOKEN)),
      signOut: async () => {
        signOuts += 1;
      },
    },
    authorization,
    invalidation: {
      invalidateCapability: async (request) => {
        invalidations += 1;
        return {
          evidenceHash: keccak256(stringToBytes("invalidated:" + request.grantId)),
          invalidatedAt: now(),
        };
      },
    },
    stores,
    chains: [chain],
    signing: {
      owner: ecdsaKey({ account: ownerAccount, validator: VALIDATOR }),
      session: ecdsaKey({ account: sessionAccount, validator: VALIDATOR }),
    },
    localKeyIds: ["session-key"],
    now,
  });
}

const oaath = createRealm();
const connection = await oaath.connect();
if ((await connection.resume()) !== null) fail("nothing may resume before consent");

const grant = await connection.requestPermission({
  chainScope: "all",
  permissions: [{ calls: [{ target: TARGET, selectors: ["0xa9059cbb"], valueLimit: "0" }] }],
  expiresIn: EXPIRES_IN,
  perChainOperationLimit: 10,
});

if (grant.state !== "active") fail("Grant state is " + grant.state);
if (ownerRequests.length !== 1) fail("owner console ran " + ownerRequests.length + " times");
if (grant.expiresAt !== START + EXPIRES_IN) fail("Grant expiry is " + grant.expiresAt);

const surface = {
  oaath: Object.keys(oaath).sort(),
  connection: Object.keys(connection).sort(),
  grant: Object.keys(grant).sort(),
};
for (const [name, keys] of Object.entries(surface)) {
  const joined = keys.join(",");
  if (/permissionId|enable|envelope|journal|revision|nonce|grantId|prepared|signature/i.test(joined)) {
    fail(name + " exposes protocol mechanics: " + joined);
  }
}
if (chainTouches !== 0) fail("consent touched the chain " + chainTouches + " times");

chainEnabled = true;
const account = await grant.account(CHAIN_ID);
if (account !== ACCOUNT) fail("the packed Grant resolved another account: " + account);
const firstProvider = oaathProvider({ grant, chain: CHAIN_ID });
const sent = await firstProvider.request({
  method: "wallet_sendCalls",
  params: [{
    version: "2.0.0",
    id: "packed-reload",
    from: account,
    chainId: "0x" + CHAIN_ID.toString(16),
    atomicRequired: true,
    calls: [{ to: TARGET, data: "0xa9059cbb" }],
  }],
});
if (sent.id !== "packed-reload") fail("wallet_sendCalls returned another id");
if (sends.length !== 1) fail("wallet_sendCalls submitted " + sends.length + " operations");
const exactHash = sends[0].userOperationHash;
await connection.close();
await oaath.close();
database.close();
database = await openOaathDatabase({ factory: indexedDb });
stores = durableStores();

// Full realm recreation: a new composition, a new connection, and a new Grant
// store wrapper over the durable state the first realm wrote.
const recreated = createRealm();
const recreatedConnection = await recreated.connect();
const resumed = await recreatedConnection.resume();
if (resumed === null) fail("a recreated realm did not resume the active Grant");
if (resumed.state !== "active") fail("the resumed Grant state is " + resumed.state);
if (resumed.expiresAt !== grant.expiresAt) fail("the resumed Grant expiry differs");
if (ownerRequests.length !== 1) fail("resume asked the owner again");
const recovered = await oaathProvider({ grant: resumed, chain: CHAIN_ID }).request({
  method: "wallet_getCallsStatus",
  params: ["packed-reload"],
});
if (recovered.id !== "packed-reload" || recovered.status !== 100) {
  fail("reloaded provider did not recover the pending bundle: " + JSON.stringify(recovered));
}
if (sends.length !== 1 || sends[0].userOperationHash !== exactHash) {
  fail("status recovery resubmitted or changed the exact operation");
}

await recreatedConnection.signOut();
if (signOuts !== 1) fail("signOut ran " + signOuts + " times");
await recreatedConnection.close();
await recreated.close();
database.close();
if (invalidations !== 0) fail("the smoke never revokes, so nothing may be invalidated");

process.stdout.write(JSON.stringify({ resolutions, exported, surface }));
`;

/** The published types must resolve and compose under `nodenext` strict. */
const TYPES = `import { OAATH_PERMISSION_REQUEST_VERSION, type PermissionRequest } from "@oaath/protocol";
import {
  type GrantStoreAdapter,
  type OaathConfiguration,
} from "@oaath/sdk/advanced";
import {
  type Oaath,
  type OaathGrantHandle,
  createOAAth,
} from "@oaath/sdk";
import {
  createMemoryGrantStoreAdapter,
} from "@oaath/sdk/testing";
import { createMemoryRelayStore, createRelayHandler, type RelayHandler } from "@oaath/server";

export const version: PermissionRequest["version"] = OAATH_PERMISSION_REQUEST_VERSION;

export const grants: GrantStoreAdapter = createMemoryGrantStoreAdapter();

export function compose(configuration: Readonly<OaathConfiguration>): Readonly<Oaath> {
  return createOAAth(configuration);
}

export async function permission(oaath: Readonly<Oaath>): Promise<Readonly<OaathGrantHandle>> {
  const connection = await oaath.connect();
  return connection.requestPermission({
    chainScope: "all",
    permissions: [{ calls: [{ target: "0x00", selectors: ["0x00"], valueLimit: "0" }] }],
    expiresIn: 1800,
    perChainOperationLimit: 10,
  });
}

export function relay(): RelayHandler {
  return createRelayHandler({
    store: createMemoryRelayStore(),
    authentication: { authenticate: async () => null },
    kms: { encrypt: async (value: string) => value, decrypt: async (value: string) => value },
    clock: { now: () => 0 },
  });
}
`;

const EXPECTED_SURFACES = {
  oaath: ["binding", "close", "connect", "disconnect"],
  connection: ["binding", "close", "requestPermission", "resume", "signOut"],
  grant: ["account", "close", "expiresAt", "revoke", "sendCalls", "state"],
};

const consumer = await createConsumer({
  label: "browser",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server"],
  dependencies: { "fake-indexeddb": "6.2.5", viem: "2.55.8" },
  files: { "smoke.mjs": SMOKE, "types.ts": TYPES },
});

try {
  consumer.typecheck();
  const report = JSON.parse(consumer.node("smoke.mjs"));

  for (const [directory, specifier] of [
    ["protocol", "@oaath/protocol"],
    ["sdk", "@oaath/sdk"],
    ["server", "@oaath/server"],
  ]) {
    const expected = await builtExports(directory);
    const actual = report.exported[specifier];
    assert(
      JSON.stringify(actual) === JSON.stringify(expected),
      `${specifier}: packed exports differ from the built surface\n    packed: ${actual.join(",")}\n    built:  ${expected.join(",")}`,
    );
    // A collapsed entry would satisfy the equality above vacuously. The sdk
    // root is deliberately minimal, so its guard is the constructor itself.
    if (specifier === "@oaath/sdk") {
      assert(actual.includes("createOAAth"), `${specifier}: the root entry lost createOAAth`);
    } else {
      assert(actual.length > 10, `${specifier}: only ${actual.length} runtime exports`);
    }
  }

  for (const [name, expected] of Object.entries(EXPECTED_SURFACES)) {
    assert(
      JSON.stringify(report.surface[name]) === JSON.stringify(expected),
      `${name} surface changed: ${report.surface[name].join(",")}`,
    );
  }

  console.log("smoke-packed-browser: ok");
  for (const [specifier, resolved] of Object.entries(report.resolutions)) {
    console.log(`  ${specifier.padEnd(16)} ${resolved.slice(resolved.indexOf("node_modules"))}`);
  }
  console.log(
    `  runtime exports  protocol ${report.exported["@oaath/protocol"].length}, sdk ${report.exported["@oaath/sdk"].length}, server ${report.exported["@oaath/server"].length}`,
  );
  console.log(
    "  golden path      connect, consent, wallet_sendCalls, realm recreation, exact status, signOut",
  );
  console.log("  types            nodenext strict, no @types/node");
} catch (error) {
  console.error("smoke-packed-browser: FAILED");
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
} finally {
  await consumer.cleanup();
}
