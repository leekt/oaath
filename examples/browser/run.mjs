/**
 * The supported browser journey, narrated: connect, request one all-chain grant,
 * execute, revoke.
 *
 * Everything an application touches is on three objects — `oaath`, `connection`,
 * `grant` — and none of them expose a permission ID, a Kernel enable envelope, an
 * operation journal, or a nonce. The relay is the real `@oaath/server` Fetch
 * handler running in this process, so the client speaks the wire contract rather
 * than a mock of it.
 *
 *   OAATH_REQUIRE_ANVIL=1   run against a real local chain (Anvil + Kernel v4)
 *   unset                   run against injected chain facts (default, no network)
 *
 * Any failed step exits non-zero, so this file doubles as a smoke.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  hashPermissionRequest,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  parseGrantPolicy,
} from "@oaath/protocol";
import { createOAAth } from "@oaath/sdk";
import { deriveSessionPolicyProfiles } from "@oaath/sdk/advanced";
import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  ecdsaKey,
  kernelAllChainCapabilityHash,
  kernelV4Deployment,
  ownerOperator,
  sessionOperator,
} from "@oaath/sdk/kernel";
import {
  createMemoryCleanupStore,
  createMemoryContextStore,
  createMemoryGrantStoreAdapter,
  createMemoryKeyStore,
  createMemoryOperationStoreAdapter,
  createMemoryPreparedCallStoreAdapter,
  createMemoryWalletCallBundleStoreAdapter,
} from "@oaath/sdk/testing";
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";
import { keccak256, stringToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const CHAIN_ID = 421_614;
const ISSUER_URL = "https://issuer.example";
const ORIGIN = "https://app.example";
const REDIRECT_URI = "https://app.example/callback";
const CLIENT_TOKEN = "client-token";
const OWNER_TOKEN = "owner-token";
const SUBJECT = "subject-1";
/** The one (target, selector) pair the application asks the owner to approve. */
const TARGET = `0x${"44".repeat(20)}`;
const SELECTOR = "0xa9059cbb";
const CALL_DATA = `0x${"a9059cbb"}${"0".repeat(64)}`;
const EXPIRES_IN = 1_800;

const say = (...parts) => console.log(...parts);
const step = (title) => say(`\n▸ ${title}`);
const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};

/** One clock in seconds, shared by the client and (in ms) by the relay. */
const clock = Math.floor(Date.now() / 1000);
const now = () => clock;

const chain =
  process.env.OAATH_REQUIRE_ANVIL === "1"
    ? await (await import("./anvil-chain.mjs")).createAnvilChain(CHAIN_ID)
    : (await import("./fake-chain.mjs")).createFakeChain(CHAIN_ID);

// Two local credentials. In a browser these are non-extractable WebCrypto keys or
// a passkey; `ecdsaKey` is the same composition path either way, and P-256 and
// WebAuthn profiles plug into it identically.
const ownerAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);
const sessionAccount = privateKeyToAccount(`0x${"12".repeat(32)}`);

/** The issuer: the real relay handler over its in-memory store. */
const callers = new Map([
  [
    CLIENT_TOKEN,
    { role: "client", clientId: "client-a", subject: SUBJECT, redirectUris: [REDIRECT_URI] },
  ],
  [OWNER_TOKEN, { role: "owner", clientId: "owner-console", subject: SUBJECT, redirectUris: [] }],
]);
const KMS_PREFIX = "oaath-example-kms:v1:";
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
      return KMS_PREFIX + Buffer.from(plaintext, "utf8").toString("base64");
    },
    async decrypt(reference) {
      return Buffer.from(reference.slice(KMS_PREFIX.length), "base64").toString("utf8");
    },
  },
  clock: { now: () => clock * 1_000 },
});
const authorized = (request, token) => {
  const headers = new Headers(request.headers);
  headers.set("authorization", `Bearer ${token}`);
  return new Request(request, { headers });
};
const ownerFetch = async (path, init) =>
  (await relay(authorized(new Request(`${ISSUER_URL}${path}`, init), OWNER_TOKEN))).json();

/**
 * The owner console. It runs on the owner's device, not in the application: it
 * reads the reviewed scope back from the relay, decides, and posts a terminal
 * decision. The application only ever receives the authorization code.
 */
let ownerReviews = 0;
const authorization = {
  async authorize({ requestId }) {
    ownerReviews += 1;
    const state = await ownerFetch(`/authorization/requests/${requestId}`);
    const scope = JSON.parse(state.requestedScope);
    say(`  owner reviews    ${state.requestedScope.slice(0, 88)}…`);
    // The owner device derives and signs the replayable install approval
    // itself: the account from its own initial packages, the permission
    // packages from the reviewed policy and operator credential. The
    // decision's capabilityHash binds exactly this capability, and the first
    // covered execution on any chain spends it.
    const ownerKey = ecdsaKey({ account: ownerAccount, validator: chain.validator });
    const deployment = kernelV4Deployment(CHAIN_ID);
    const ownerRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({ key: ownerKey }),
      reads: chain.capability.reads,
    });
    const descriptor = await ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: [...ownerRuntime.packages],
    });
    const sessionRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: ecdsaKey({
          account: { address: scope.operatorCredential.address, sign: async () => "0x" },
          validator: chain.validator,
        }),
        policies: deriveSessionPolicyProfiles(parseGrantPolicy(scope.policy)),
      }),
      reads: chain.capability.reads,
    });
    const installApproval = await approveKernelPermissionAllChain({
      owner: ownerKey,
      account: descriptor.account,
      installNonce: "0",
      packages: [...sessionRuntime.packages],
    });
    const decided = await ownerFetch(`/authorization/requests/${requestId}/decision`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        outcome: "approved",
        artifact: JSON.stringify({
          version: OAATH_PERMISSION_DECISION_VERSION,
          kind: "approve",
          requestId,
          requestHash: hashPermissionRequest({ ...scope, requestId }),
          decidedAt: now(),
          // Approving the requested policy unchanged. Narrowing it here is
          // allowed; widening it is refused by the client.
          approvedPolicy: scope.policy,
          capabilityHash: kernelAllChainCapabilityHash(installApproval),
          installApproval,
        }),
      }),
    });
    expect(typeof decided.code === "string", "the owner console could not record a decision");
    return { code: decided.code };
  },
};

// Durable state. A browser swaps these for the `createIndexedDb*` adapters
// from the same entry; nothing else in this file changes.
const stores = {
  grants: createMemoryGrantStoreAdapter(),
  operations: createMemoryOperationStoreAdapter(),
  walletCallBundles: createMemoryWalletCallBundleStoreAdapter(),
  preparedCallContexts: createMemoryPreparedCallStoreAdapter(),
  keys: createMemoryKeyStore(),
  cleanup: createMemoryCleanupStore(),
  context: createMemoryContextStore(),
};

let signOuts = 0;
let invalidations = 0;
const oaath = createOAAth({
  binding: {
    issuer: ISSUER_URL,
    applicationId: "app-a",
    applicationName: "OAAth Browser Example",
    clientId: "client-a",
    origin: ORIGIN,
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
      ownerCredential: {
        version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
        kind: "ecdsa",
        address: ownerAccount.address.toLowerCase(),
      },
    },
    operatorCredential: {
      version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: sessionAccount.address.toLowerCase(),
    },
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
    // The deployment proves the replayable approval capability is dead. The SDK
    // never invents this evidence.
    invalidateCapability: async ({ grantId }) => {
      invalidations += 1;
      return {
        evidenceHash: keccak256(stringToBytes(`invalidated:${grantId}`)),
        invalidatedAt: now(),
      };
    },
  },
  stores,
  chains: [chain.capability],
  signing: {
    owner: ecdsaKey({ account: ownerAccount, validator: chain.validator }),
    session: ecdsaKey({ account: sessionAccount, validator: chain.validator }),
  },
  localKeyIds: ["session-key"],
  now,
});

try {
  say(`chain            ${chain.label}, chain id ${CHAIN_ID}`);
  say(`issuer           ${ISSUER_URL} (in-process @oaath/server relay)`);

  step("connect");
  const connection = await oaath.connect();
  expect((await connection.resume()) === null, "nothing may resume before consent");
  say("  connected        no authority yet: nothing is persisted before consent");

  step("request one all-chain grant");
  const grant = await connection.requestPermission({
    chainScope: "all",
    permissions: [{ calls: [{ target: TARGET, selectors: [SELECTOR], valueLimit: "0" }] }],
    expiresIn: EXPIRES_IN,
    perChainOperationLimit: 10,
  });
  expect(grant.state === "active", `the Grant is ${grant.state}`);
  expect(ownerReviews === 1, `the owner was asked ${ownerReviews} times`);
  say(`  grant            ${grant.state}, expires at ${grant.expiresAt}`);
  say("  scope            one owner review covers every supported chain, present and future");

  step("execute");
  const operation = await grant.sendCalls({
    chain: CHAIN_ID,
    calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
  });
  const outcome = await operation.wait();
  expect(outcome.status === "finalized", `the operation is ${outcome.status}`);
  expect(outcome.outcome === "success", `the operation outcome is ${outcome.outcome}`);
  expect(chain.sends.length === 1, `the transport was handed ${chain.sends.length} snapshots`);
  say(`  submitted        ${chain.sends[0].userOperationHash}`);
  say(`  finalized        ${outcome.status}/${outcome.outcome} in ${outcome.transactionHash}`);
  say("  identity         observation finalized the exact operation that was submitted, once");

  step("revoke");
  await grant.revoke();
  // The replayable capability dies first; then, because this realm holds the
  // owner's signing capability, revoke removes the installed chain permission
  // with one owner-signed revocation operation and completes to `revoked`
  // only after that operation's finalized success.
  expect(grant.state === "revoked", `the Grant is ${grant.state}`);
  expect(invalidations === 1, `the capability was invalidated ${invalidations} times`);
  expect(
    chain.sends.length === 2,
    `revocation submitted ${chain.sends.length - 1} extra snapshots`,
  );
  expect(
    chain.sends[1].kind === "revocation",
    `the removal operation kind is ${chain.sends[1].kind}`,
  );
  say("  grant            revoked: capability dead, chain permission uninstalled by the owner");
  say(`  removal          ${chain.sends[1].userOperationHash} (owner-signed uninstall)`);

  step("sign out and close");
  await connection.signOut();
  await connection.close();
  await oaath.close();
  expect(signOuts === 1, `signOut ran ${signOuts} times`);
  say("  released         relay authentication dropped, runtime resources closed");

  say("\nbrowser example: ok");
} catch (error) {
  console.error("\nbrowser example: FAILED");
  console.error(error);
  process.exitCode = 1;
} finally {
  chain.stop();
}
