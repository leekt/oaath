/**
 * The reference OAAth service deployment: one process serves the relay over
 * real HTTP with real chain execution ports, and a URL-only client completes
 * the whole golden path against it — `createOAAth({ url })`, nothing else.
 *
 * ```text
 * service   @oaath/server relay over node:http
 *           bootstrap    application identity + account + owner validator
 *           chains       every port answered from a real local chain
 *                        (reads, observation, bundler probe, quote,
 *                         submission through EntryPoint.handleOps, usage)
 * owner     an in-process console standing in for the owner device: it
 *           reviews each scope, derives the account and permission packages
 *           independently, and signs the replayable install approval
 * client    createOAAth({ url }) over global fetch — the only deployment
 *           fact it holds is the URL and its bearer credential
 * ```
 *
 * A production deployment replaces exactly three things: the in-memory store
 * with PostgreSQL, the demo bearer tokens with its own authentication port,
 * and the local Anvil chain with its RPC/bundler endpoints. Nothing about the
 * client changes.
 *
 * @author taek <leekt216@gmail.com>
 */

import { createServer } from "node:http";
import {
  hashPermissionRequest,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
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
  encodeKernelV4PermissionUninstallCalls,
  kernelAllChainCapabilityHash,
  kernelV4Deployment,
  ownerOperator,
  sessionOperator,
} from "@oaath/sdk/kernel";
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";
import { privateKeyToAccount } from "viem/accounts";
import { createAnvilChain } from "../browser/anvil-chain.mjs";

const CHAIN_ID = 421_614;
const CLIENT_TOKEN = process.env.OAATH_CLIENT_TOKEN ?? "demo-client-token";
const OWNER_TOKEN = process.env.OAATH_OWNER_TOKEN ?? "demo-owner-token";
/** The application's own origin; the service registers its redirect target. */
const APP_ORIGIN = "http://localhost:9797";

const say = (line) => console.log(line);
const step = (label) => say(`\n▸ ${label}`);
function expect(fact, message) {
  if (!fact) throw new Error(message);
}

const ownerAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);

step("start a real chain and deploy the reviewed Kernel stack");
const chain = await createAnvilChain(CHAIN_ID);
say(`  chain            ${chain.label}`);

const ownerCredential = Object.freeze({
  version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  kind: "ecdsa",
  address: ownerAccount.address.toLowerCase(),
});
const accountProfile = Object.freeze({
  version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  kind: "kernel",
  accountIndex: "0",
  kernelVersion: "0.4.0",
  factoryRoute: "kernel_factory",
  entryPoint: Object.freeze({ version: "0.7" }),
  ownerCredential,
});

/** One deployment-injected chain execution port over the real capability. */
function chainPort(capability) {
  return {
    chainId: capability.chainId,
    reads: (request) => capability.reads.read(request),
    observation: (request) => capability.observation.read(request),
    bundler: (request) => capability.bundler.probe(request),
    quote: (request) => capability.quote(request),
    submission: async (request) => {
      const session = await capability.submission.open(request);
      try {
        return await session.send();
      } finally {
        await session.close();
      }
    },
    usage: capability.usage === null ? null : (request) => capability.usage(request),
    feePayer: capability.feePayer,
    staticPaymasterConfigurationHash: capability.staticPaymasterConfigurationHash,
  };
}

step("serve the relay over HTTP");
const relayHandler = createRelayHandler({
  store: createMemoryRelayStore(),
  authentication: {
    async authenticate(request) {
      const header = request.headers.get("authorization") ?? "";
      const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
      if (token === CLIENT_TOKEN) {
        return {
          role: "client",
          clientId: "demo-client",
          subject: "demo-subject",
          redirectUris: [`${APP_ORIGIN}/callback`],
        };
      }
      if (token === OWNER_TOKEN) {
        return {
          role: "owner",
          clientId: "owner-console",
          subject: "demo-subject",
          redirectUris: [],
        };
      }
      return null;
    },
  },
  kms: {
    async encrypt(plaintext) {
      return `demo-kms:${Buffer.from(plaintext, "utf8").toString("base64")}`;
    },
    async decrypt(reference) {
      if (!reference.startsWith("demo-kms:")) throw new Error("unknown ciphertext reference");
      return Buffer.from(reference.slice("demo-kms:".length), "base64").toString("utf8");
    },
  },
  clock: { now: () => Date.now() },
  bootstrap: {
    application: {
      applicationId: "demo-app",
      applicationName: "OAAth Reference Service",
      clientId: "demo-client",
      redirectUris: [`${APP_ORIGIN}/callback`],
    },
    userHandle: "demo-user",
    account: accountProfile,
    ownerValidator: chain.validator,
  },
  chains: [chainPort(chain.capability)],
});

const server = createServer(async (incoming, outgoing) => {
  const chunks = [];
  for await (const chunk of incoming) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  const url = new URL(incoming.url ?? "/", "http://localhost");
  const response = await relayHandler(
    new Request(`http://localhost${url.pathname}${url.search}`, {
      method: incoming.method,
      headers: Object.fromEntries(
        Object.entries(incoming.headers).map(([key, value]) => [key, String(value)]),
      ),
      ...(body.length ? { body } : {}),
    }),
  );
  outgoing.writeHead(response.status, Object.fromEntries(response.headers));
  outgoing.end(Buffer.from(await response.arrayBuffer()));
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const url = `http://127.0.0.1:${server.address().port}`;
say(`  service          ${url}`);

/**
 * The owner console, standing in for the owner device. It reads the reviewed
 * scope back from the relay, derives the account and the permission packages
 * independently — from its own key, the reviewed policy, and the operator
 * credential in the scope — and signs the replayable install approval.
 *
 * It also completes revocation: the client can kill the capability but never
 * holds owner authority, so the console removes the installed chain
 * permission with an owner-signed operation and submits it through the
 * relay's owner lane — the one caller the invalidation gate lets through.
 */
async function ownerConsole() {
  const ownerFetch = async (path, init) =>
    (
      await fetch(`${url}${path}`, {
        ...init,
        headers: { ...init?.headers, authorization: `Bearer ${OWNER_TOKEN}` },
      })
    ).json();
  const ownerKey = ecdsaKey({ account: ownerAccount, validator: chain.validator });
  const deployment = kernelV4Deployment(CHAIN_ID);
  const ownerRuntime = createKernelRuntime({
    deployment,
    operator: ownerOperator({ key: ownerKey }),
    reads: chain.capability.reads,
  });
  /** requestId -> the exact packages the approval installed. */
  const approvals = new Map();
  return {
    async approve(requestId) {
      const state = await ownerFetch(`/authorization/requests/${requestId}`);
      const scope = JSON.parse(state.requestedScope);
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
      approvals.set(requestId, installApproval);
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
            decidedAt: Math.floor(Date.now() / 1000),
            approvedPolicy: scope.policy,
            capabilityHash: kernelAllChainCapabilityHash(installApproval),
            installApproval,
          }),
        }),
      });
      expect(typeof decided.code === "string", "the owner console could not record a decision");
    },
    async removePermission(requestId) {
      const approval = approvals.get(requestId);
      expect(approval !== undefined, "the console never approved this request");
      // The removal is derived from the same packages the approval installed;
      // no second description of the permission exists to drift.
      const bound = await ownerRuntime.bindAccount({
        accountIndex: "0",
        initialPackages: [...ownerRuntime.packages],
      });
      const calls = encodeKernelV4PermissionUninstallCalls({
        account: approval.account,
        packages: approval.packages,
      });
      const quote = await chain.capability.quote({
        chainId: CHAIN_ID,
        kind: "revocation",
        signer: "owner",
        account: bound.account,
        calls,
        paymaster: null,
      });
      const prepared = ownerRuntime.prepareOperation({
        kind: "revocation",
        grantId: `owner-removal-${requestId}`,
        account: bound,
        nonceKey: quote.nonceKey,
        sequence: quote.sequence,
        calls,
        gas: quote.gas,
      });
      const signature = await ownerRuntime.signOperation(prepared);
      // Through the relay's own HTTP surface as the owner role: the exact
      // lane the invalidation gate keeps open after the capability died.
      const submitted = await ownerFetch(`/chains/${CHAIN_ID}/submissions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          request: {
            prepared,
            signature,
            route: "entrypoint-handleops",
            feePayer: chain.capability.feePayer,
          },
        }),
      });
      expect(
        submitted.present === true &&
          submitted.result?.userOperationHash === prepared.userOperationHash,
        "the relay refused the owner removal",
      );
      return prepared.userOperationHash;
    },
  };
}

// The owner decides as each request appears, exactly as a phone would react
// to a push: this demo polls the same relay the client uses.
const owner = await ownerConsole();
const approvedRequests = new Set();
const clientFetch = async (request) => {
  const authorized = new Request(request, {
    headers: { ...Object.fromEntries(request.headers), authorization: `Bearer ${CLIENT_TOKEN}` },
  });
  const response = await fetch(authorized);
  if (
    request.method === "POST" &&
    new URL(request.url).pathname === "/authorization/requests" &&
    response.status === 201
  ) {
    const { requestId } = await response.clone().json();
    if (!approvedRequests.has(requestId)) {
      approvedRequests.add(requestId);
      await owner.approve(requestId);
    }
  }
  return response;
};

step("URL-only client: connect, request permission, execute, read the receipt");
const oaath = createOAAth({
  url,
  fetch: clientFetch,
  origin: APP_ORIGIN,
});
const connection = await oaath.connect();
say(
  `  account profile  index ${oaath.binding.account.accountIndex}, owner ${ownerCredential.address}`,
);
const target = `0x${"44".repeat(20)}`;
const selector = "0xa9059cbb";
const grant = await connection.requestPermission({
  chainScope: "all",
  permissions: [{ calls: [{ target, selectors: [selector], valueLimit: "1000" }] }],
  expiresIn: 1800,
  perChainOperationLimit: 10,
});
expect(grant.state === "active", `the Grant is ${grant.state}`);
say(`  grant            active; account ${await grant.account(CHAIN_ID)}`);

const operation = await grant.sendCalls({
  chain: CHAIN_ID,
  calls: [{ target, value: "5", data: `${selector}${"0".repeat(128)}` }],
});
const outcome = await operation.wait();
expect(outcome.status === "finalized", `the operation is ${outcome.status}`);
expect(outcome.outcome === "success", `the call ${outcome.outcome}`);
const receipt = await operation.receipt();
say(
  `  finalized        ${outcome.transactionHash} (block ${receipt.blockNumber}, ${receipt.gasUsed} gas)`,
);
expect(receipt.status === "success", "the receipt disagrees with the outcome");

step("revoke");
await grant.revoke();
expect(grant.state === "revoking", `the Grant is ${grant.state}`);
say(
  "  grant            revoking: the capability is dead at the service; the chain permission awaits owner-signed removal",
);

step("owner console removes the chain permission through the relay owner lane");
const removalRequestId = [...approvedRequests][0];
const removalHash = await owner.removePermission(removalRequestId);
say(`  removal          ${removalHash} (owner-signed uninstall, submitted as the owner role)`);

step("the client observes the removal and completes revocation");
await grant.revoke();
expect(grant.state === "revoked", `the Grant is ${grant.state}`);
say("  grant            revoked: the chain itself proved the permission absent");

await connection.close();
await oaath.close();
server.close();
chain.stop();
say("\nservice example: ok");
