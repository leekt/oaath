/** OAAth-owned local-chain fixture for external consumers. Never a production dependency. */
import {
  hashPermissionRequest,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  parseGrantPolicy,
} from "@oaath/protocol";
import { createOAAth, type Oaath } from "@oaath/sdk";
import { deriveSessionPolicyProfiles } from "@oaath/sdk/advanced";
import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  ecdsaKey,
  kernelAllChainCapabilityHash,
  kernelPermissionInstallNonce,
  kernelV4Deployment,
  ownerOperator,
  sessionOperator,
} from "@oaath/sdk/kernel";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbPreparedCallStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  type OaathDatabase,
  openOaathDatabase,
} from "@oaath/sdk/persistence";
import { createMemoryRelayStore, createRelayHandler, type RelayCaller } from "@oaath/server";
import { IDBFactory } from "fake-indexeddb";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createAnvilChain } from "./anvil-chain.mjs";

export interface LocalAnvilFixture {
  readonly chainIds: readonly number[];
  /** Loopback-only URL for ordinary public-chain reads by the consumer. */
  readonly rpcUrl: (chainId: number) => string;
  /** Closes prior SDK/database instances and opens a new client over retained state. */
  readonly openClient: () => Promise<Readonly<Oaath>>;
  readonly closeClient: () => Promise<void>;
  readonly approvalCount: number;
  readonly submissionCount: number;
  /** Attempts client, database, and every local process cleanup. */
  readonly close: () => Promise<void>;
}

/**
 * Starts one or two owned Anvil chains with the real pinned Kernel runtime.
 * Requests are approved by a local test owner; this is never a production
 * authorization service. No credentials, signatures, or raw errors escape.
 */
export async function createLocalAnvilFixture(
  input: Readonly<{ chainIds?: readonly number[] }> = {},
): Promise<Readonly<LocalAnvilFixture>> {
  const chainIds = [...(input.chainIds ?? [421_614])];
  if (
    chainIds.length < 1 ||
    chainIds.length > 2 ||
    new Set(chainIds).size !== chainIds.length ||
    chainIds.some((id) => !Number.isSafeInteger(id) || id < 1)
  ) {
    throw new Error("local_fixture_chains_invalid");
  }
  const chains = new Map<number, Awaited<ReturnType<typeof createAnvilChain>>>();
  try {
    for (const id of chainIds) chains.set(id, await createAnvilChain(id));
  } catch {
    for (const chain of chains.values()) chain.stop();
    throw new Error("local_fixture_start_failed");
  }
  const first = chains.values().next().value;
  const firstChainId = chainIds[0];
  if (!first || firstChainId === undefined) throw new Error("local_fixture_chains_invalid");
  const now = () => Math.floor(Date.now() / 1000);
  const owner = privateKeyToAccount(generatePrivateKey());
  const session = privateKeyToAccount(generatePrivateKey());
  const issuerUrl = "https://local-fixture.example";
  const redirectUri = "https://consumer.example/callback";
  const clientToken = crypto.randomUUID();
  const ownerToken = crypto.randomUUID();
  const kms = new Map<string, string>();
  const callers = new Map<string, RelayCaller>([
    [
      clientToken,
      {
        role: "client",
        clientId: "fixture-client",
        subject: "fixture-subject",
        redirectUris: [redirectUri],
        organizationAudience: null,
      },
    ],
    [
      ownerToken,
      {
        role: "owner",
        clientId: "fixture-owner",
        subject: "fixture-subject",
        redirectUris: [],
        organizationAudience: null,
      },
    ],
  ]);
  const relay = createRelayHandler({
    ownerRouting: {
      async resolveOwner() {
        return { ownerDeviceId: "fixture-owner", ownerSubject: "fixture-subject" };
      },
    },
    store: createMemoryRelayStore(),
    authentication: {
      async authenticate(request) {
        const header = request.headers.get("authorization") ?? "";
        return callers.get(header.startsWith("Bearer ") ? header.slice(7) : "") ?? null;
      },
    },
    kms: {
      async encrypt(plaintext) {
        const id = crypto.randomUUID();
        kms.set(id, plaintext);
        return id;
      },
      async decrypt(id) {
        const value = kms.get(id);
        if (value === undefined) throw new Error("fixture_record_missing");
        return value;
      },
    },
    clock: { now: () => now() * 1000 },
  });
  function authorized(request: Request, token: string): Request {
    const headers = new Headers(request.headers);
    headers.set("authorization", `Bearer ${token}`);
    return new Request(request, { headers });
  }
  let approvalCount = 0;
  const authorization = {
    async authorize({ requestId }: { readonly requestId: string }) {
      approvalCount += 1;
      const stateResponse = await relay(
        authorized(new Request(`${issuerUrl}/authorization/requests/${requestId}`), ownerToken),
      );
      if (!stateResponse.ok) throw new Error("fixture_authorization_unavailable");
      const state = await stateResponse.json();
      const scope = JSON.parse(state.requestedScope);
      const ownerKey = ecdsaKey({ account: owner, validator: first.validator });
      const deployment = kernelV4Deployment(firstChainId);
      const ownerRuntime = createKernelRuntime({
        deployment,
        operator: ownerOperator({ key: ownerKey }),
        reads: first.capability.reads,
      });
      const descriptor = await ownerRuntime.bindAccount({
        accountIndex: "0",
        initialPackages: [...ownerRuntime.packages],
      });
      const sessionRuntime = createKernelRuntime({
        deployment,
        operator: sessionOperator({
          key: ecdsaKey({ account: session, validator: first.validator }),
          policies: deriveSessionPolicyProfiles(parseGrantPolicy(scope.policy)),
        }),
        reads: first.capability.reads,
      });
      const requestHash = hashPermissionRequest({ ...scope, requestId });
      const installApproval = await approveKernelPermissionAllChain({
        owner: ownerKey,
        account: descriptor.account,
        installNonce: kernelPermissionInstallNonce(requestHash),
        packages: [...sessionRuntime.packages],
      });
      const response = await relay(
        authorized(
          new Request(`${issuerUrl}/authorization/requests/${requestId}/decision`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              outcome: "approved",
              artifact: JSON.stringify({
                version: OAATH_PERMISSION_DECISION_VERSION,
                kind: "approve",
                requestId,
                requestHash,
                decidedAt: now(),
                approvedPolicy: scope.policy,
                capabilityHash: kernelAllChainCapabilityHash(installApproval),
                installApproval,
              }),
            }),
          }),
          ownerToken,
        ),
      );
      if (!response.ok) throw new Error("fixture_decision_failed");
      const result = await response.json();
      if (typeof result.code !== "string") throw new Error("fixture_decision_failed");
      return { code: result.code };
    },
  };
  const factory = new IDBFactory();
  let client: Readonly<Oaath> | undefined;
  let database: OaathDatabase | undefined;
  let closed = false;
  async function closeClient(): Promise<void> {
    const results = await Promise.allSettled([
      client?.close().then(() => {
        client = undefined;
      }),
    ]);
    // SDK resource cleanup must finish before closing its backing connection.
    results.push(
      ...(await Promise.allSettled([
        Promise.resolve().then(() => {
          database?.close();
          database = undefined;
        }),
      ])),
    );
    if (results.some((result) => result.status === "rejected"))
      throw new Error("local_fixture_cleanup_failed");
  }
  return Object.freeze({
    chainIds: Object.freeze(chainIds),
    rpcUrl(chainId: number): string {
      const chain = chains.get(chainId);
      if (!chain) throw new Error("local_fixture_chain_unknown");
      return chain.url;
    },
    get approvalCount() {
      return approvalCount;
    },
    get submissionCount() {
      return [...chains.values()].reduce((count, chain) => count + chain.sends.length, 0);
    },
    async openClient(): Promise<Readonly<Oaath>> {
      if (closed) throw new Error("local_fixture_closed");
      await closeClient();
      database = await openOaathDatabase({ factory });
      client = createOAAth({
        binding: {
          issuer: issuerUrl,
          applicationId: "fixture-application",
          applicationName: "Local SDK Consumer",
          clientId: "fixture-client",
          origin: "https://consumer.example",
          redirectUri,
          deviceId: "fixture-device",
          userHandle: "fixture-user",
          context: {
            version: "oaath.workspace-account-context/v1",
            workspaceId: "fixture-workspace",
            workspaceKind: "personal",
            accountId: "fixture-account",
          },
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
              address: owner.address.toLowerCase(),
            },
          },
          operatorCredential: {
            version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
            kind: "ecdsa",
            address: session.address.toLowerCase(),
          },
        },
        issuer: {
          url: issuerUrl,
          fetch: (request: Request) => relay(authorized(request, clientToken)),
          async signOut() {},
        },
        authorization,
        // This fixture proves execution only and must never fabricate revocation evidence.
        invalidation: {
          async invalidateCapability() {
            throw new Error("local_fixture_revocation_unsupported");
          },
        },
        stores: {
          grants: createIndexedDbGrantStoreAdapter(database),
          operations: createIndexedDbOperationStoreAdapter(database),
          walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
          preparedCallContexts: createIndexedDbPreparedCallStoreAdapter(database),
          keys: createIndexedDbKeyStore(database),
          cleanup: createIndexedDbCleanupStore(database),
          context: createIndexedDbContextStore(database),
        },
        chains: [...chains.values()].map((chain) => chain.capability),
        signing: {
          owner: ecdsaKey({ account: owner, validator: first.validator }),
          session: ecdsaKey({ account: session, validator: first.validator }),
        },
        localKeyIds: [],
        now,
      });
      return client;
    },
    closeClient,
    async close(): Promise<void> {
      const results = await Promise.allSettled([
        closeClient(),
        ...[...chains.values()].map(async (chain) => {
          chain.stop();
        }),
      ]);
      if (results.some((result) => result.status === "rejected"))
        throw new Error("local_fixture_cleanup_failed");
      kms.clear();
      closed = true;
    },
  });
}
