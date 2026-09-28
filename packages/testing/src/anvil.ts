/** OAAth-owned local-chain fixture for external consumers. Never a production dependency. */
import {
  hashPermissionRequest,
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
import { createMemoryRelayStore, createRelayHandler, type RelayCaller } from "@oaath/server";
import { IDBFactory } from "fake-indexeddb";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { LOCAL_ISSUER, LOCAL_REDIRECT, localClientBinding } from "./anvil-binding.js";
import { createAnvilChain } from "./anvil-chain.mjs";
import { captureLocalAnvilRecovery, type LocalAnvilRecovery } from "./anvil-recovery.js";
import { openLocalClientStores } from "./anvil-stores.js";

export { type LocalAnvilRecovery, openLocalAnvilRecoveryClient } from "./anvil-recovery.js";

export interface LocalAnvilFixture {
  readonly chainIds: readonly number[];
  /** Owned Anvil PIDs for parent-harness cleanup after killing the client process. */
  readonly processIds: readonly number[];
  /** Public identities/endpoints only; present when stateDirectory is configured. */
  readonly recovery: Readonly<LocalAnvilRecovery> | null;
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
  input: Readonly<{ chainIds?: readonly number[]; stateDirectory?: string }> = {},
): Promise<Readonly<LocalAnvilFixture>> {
  const stateDirectory = input.stateDirectory;
  if (stateDirectory !== undefined && (typeof stateDirectory !== "string" || !stateDirectory))
    throw new Error("local_fixture_storage_invalid");
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
  const issuerUrl = LOCAL_ISSUER;
  const redirectUri = LOCAL_REDIRECT;
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
  let storage: Awaited<ReturnType<typeof openLocalClientStores>> | undefined;
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
        storage?.close().then(() => {
          storage = undefined;
        }),
      ])),
    );
    if (results.some((result) => result.status === "rejected"))
      throw new Error("local_fixture_cleanup_failed");
  }
  return Object.freeze({
    chainIds: Object.freeze(chainIds),
    processIds: Object.freeze(
      [...chains.values()].map((chain) => {
        if (chain.processId === undefined) throw new Error("local_fixture_process_missing");
        return chain.processId;
      }),
    ),
    recovery:
      stateDirectory === undefined
        ? null
        : captureLocalAnvilRecovery({
            version: "oaath.local-anvil-recovery/v1",
            owner: owner.address,
            session: session.address,
            chains: [...chains.values()].map((chain) => ({
              chainId: chain.capability.chainId,
              rpcUrl: chain.url,
              validator: chain.validator,
              feePayer: chain.capability.feePayer,
            })),
          }),
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
      storage = await openLocalClientStores(factory, stateDirectory);
      client = createOAAth({
        binding: localClientBinding(owner.address, session.address),
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
        stores: storage.stores,
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
