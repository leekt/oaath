/** OAAth-owned local-chain fixture for external consumers. Never a production dependency. */
import {
  hashPermissionRequest,
  OAATH_PERMISSION_DECISION_VERSION,
  type PermissionRequest,
} from "@oaath/protocol";
import { createOAAth, type Oaath } from "@oaath/sdk";
import type { OaathChainCapability, OaathSubmissionCapability } from "@oaath/sdk/advanced";
import { deriveSessionPolicyProfiles } from "@oaath/sdk/advanced";
import {
  approveKernelPermission,
  bindKernelAccount,
  createKernelRuntime,
  kernelAccountDeployment,
  kernelDeployment,
  kernelKey,
  kernelPermissionCapabilityHash,
  kernelPermissionNonce,
  ownerOperator,
  sessionOperator,
} from "@oaath/sdk/kernel";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { IDBFactory } from "fake-indexeddb";
import { localClientBinding } from "./anvil-binding.js";
import { createAnvilChain } from "./anvil-chain.mjs";
import { captureLocalAnvilRecovery, type LocalAnvilRecovery } from "./anvil-recovery.js";
import { openLocalClientStores } from "./anvil-stores.js";

export { createLocalOwnerAnvilFixture, type LocalOwnerAnvilFixture } from "./anvil-owner.js";
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

/** The local chain's handleOps fee payer, retained for recovery. */
function handleOpsFeePayer(
  capability: Readonly<{ routes: readonly Readonly<{ kind: string; feePayer?: unknown }>[] }>,
): unknown {
  const route = capability.routes.find((entry) => entry.kind === "erc4337-handleops");
  if (route === undefined) throw new Error("local_fixture_fee_payer_missing");
  return route.feePayer;
}

/**
 * Starts one or two owned Anvil chains with the real pinned Kernel runtime.
 * Requests are approved by a local test owner; this is never a production
 * authorization service. No credentials, signatures, or raw errors escape.
 */
export async function createLocalAnvilFixture(
  input: Readonly<{
    chainIds?: readonly number[];
    stateDirectory?: string;
    kernelVersion?: "0.4.0" | "0.3.3";
    /**
     * Test-only interposition on the SDK's submission capability, e.g. to hold
     * one accepted send. The fixture never retries or replays on its behalf.
     */
    submission?: (open: OaathSubmissionCapability["open"]) => OaathSubmissionCapability["open"];
  }> = {},
): Promise<Readonly<LocalAnvilFixture>> {
  const version = input.kernelVersion ?? "0.4.0";
  if (version !== "0.4.0" && version !== "0.3.3") throw new Error("local_fixture_kernel_invalid");
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
  const owner = privateKeyToAccount(generatePrivateKey());
  const session = privateKeyToAccount(generatePrivateKey());
  try {
    for (const id of chainIds)
      chains.set(
        id,
        await createAnvilChain(id, { existingOwner: version === "0.3.3" ? owner.address : null }),
      );
  } catch {
    for (const chain of chains.values()) chain.stop();
    throw new Error("local_fixture_start_failed");
  }
  const first = chains.values().next().value;
  const firstChainId = chainIds[0];
  if (!first || firstChainId === undefined) throw new Error("local_fixture_chains_invalid");
  const now = () => Math.floor(Date.now() / 1000);
  if ([...chains.values()].some((chain) => chain.existingAccount !== first.existingAccount)) {
    for (const chain of chains.values()) chain.stop();
    throw new Error("local_fixture_account_mismatch");
  }
  let approvalCount = 0;
  /** The fixture owner approves every reviewed request, as an owner device would. */
  const approving = first;
  const approvingChainId = firstChainId;
  async function approve(request: Readonly<PermissionRequest>): Promise<unknown> {
    approvalCount += 1;
    const ownerKey = kernelKey({ account: owner, validator: approving.validator });
    // Like an owner device: the packages bind the operator credential the
    // owner reviewed, never a key the application holds.
    const sessionKey = kernelKey({ credential: request.operatorCredential, validator: null });
    const requestHash = hashPermissionRequest(request);
    const reads = approving.capability.reads;
    const sessionOperatorProfile = sessionOperator({
      key: sessionKey,
      policies: deriveSessionPolicyProfiles(request.policy),
    });
    // An existing account names its own deployment; a derived one uses the default.
    const existing =
      approving.existingAccount === null
        ? null
        : await bindKernelAccount({
            chainId: approvingChainId,
            address: approving.existingAccount,
            reads,
          });
    const deployment =
      existing === null
        ? kernelDeployment({ chainId: approvingChainId })
        : kernelAccountDeployment(existing);
    const runtime = createKernelRuntime({ deployment, operator: sessionOperatorProfile, reads });
    const ownerRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({ key: ownerKey }),
      reads,
    });
    const account =
      approving.existingAccount !== null
        ? await runtime.bindAccount({ address: approving.existingAccount })
        : await ownerRuntime.bindAccount({
            accountIndex: "0",
            initialPackages: [...ownerRuntime.packages],
          });
    const installApproval = await approveKernelPermission({
      owner: ownerKey,
      runtime,
      account,
      nonce: await kernelPermissionNonce({ runtime, account, reads, requestHash }),
    });
    return {
      version: OAATH_PERMISSION_DECISION_VERSION,
      kind: "approve",
      requestId: request.requestId,
      requestHash,
      decidedAt: now(),
      approvedPolicy: request.policy,
      capabilityHash: kernelPermissionCapabilityHash(installApproval),
      installApproval,
    };
  }
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
            existingAccount: first.existingAccount,
            owner: owner.address,
            session: session.address,
            chains: [...chains.values()].map((chain) => ({
              chainId: chain.capability.chainId,
              rpcUrl: chain.url,
              validator: chain.validator,
              feePayer: handleOpsFeePayer(chain.capability),
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
        binding: localClientBinding(owner.address, session.address, first.existingAccount),
        approve,
        // This fixture proves execution only and must never fabricate revocation evidence.
        invalidation: {
          async invalidateCapability() {
            throw new Error("local_fixture_revocation_unsupported");
          },
        },
        stores: storage.stores,
        // The fixture chain capability is authored in JavaScript.
        chains: [...chains.values()].map((chain) =>
          input.submission === undefined
            ? chain.capability
            : {
                ...chain.capability,
                submission: { open: input.submission(chain.capability.submission.open) },
              },
        ) as readonly OaathChainCapability[],
        signing: {
          owner: kernelKey({ account: owner, validator: first.validator }),
          session: kernelKey({ account: session, validator: first.validator }),
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
      closed = true;
    },
  });
}
