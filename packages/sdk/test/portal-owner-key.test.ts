/**
 * An owner realm whose key is the account root in the OAAth portal: the
 * realm's own prepared operation is shown as one exact owner-operation
 * request, the root signs it there, and the realm submits it through its
 * routes. Kernel 0.3.3, as Orchestra's org accounts.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOAAth, portalOwnerKey } from "../src/index.js";
import type { KernelReadRequest } from "../src/kernel/deployment/account.js";
import { kernelDeployment } from "../src/kernel.js";
import type { KernelV4AccountReadRequest } from "../src/kernel-v4.js";
import { createMemoryOperationStoreAdapter } from "../src/persistence/memory/stores.js";
import { ACCOUNT, CHAIN_ID, createChainFixture, sendCallsInput } from "./support/browser.js";
import { installOAuthPortal } from "./support/oauth-portal.js";

afterEach(() => vi.unstubAllGlobals());

function v33Chain(owner: `0x${string}`) {
  const base = createChainFixture();
  const deployment = kernelDeployment({ chainId: CHAIN_ID, kernelVersion: "0.3.3" });
  return {
    base,
    chain: {
      ...base.capability,
      reads: {
        async read(request: KernelReadRequest): Promise<unknown> {
          if (request.type === "code") return "0x6000";
          if (request.type === "kernel_account_implementation") return deployment.implementation;
          if (request.type === "kernel_account_version") return "kernel.advanced.v0.3.3";
          if (request.type === "kernel_account_entrypoint") return deployment.entryPoint.address;
          if (request.type === "kernel_account_root_validator")
            return `0x01${deployment.ecdsaValidator.slice(2)}`;
          if (request.type === "kernel_ecdsa_owner") return owner;
          return base.capability.reads.read(request as KernelV4AccountReadRequest);
        },
      },
    },
  };
}

describe("portalOwnerKey", () => {
  it("has the root sign the realm's exact operation in the portal, then submits it", async () => {
    const root = privateKeyToAccount(generatePrivateKey());
    const ownerAddress = root.address.toLowerCase() as `0x${string}`;
    const account = {
      version: "oaath.kernel-existing-account-profile/v1",
      kind: "kernel",
      kernelVersion: "0.3.3",
      address: ACCOUNT,
      entryPoint: { version: "0.7" },
      ownerCredential: {
        version: "oaath.owner-credential-profile/v1",
        kind: "ecdsa",
        address: ownerAddress,
      },
    } as const;
    const seen: unknown[] = [];
    const { approvals, launch } = await installOAuthPortal({
      signOperation: async (request) => {
        seen.push(request);
        const { userOperationHash } = request as { userOperationHash: `0x${string}` };
        return {
          version: "oaath.signed-owner-operation/v1",
          request,
          // As the portal's wallet signs: personal_sign over the raw hash (EIP-191).
          signature: await root.signMessage({ message: { raw: userOperationHash } }),
        };
      },
    });
    const { kind: _, ...login } = approvals;
    const { base, chain } = v33Chain(ownerAddress);
    const client = createOAAth({
      chains: [chain],
      stores: { kind: "memory", operations: createMemoryOperationStoreAdapter() },
    });
    try {
      const owner = client.account(ACCOUNT).owner(portalOwnerKey({ ...login, account, launch }));
      const operation = await owner.sendCalls(sendCallsInput());
      const done = await operation.wait();
      expect(done.status).toBe("finalized");
      // The portal saw the realm's own operation, on EntryPoint 0.7.
      expect(seen).toHaveLength(1);
      expect(seen[0]).toMatchObject({
        account,
        chainId: CHAIN_ID,
        entryPoint: "0x0000000071727de22e5e9d8baf0edac6f37da032",
        userOperation: { sender: ACCOUNT },
      });
      expect(base.sends).toHaveLength(1);
    } finally {
      await client.close();
    }
  });

  it("refuses a portal signature that is not the root's", async () => {
    const root = privateKeyToAccount(generatePrivateKey());
    const other = privateKeyToAccount(generatePrivateKey());
    const ownerAddress = root.address.toLowerCase() as `0x${string}`;
    const { approvals, launch } = await installOAuthPortal({
      signOperation: async (request) => ({
        version: "oaath.signed-owner-operation/v1",
        request,
        signature: await other.signMessage({
          message: { raw: (request as { userOperationHash: `0x${string}` }).userOperationHash },
        }),
      }),
    });
    const { kind: _, ...login } = approvals;
    const { base, chain } = v33Chain(ownerAddress);
    const client = createOAAth({
      chains: [chain],
      stores: { kind: "memory", operations: createMemoryOperationStoreAdapter() },
    });
    try {
      const account = {
        version: "oaath.kernel-existing-account-profile/v1",
        kind: "kernel",
        kernelVersion: "0.3.3",
        address: ACCOUNT,
        entryPoint: { version: "0.7" },
        ownerCredential: {
          version: "oaath.owner-credential-profile/v1",
          kind: "ecdsa",
          address: ownerAddress,
        },
      } as const;
      const owner = client.account(ACCOUNT).owner(portalOwnerKey({ ...login, account, launch }));
      // The portal refuses another key's signature before the realm sees it.
      const failed = await owner.sendCalls(sendCallsInput()).then(
        (operation) => operation.wait(),
        (error: unknown) => ({ status: "refused", error }),
      );
      expect(failed.status).not.toBe("finalized");
      expect(base.sends).toHaveLength(0);
    } finally {
      await client.close();
    }
  });
});
