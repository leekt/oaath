/**
 * A portal account's root approves one exact owner operation offline, and the
 * holder of the signed artifact verifies and submits it. For each root kind the
 * operation deploys the factory-derived account and executes its call through
 * a local bundler; a tampered artifact is refused before anything is sent, and
 * a reload observes the receipt by hash without resubmitting. The same account,
 * then imported as an existing profile, executes its next owner operation.
 */
import { OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION } from "@oaath/protocol";
import { getSigningHash, type Operation } from "cetane/execution/erc4337";
import { encodeFunctionData, parseEther } from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { afterAll, describe, expect, it } from "vitest";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import { credentialKey } from "../src/kernel/key/credential.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { kernelDeployment, prepareOwnerOperation, verifyOwnerOperation } from "../src/kernel.js";
import type { AnvilChain, KernelHarness } from "./support/anvil.js";
import { startPortalChain } from "./support/portal-chain.js";
import {
  PORTAL_ORIGIN,
  PORTAL_RP_ID,
  type PortalRootKind,
  portalRoot,
} from "./support/portal-roots.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
const CHAIN_ID = 8_453;
const RELYING_PARTY = { rpId: PORTAL_RP_ID, origin: PORTAL_ORIGIN };
const gas = Object.freeze({
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
});

const chains: AnvilChain[] = [];
afterAll(() => {
  for (const chain of chains) chain.stop();
});

/** A local ERC-4337 bundler: it counts sends and reads receipts from EntryPoint logs. */
function fixtureBundler(harness: KernelHarness) {
  let sends = 0;
  return {
    sends: () => sends,
    async sendUserOperation(wire: Record<string, `0x${string}`>, entryPoint: `0x${string}`) {
      sends++;
      const quantity = (key: string) => BigInt(wire[key] as string);
      const operation: Operation = {
        sender: wire.sender as `0x${string}`,
        nonce: quantity("nonce"),
        callData: wire.callData as `0x${string}`,
        callGasLimit: quantity("callGasLimit"),
        verificationGasLimit: quantity("verificationGasLimit"),
        preVerificationGas: quantity("preVerificationGas"),
        maxFeePerGas: quantity("maxFeePerGas"),
        maxPriorityFeePerGas: quantity("maxPriorityFeePerGas"),
        signature: wire.signature as `0x${string}`,
        ...(wire.factory ? { factory: wire.factory, factoryData: wire.factoryData } : {}),
      };
      const hash = await harness.wallet.sendTransaction({
        account: harness.submitter,
        chain: null,
        to: entryPoint,
        gas: 8_000_000n,
        data: encodeFunctionData({
          abi: entryPoint07Abi,
          functionName: "handleOps",
          args: [
            [toPackedUserOperation({ ...operation, factory: operation.factory })],
            harness.submitter.address,
          ],
        }),
      });
      expect((await harness.client.waitForTransactionReceipt({ hash })).status).toBe("success");
      return getSigningHash(operation, CHAIN_ID, entryPoint, "0.9");
    },
    async getUserOperationReceipt(entryPoint: `0x${string}`, userOpHash: `0x${string}`) {
      const logs = await harness.client.getContractEvents({
        address: entryPoint,
        abi: entryPoint07Abi,
        eventName: "UserOperationEvent",
        args: { userOpHash },
        fromBlock: 0n,
      });
      return logs.length === 1 ? { success: logs[0]?.args.success } : null;
    },
  };
}

(requireAnvil ? describe : describe.skip)("portal account roots approve owner operations", () => {
  it.each<PortalRootKind>(["ecdsa", "p256", "webauthn"])(
    "%s root: sign offline, refuse tampering, deploy and execute, observe after reload",
    async (kind) => {
      const harness = await startPortalChain(CHAIN_ID, chains);
      const root = portalRoot(kind);
      const target = `0x${"7a".repeat(20)}` as const;
      const input = {
        account: {
          version: "oaath.kernel-account-profile/v1",
          kind: "kernel",
          accountIndex: "0",
          kernelVersion: "0.4.0",
          factoryRoute: "kernel_factory",
          entryPoint: { version: "0.9" },
          ownerCredential: root.credential,
        },
        chainId: CHAIN_ID,
        deployed: false,
        calls: [{ target, value: "500", data: "0x" }],
        nonce: { lane: "0", sequence: "0" },
        gas,
      } as const;
      const prepared = prepareOwnerOperation(input);
      // The offline-derived sender is the factory's own counterfactual address.
      const owner = createKernelRuntime({
        deployment: kernelDeployment({ chainId: CHAIN_ID }),
        operator: ownerOperator({
          key: credentialKey({ credential: root.credential, validator: root.validator }),
        }),
        reads: harness.reads,
      });
      const account = await owner.bindAccount({
        accountIndex: "0",
        initialPackages: owner.packages,
      });
      expect(prepared.request.userOperation.sender).toBe(account.account);
      expect(account.state).toBe("counterfactual");

      await expect(prepared.sign(portalRoot(kind, "other").key)).rejects.toMatchObject({
        code: "kernel_runtime_binding_mismatch",
      });
      // The signed artifact crosses from the portal to the dapp as JSON.
      const stored = JSON.stringify(await prepared.sign(root.key));
      await harness.fund(account.account, parseEther("1"));
      const bundler = fixtureBundler(harness);

      // A re-encoded, re-hashed operation with a larger value keeps the root's
      // signature, and is refused before it is sent.
      const tampered = {
        ...JSON.parse(stored),
        request: prepareOwnerOperation({
          ...input,
          calls: [{ target, value: "5000", data: "0x" }],
        }).request,
      };
      await expect(verifyOwnerOperation(tampered, RELYING_PARTY)).rejects.toMatchObject({
        code: "kernel_runtime_signature_invalid",
      });
      expect(bundler.sends()).toBe(0);

      const verified = await verifyOwnerOperation(JSON.parse(stored), RELYING_PARTY);
      expect(
        await bundler.sendUserOperation({ ...verified.userOperation }, verified.entryPoint),
      ).toBe(prepared.request.userOperationHash);
      expect(await harness.client.getBalance({ address: target })).toBe(500n);
      expect(await harness.client.getCode({ address: account.account })).toBeTruthy();

      // Reload: only the stored artifact survives. Observation reads by hash and sends nothing.
      const reloaded = await verifyOwnerOperation(JSON.parse(stored), RELYING_PARTY);
      expect(
        await bundler.getUserOperationReceipt(
          reloaded.entryPoint,
          reloaded.signed.request.userOperationHash,
        ),
      ).toEqual({ success: true });
      expect(bundler.sends()).toBe(1);

      // The same deployed account, imported as an existing profile: the next
      // owner operation executes at its own address, with no factory.
      const imported = prepareOwnerOperation({
        ...input,
        account: {
          version: OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
          kind: "kernel",
          address: account.account,
          kernelVersion: "0.4.0",
          entryPoint: { version: "0.9" },
          ownerCredential: root.credential,
        },
        deployed: true,
        nonce: { lane: "0", sequence: "1" },
      });
      expect(imported.request.userOperation.sender).toBe(account.account);
      expect(imported.request.userOperation.factory).toBeNull();
      const importedVerified = await verifyOwnerOperation(
        JSON.parse(JSON.stringify(await imported.sign(root.key))),
        RELYING_PARTY,
      );
      expect(
        await bundler.sendUserOperation(
          { ...importedVerified.userOperation },
          importedVerified.entryPoint,
        ),
      ).toBe(imported.request.userOperationHash);
      expect(await harness.client.getBalance({ address: target })).toBe(1000n);
    },
    120_000,
  );
});
