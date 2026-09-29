/**
 * #238 acceptance: one consumer path, with no Kernel or EntryPoint version
 * literal, binds and sends owner calls through an existing Kernel v3.3 and an
 * existing Kernel v4 account on local Anvil. A deployment that disagrees with
 * the account fails with one structured code before any signing.
 */
import type { OaathOwnerClient } from "@oaath/sdk";
import {
  bindKernelAccount,
  createKernelReads,
  createKernelRuntime,
  kernelAccountDeployment,
  kernelDeployment,
  kernelKey,
  ownerOperator,
} from "@oaath/sdk/kernel";
import { createPublicClient, http } from "viem";
import { describe, expect, it } from "vitest";
import { createLocalOwnerAnvilFixture, type LocalOwnerAnvilFixture } from "../src/anvil-owner.js";

const target = `0x${"44".repeat(20)}` as const;

/** The adopter code under test. Nothing here names a Kernel or EntryPoint version. */
async function sendOwnerCalls(
  input: Readonly<{
    chainId: number;
    rpcUrl: string;
    address: `0x${string}`;
    client: Readonly<OaathOwnerClient>;
    wallet: LocalOwnerAnvilFixture["wallet"];
  }>,
) {
  const reads = createKernelReads(
    createPublicClient({ transport: http(input.rpcUrl, { retryCount: 0 }) }),
  );
  const account = await bindKernelAccount({
    chainId: input.chainId,
    address: input.address,
    reads,
  });
  const owner = input.client.account(input.address).owner(input.wallet);
  const request = { chain: input.chainId, calls: [{ target, data: "0x", value: "1" }] };
  const review = await owner.reviewCalls(request);
  const operation = await owner.sendCalls(request);
  return { account, review, outcome: await operation.wait({ attempts: 3 }) };
}

(process.env.OAATH_REQUIRE_ANVIL === "1" ? describe : describe.skip)(
  "version-agnostic Kernel accounts",
  () => {
    it.each(["0.3.3", "0.4.0"] as const)(
      "binds and sends owner calls through an existing Kernel %s account",
      async (kernelVersion) => {
        const fixture = await createLocalOwnerAnvilFixture({ kernelVersion });
        try {
          const publicClient = createPublicClient({
            transport: http(fixture.rpcUrl, { retryCount: 0 }),
          });
          const before = await publicClient.getBalance({ address: target });
          const { account, review, outcome } = await sendOwnerCalls({
            chainId: fixture.chainId,
            rpcUrl: fixture.rpcUrl,
            address: fixture.address,
            client: await fixture.openClient(),
            wallet: fixture.wallet,
          });
          expect(account.account).toBe(fixture.address);
          expect(kernelAccountDeployment(account).kernelVersion).toBe(kernelVersion);
          expect(review).toMatchObject({
            kernelVersion,
            signer: "owner",
            route: "erc4337-bundler",
          });
          expect(outcome.status).toBe("finalized");
          expect(await publicClient.getBalance({ address: target })).toBe(before + 1n);
          expect(fixture.signatureCount).toBe(1);
          expect(fixture.bundlerSubmissionCount).toBe(1);
        } finally {
          await fixture.close();
        }
      },
    );

    it.each([
      ["0.3.3", "0.4.0"],
      ["0.4.0", "0.3.3"],
    ] as const)(
      "refuses a %s account under an explicit %s deployment before signing",
      async (kernelVersion, other) => {
        const fixture = await createLocalOwnerAnvilFixture({ kernelVersion });
        try {
          const reads = createKernelReads(
            createPublicClient({ transport: http(fixture.rpcUrl, { retryCount: 0 }) }),
          );
          const deployment = kernelDeployment({ chainId: fixture.chainId, kernelVersion: other });
          const mismatch = { code: "kernel_runtime_deployment_mismatch" };
          await expect(
            bindKernelAccount({
              chainId: fixture.chainId,
              address: fixture.address,
              reads,
              deployment,
            }),
          ).rejects.toMatchObject(mismatch);
          const validator = kernelDeployment({
            chainId: fixture.chainId,
            kernelVersion: "0.3.3",
          }).ecdsaValidator;
          const runtime = createKernelRuntime({
            deployment,
            operator: ownerOperator({ key: kernelKey({ wallet: fixture.wallet, validator }) }),
            reads,
          });
          await expect(runtime.bindAccount({ address: fixture.address })).rejects.toMatchObject(
            mismatch,
          );
          expect(fixture.signatureCount).toBe(0);
          expect(fixture.bundlerSubmissionCount).toBe(0);
        } finally {
          await fixture.close();
        }
      },
    );
  },
);
