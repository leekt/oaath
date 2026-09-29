/**
 * Deploy an existing ECDSA-root Kernel v4 account whose root validator is the
 * reviewed ECDSA validator, so owner mode can prove its owner onchain.
 */
import { KERNEL_V4_CREATE2_DEPLOYER } from "@oaath/sdk/advanced";
import { createKernelRuntime, kernelDeployment, kernelKey, ownerOperator } from "@oaath/sdk/kernel";
import type { Hex } from "viem";
import type { PrivateKeyAccount } from "viem/accounts";
import v33 from "../../sdk/test/fixtures/kernel-v33-deployments.json" with { type: "json" };
import type { deployKernelStack, startAnvil } from "./anvil-process.mjs";

export async function deployLocalV4OwnerAccount(
  chain: Awaited<ReturnType<typeof startAnvil>>,
  stack: Awaited<ReturnType<typeof deployKernelStack>>,
  owner: PrivateKeyAccount,
): Promise<Hex> {
  const validator = kernelDeployment({
    chainId: chain.chainId,
    kernelVersion: "0.3.3",
  }).ecdsaValidator;
  const deployed = await stack.wallet.sendTransaction({
    account: stack.submitter,
    chain: null,
    to: KERNEL_V4_CREATE2_DEPLOYER,
    data: v33.ecdsaValidator.deploymentInput as Hex,
    gas: 10_000_000n,
  });
  if ((await chain.client.waitForTransactionReceipt({ hash: deployed })).status !== "success")
    throw new Error("local_fixture_deployment_failed");
  const runtime = createKernelRuntime({
    deployment: kernelDeployment({ chainId: chain.chainId }),
    operator: ownerOperator({ key: kernelKey({ account: owner, validator }) }),
    reads: stack.reads,
  });
  const account = await runtime.bindAccount({
    initialPackages: runtime.packages,
    accountIndex: "0",
  });
  const hash = await stack.wallet.sendTransaction({
    account: stack.submitter,
    chain: null,
    to: account.factory,
    data: account.factoryDeployCalldata,
    gas: 10_000_000n,
  });
  if ((await chain.client.waitForTransactionReceipt({ hash })).status !== "success")
    throw new Error("local_fixture_account_failed");
  return account.account;
}
