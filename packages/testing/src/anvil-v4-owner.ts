/**
 * Deploy an existing Kernel v4 account whose root validator exposes its owner
 * onchain (the reviewed ECDSA validator or the pinned raw P-256 validator), so
 * owner mode can prove the owner.
 */
import {
  createKernelRuntime,
  type KeyProfile,
  kernelDeployment,
  ownerOperator,
} from "@oaath/sdk/kernel";
import type { Hex } from "viem";
import v33 from "../../sdk/test/fixtures/kernel-v33-deployments.json" with { type: "json" };
import type { deployKernelStack, startAnvil } from "./anvil-process.mjs";

export async function deployLocalV4OwnerAccount(
  chain: Awaited<ReturnType<typeof startAnvil>>,
  stack: Awaited<ReturnType<typeof deployKernelStack>>,
  owner: Readonly<KeyProfile>,
): Promise<Hex> {
  const deployed = await stack.wallet.sendTransaction({
    account: stack.submitter,
    chain: null,
    to: kernelDeployment({ chainId: chain.chainId }).create2Deployer,
    data: v33.ecdsaValidator.deploymentInput as Hex,
    gas: 10_000_000n,
  });
  if ((await chain.client.waitForTransactionReceipt({ hash: deployed })).status !== "success")
    throw new Error("local_fixture_deployment_failed");
  const runtime = createKernelRuntime({
    deployment: kernelDeployment({ chainId: chain.chainId }),
    operator: ownerOperator({ key: owner }),
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
