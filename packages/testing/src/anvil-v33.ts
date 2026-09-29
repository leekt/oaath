/** Deploy the real v3.3 account at the same address for each local fixture chain. */
import { KERNEL_V4_CREATE2_DEPLOYER, kernelV33Deployment } from "@oaath/sdk/kernel";
import { encodeFunctionData, type Hex, parseAbi, zeroAddress, zeroHash } from "viem";
import v33 from "../../sdk/test/fixtures/kernel-v33-deployments.json" with { type: "json" };
import type { deployKernelStack, startAnvil } from "./anvil-process.mjs";

export async function deployLocalV33Account(
  chain: Awaited<ReturnType<typeof startAnvil>>,
  stack: Awaited<ReturnType<typeof deployKernelStack>>,
  owner: Hex,
): Promise<Hex> {
  const deployment = kernelV33Deployment(chain.chainId);
  for (const module of [v33.kernel, v33.factory, v33.ecdsaValidator]) {
    const hash = await stack.wallet.sendTransaction({
      account: stack.submitter,
      chain: null,
      to: KERNEL_V4_CREATE2_DEPLOYER,
      data: module.deploymentInput as Hex,
      gas: 10_000_000n,
    });
    if ((await chain.client.waitForTransactionReceipt({ hash })).status !== "success")
      throw new Error("local_fixture_deployment_failed");
  }
  const init = encodeFunctionData({
    abi: parseAbi([
      "function initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
    ]),
    functionName: "initialize",
    args: [`0x01${deployment.ecdsaValidator.slice(2)}`, zeroAddress, owner, "0x", []],
  });
  const factoryAbi = parseAbi([
    "function createAccount(bytes data, bytes32 salt) returns (address)",
    "function getAddress(bytes data, bytes32 salt) view returns (address)",
  ]);
  const address = (
    await chain.client.readContract({
      address: deployment.factory,
      abi: factoryAbi,
      functionName: "getAddress",
      args: [init, zeroHash],
    })
  ).toLowerCase() as Hex;
  const creation = await stack.wallet.writeContract({
    account: stack.submitter,
    chain: null,
    address: deployment.factory,
    abi: factoryAbi,
    functionName: "createAccount",
    args: [init, zeroHash],
  });
  if ((await chain.client.waitForTransactionReceipt({ hash: creation })).status !== "success")
    throw new Error("local_fixture_account_failed");
  return address;
}
