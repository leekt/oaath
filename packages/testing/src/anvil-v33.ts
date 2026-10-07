/** Deploy the real v3.3 account at the same address for each local fixture chain. */

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { kernelDeployment } from "@oaath/sdk/kernel";
import type { Hex } from "cetane";
import { concatHex, encodeFunctionData, parseAbi } from "cetane/utils";

const zeroAddress = `0x${"00".repeat(20)}` as const;
const zeroHash = `0x${"00".repeat(32)}` as const;

import v33 from "../../sdk/test/fixtures/kernel-v33-deployments.json" with { type: "json" };
import type { deployKernelStack, startAnvil } from "./anvil-process.mjs";

export async function deployLocalV33Account(
  chain: Awaited<ReturnType<typeof startAnvil>>,
  stack: Awaited<ReturnType<typeof deployKernelStack>>,
  owner: Hex,
): Promise<Hex> {
  const deployment = kernelDeployment({ chainId: chain.chainId, kernelVersion: "0.3.3" });
  const entryPoint = JSON.parse(
    await readFile(createRequire(import.meta.url).resolve(v33.entryPoint.artifact), "utf8"),
  );
  const entryPointHash = await stack.wallet.sendTransaction({
    account: stack.submitter,
    to: deployment.create2Deployer,
    data: concatHex([v33.entryPoint.deploymentSalt as Hex, entryPoint.bytecode as Hex]),
    gas: 10_000_000n,
  });
  if ((await chain.client.waitForTransactionReceipt({ hash: entryPointHash })).status !== "success")
    throw new Error("local_fixture_deployment_failed");
  for (const module of [v33.kernel, v33.factory, v33.ecdsaValidator]) {
    const hash = await stack.wallet.sendTransaction({
      account: stack.submitter,
      to: deployment.create2Deployer,
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
    address: deployment.factory,
    abi: factoryAbi,
    functionName: "createAccount",
    args: [init, zeroHash],
  });
  if ((await chain.client.waitForTransactionReceipt({ hash: creation })).status !== "success")
    throw new Error("local_fixture_account_failed");
  return address;
}
