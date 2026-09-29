import { readFile } from "node:fs/promises";
import {
  concat,
  encodeFunctionData,
  getCreate2Address,
  type Hex,
  parseAbi,
  parseEther,
  toHex,
  zeroAddress,
} from "viem";
import { expect } from "vitest";
import { kernelV33Deployment } from "../../src/kernel/deployment/v33.js";
import { KERNEL_V4_CREATE2_DEPLOYER } from "../../src/kernel-v4.js";
import type { createHarness } from "./anvil.js";

/** Deploys the canonical v3.3 fixture and a real existing ECDSA-root account. */
export async function deployKernelV33Account(
  harness: Awaited<ReturnType<typeof createHarness>>,
  chainId: number,
  ownerAddress: Hex,
) {
  const deployment = kernelV33Deployment(chainId);
  const fixture = JSON.parse(
    await readFile(new URL("../fixtures/kernel-v33-deployments.json", import.meta.url), "utf8"),
  ) as {
    version: string;
    kernel: { address: Hex; deploymentInput: Hex };
    factory: { address: Hex; deploymentInput: Hex };
    ecdsaValidator: { address: Hex; deploymentInput: Hex };
  };
  expect(fixture.version).toBe("oaath.kernel-v33-deployments/v1");
  const entryPoint = JSON.parse(
    await readFile(
      new URL(`../../node_modules/${harness.fixture.entryPoint.artifact}`, import.meta.url),
      "utf8",
    ),
  ) as { bytecode: Hex };
  await harness.deployCreate2(
    concat([harness.fixture.entryPoint.deploymentSalt, entryPoint.bytecode]),
  );
  for (const module of [fixture.kernel, fixture.factory, fixture.ecdsaValidator]) {
    expect(
      getCreate2Address({
        from: KERNEL_V4_CREATE2_DEPLOYER,
        salt: `0x${module.deploymentInput.slice(2, 66)}`,
        bytecode: `0x${module.deploymentInput.slice(66)}`,
      }).toLowerCase(),
    ).toBe(module.address);
    await harness.deployCreate2(module.deploymentInput);
  }
  expect(fixture.kernel.address).toBe(deployment.implementation);
  expect(fixture.factory.address).toBe(deployment.factory);
  expect(fixture.ecdsaValidator.address).toBe(deployment.ecdsaValidator);
  const address = await createKernelV33Account(harness, chainId, ownerAddress, 0n);
  return { deployment, address };
}

/** One more real v3.3 account for the same owner; `index` is the factory salt. */
export async function createKernelV33Account(
  harness: Awaited<ReturnType<typeof createHarness>>,
  chainId: number,
  ownerAddress: Hex,
  index: bigint,
): Promise<Hex> {
  const deployment = kernelV33Deployment(chainId);
  const salt = toHex(index, { size: 32 });
  const init = encodeFunctionData({
    abi: parseAbi([
      "function initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
    ]),
    functionName: "initialize",
    args: [`0x01${deployment.ecdsaValidator.slice(2)}`, zeroAddress, ownerAddress, "0x", []],
  });
  const factoryAbi = parseAbi([
    "function createAccount(bytes data, bytes32 salt) returns (address)",
    "function getAddress(bytes data, bytes32 salt) view returns (address)",
  ]);
  const address = await harness.client.readContract({
    address: deployment.factory,
    abi: factoryAbi,
    functionName: "getAddress",
    args: [init, salt],
  });
  const creation = await harness.wallet.writeContract({
    chain: null,
    address: deployment.factory,
    abi: factoryAbi,
    functionName: "createAccount",
    args: [init, salt],
  });
  expect((await harness.client.waitForTransactionReceipt({ hash: creation })).status).toBe(
    "success",
  );
  await harness.fund(address, parseEther("1"));
  return address;
}
