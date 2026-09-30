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

type Module = { address: Hex; deploymentInput: Hex };

async function readV33Fixture() {
  const fixture = JSON.parse(
    await readFile(new URL("../fixtures/kernel-v33-deployments.json", import.meta.url), "utf8"),
  ) as {
    version: string;
    kernel: Module;
    factory: Module;
    ecdsaValidator: Module;
    metaFactory: Module;
  };
  expect(fixture.version).toBe("oaath.kernel-v33-deployments/v1");
  return fixture;
}

function expectCreate2(module: Module) {
  expect(
    getCreate2Address({
      from: KERNEL_V4_CREATE2_DEPLOYER,
      salt: `0x${module.deploymentInput.slice(2, 66)}`,
      bytecode: `0x${module.deploymentInput.slice(66)}`,
    }).toLowerCase(),
  ).toBe(module.address);
}

/** Deploys the canonical v3.3 fixture and a real existing ECDSA-root account. */
export async function deployKernelV33Account(
  harness: Awaited<ReturnType<typeof createHarness>>,
  chainId: number,
  ownerAddress: Hex,
) {
  const deployment = await deployKernelV33Contracts(harness, chainId);
  const address = await createKernelV33Account(harness, chainId, ownerAddress, 0n);
  return { deployment, address };
}

/** The canonical EntryPoint, implementation, factory and ECDSA validator; no account. */
export async function deployKernelV33Contracts(
  harness: Awaited<ReturnType<typeof createHarness>>,
  chainId: number,
) {
  const deployment = kernelV33Deployment(chainId);
  const fixture = await readV33Fixture();
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
    expectCreate2(module);
    await harness.deployCreate2(module.deploymentInput);
  }
  expect(fixture.kernel.address).toBe(deployment.implementation);
  expect(fixture.factory.address).toBe(deployment.factory);
  expect(fixture.ecdsaValidator.address).toBe(deployment.ecdsaValidator);
  return deployment;
}

/**
 * ZeroDev's canonical MetaFactory (FactoryStaker) from the same reviewed
 * source. `approve` impersonates its recorded owner to approve the factory,
 * as ZeroDev has on production chains.
 */
export async function deployKernelV33MetaFactory(
  harness: Awaited<ReturnType<typeof createHarness>>,
  chainId: number,
  approve: boolean,
) {
  const deployment = kernelV33Deployment(chainId);
  const { metaFactory } = await readV33Fixture();
  expectCreate2(metaFactory);
  expect(metaFactory.address).toBe(deployment.metaFactory);
  if (!(await harness.client.getCode({ address: deployment.metaFactory })))
    await harness.deployCreate2(metaFactory.deploymentInput);
  if (!approve) return;
  const abi = parseAbi([
    "function owner() view returns (address)",
    "function approveFactory(address factory, bool approval) payable",
  ]);
  const owner = await harness.client.readContract({
    address: deployment.metaFactory,
    abi,
    functionName: "owner",
  });
  await harness.client.request({
    method: "anvil_impersonateAccount" as "eth_chainId",
    params: [owner] as never,
  });
  await harness.fund(owner, parseEther("1"));
  const hash = (await harness.client.request({
    method: "eth_sendTransaction" as "eth_chainId",
    params: [
      {
        from: owner,
        to: deployment.metaFactory,
        data: encodeFunctionData({
          abi,
          functionName: "approveFactory",
          args: [deployment.factory, true],
        }),
      },
    ] as never,
  })) as Hex;
  expect((await harness.client.waitForTransactionReceipt({ hash })).status).toBe("success");
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
