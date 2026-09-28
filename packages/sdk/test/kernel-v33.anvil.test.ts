import { readFile } from "node:fs/promises";
import {
  concat,
  encodeFunctionData,
  getCreate2Address,
  type Hex,
  parseAbi,
  parseEther,
  zeroAddress,
  zeroHash,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, describe, expect, it } from "vitest";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import { createKernelV33Reads, kernelV33Deployment } from "../src/kernel/deployment/v33.js";
import { ecdsaKey } from "../src/kernel/key/ecdsa.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { KERNEL_V4_CREATE2_DEPLOYER } from "../src/kernel-v4.js";
import { type AnvilChain, createHarness, startAnvil } from "./support/anvil.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
let chain: AnvilChain | undefined;
afterAll(() => chain?.stop());

(requireAnvil ? describe : describe.skip)("existing Kernel v3.3 / EntryPoint 0.7", () => {
  it("executes from an existing factory-deployed account without migration or an enable envelope", async () => {
    chain = await startAnvil(143);
    const harness = await createHarness(chain);
    const deployment = kernelV33Deployment(143);
    const fixture = JSON.parse(
      await readFile(new URL("./fixtures/kernel-v33-deployments.json", import.meta.url), "utf8"),
    ) as {
      version: string;
      kernel: { address: Hex; deploymentInput: Hex };
      factory: { address: Hex; deploymentInput: Hex };
      ecdsaValidator: { address: Hex; deploymentInput: Hex };
    };
    expect(fixture.version).toBe("oaath.kernel-v33-deployments/v1");
    const entryPoint = JSON.parse(
      await readFile(
        new URL(`../node_modules/${harness.fixture.entryPoint.artifact}`, import.meta.url),
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
    const owner = privateKeyToAccount(generatePrivateKey());
    const init = encodeFunctionData({
      abi: parseAbi([
        "function initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
      ]),
      functionName: "initialize",
      args: [`0x01${deployment.ecdsaValidator.slice(2)}`, zeroAddress, owner.address, "0x", []],
    });
    const factoryAbi = parseAbi([
      "function createAccount(bytes data, bytes32 salt) returns (address)",
      "function getAddress(bytes data, bytes32 salt) view returns (address)",
    ]);
    const address = await harness.client.readContract({
      address: deployment.factory,
      abi: factoryAbi,
      functionName: "getAddress",
      args: [init, zeroHash],
    });
    const creation = await harness.wallet.writeContract({
      chain: null,
      address: deployment.factory,
      abi: factoryAbi,
      functionName: "createAccount",
      args: [init, zeroHash],
    });
    expect((await harness.client.waitForTransactionReceipt({ hash: creation })).status).toBe(
      "success",
    );
    await harness.fund(address, parseEther("1"));

    // The SDK is constructed only after the account already exists.
    const runtime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: ecdsaKey({ account: owner, validator: deployment.ecdsaValidator }),
      }),
      reads: createKernelV33Reads(harness.client),
    });
    const bound = await runtime.bindAccount({ address });
    const target = privateKeyToAccount(generatePrivateKey()).address.toLowerCase() as Hex;
    const operation = runtime.prepareOperation({
      kind: "execution",
      grantId: "local-owner-operation",
      account: bound,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "7", data: "0x" }],
      gas: {
        callGasLimit: "200000",
        verificationGasLimit: "300000",
        preVerificationGas: "50000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    expect(operation.userOperation.sender).toBe(address.toLowerCase());
    expect(operation.userOperation.factory).toBeNull();
    const signature = await runtime.signOperation(operation);
    expect(signature.length).toBe(132);
    expect(await harness.sendSigned(operation, signature)).toBe("success");
    expect(await harness.client.getBalance({ address: target })).toBe(7n);
    // Observation and account recreation do not change ownership or deploy a new address.
    expect((await runtime.bindAccount({ address })).account).toBe(address.toLowerCase());
  }, 30_000);
});
