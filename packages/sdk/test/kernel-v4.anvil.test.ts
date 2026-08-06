import { type ChildProcess, spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import {
  concat,
  createPublicClient,
  createWalletClient,
  decodeAbiParameters,
  encodeFunctionData,
  type Hex,
  http,
  parseAbi,
  parseEther,
} from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
// One repo-owned deny list; this copy had already gone stale against it.
import { scrubLiveProviderEnvironment } from "../../../scripts/live-provider-environment.mjs";
import {
  bindKernelV4Account,
  createKernelV4Reads,
  encodeKernelV4FactoryAddressRead,
  encodeKernelV4InstallModules,
  encodeKernelV4ValidatorData,
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_EXECUTE_SELECTOR,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  prepareKernelV4UserOperation,
} from "../src/kernel.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
const chainId = 421_614;
const addressResult = [{ type: "address" }] as const;
const entryPointReads = parseAbi([
  "function getNonce(address sender, uint192 key) view returns (uint256)",
]);

interface DeploymentFixture {
  version: "kernel-v4-v0.7-local-fixture/v6";
  entryPoint: { deploymentSalt: Hex; packageVersion: "0.7.0"; artifact: string };
  kernelUups: { transactionHash: Hex; deploymentInput: Hex };
  kernelImmutableEcdsa: { transactionHash: Hex; deploymentInput: Hex };
  kernelFactory: { transactionHash: Hex; deploymentInput: Hex };
  ecdsaValidator: {
    repository: string;
    commit: string;
    source: string;
    bytecode: Hex;
  };
}

let anvil: ChildProcess | undefined;
let url = "";

function lower(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function quantity(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("loopback port unavailable");
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return address.port;
}

async function waitForAnvil(): Promise<void> {
  const client = createPublicClient({ transport: http(url, { retryCount: 0 }) });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (anvil?.exitCode !== null) throw new Error("Anvil exited before readiness");
    try {
      if ((await client.getChainId()) === chainId) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("Anvil readiness deadline expired");
}

beforeAll(async () => {
  if (!requireAnvil) return;
  const port = await reservePort();
  url = `http://127.0.0.1:${port}`;
  anvil = spawn(
    process.env.ANVIL_PATH ?? "anvil",
    [
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--chain-id",
      String(chainId),
      "--hardfork",
      "prague",
      "--accounts",
      "0",
      "--silent",
    ],
    { env: scrubLiveProviderEnvironment(process.env), stdio: "ignore" },
  );
  await waitForAnvil();
});

afterAll(() => {
  anvil?.kill("SIGTERM");
});

(requireAnvil ? describe : describe.skip)("Kernel v4 / EntryPoint 0.7 local proof", () => {
  it("deploys through the canonical factory and executes the exact prepared operation", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL("./fixtures/kernel-v4-v0.7-deployments.json", import.meta.url),
        "utf8",
      ),
    ) as DeploymentFixture;
    expect(fixture).toMatchObject({
      version: "kernel-v4-v0.7-local-fixture/v6",
      entryPoint: { packageVersion: "0.7.0" },
      ecdsaValidator: {
        repository: "https://github.com/zerodevapp/kernel",
        source: "test/mock/ECDSAValidator.sol",
      },
    });

    const entryPointArtifact = JSON.parse(
      await readFile(join(process.cwd(), "node_modules", fixture.entryPoint.artifact), "utf8"),
    ) as { bytecode: Hex };
    const client = createPublicClient({ transport: http(url, { retryCount: 0 }) });
    const submitter = privateKeyToAccount(generatePrivateKey());
    const wallet = createWalletClient({
      account: submitter,
      transport: http(url, { retryCount: 0 }),
    });
    await client.request({
      method: "anvil_setBalance" as "eth_chainId",
      params: [submitter.address, quantity(parseEther("100"))] as never,
    });

    const deployCreate2 = async (deploymentInput: Hex) => {
      const hash = await wallet.sendTransaction({
        account: submitter,
        chain: null,
        to: KERNEL_V4_CREATE2_DEPLOYER,
        data: deploymentInput,
        gas: 10_000_000n,
      });
      expect((await client.waitForTransactionReceipt({ hash })).status).toBe("success");
    };
    await deployCreate2(concat([fixture.entryPoint.deploymentSalt, entryPointArtifact.bytecode]));
    await deployCreate2(fixture.kernelUups.deploymentInput);
    await deployCreate2(fixture.kernelImmutableEcdsa.deploymentInput);
    await deployCreate2(fixture.kernelFactory.deploymentInput);

    for (const deployed of [
      KERNEL_V4_ENTRY_POINT_V07,
      KERNEL_V4_UUPS_IMPLEMENTATION_V07,
      KERNEL_V4_FACTORY_V07,
    ]) {
      expect(await client.getCode({ address: deployed })).toMatch(/^0x[0-9a-f]{2,}$/u);
    }
    const deployValidator = async () => {
      const hash = await wallet.deployContract({
        account: submitter,
        chain: null,
        abi: [],
        bytecode: fixture.ecdsaValidator.bytecode,
        gas: 2_000_000n,
      });
      const receipt = await client.waitForTransactionReceipt({ hash });
      if (!receipt.contractAddress || receipt.status !== "success") {
        throw new Error("validator deployment failed");
      }
      return lower(receipt.contractAddress);
    };
    const validator = await deployValidator();
    const operator = privateKeyToAccount(generatePrivateKey());
    const packages = [
      {
        moduleType: 1 as const,
        module: validator,
        moduleData: lower(operator.address),
        internalData: encodeKernelV4ValidatorData({ hook: "none", selectors: [] }),
      },
    ];
    const accountRead = await client.call({
      to: KERNEL_V4_FACTORY_V07,
      data: encodeKernelV4FactoryAddressRead({ initialPackages: packages, accountIndex: "0" }),
    });
    if (!accountRead.data) throw new Error("counterfactual address is unavailable");
    const account = lower(decodeAbiParameters(addressResult, accountRead.data)[0]);
    const fundHash = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: account,
      value: parseEther("1"),
    });
    await client.waitForTransactionReceipt({ hash: fundHash });

    const reads = createKernelV4Reads(client);
    const descriptor = await bindKernelV4Account({
      chainId,
      initialPackages: packages,
      accountIndex: "0",
      reads,
    });
    expect(descriptor).toMatchObject({
      state: "counterfactual",
      account,
      factory: KERNEL_V4_FACTORY_V07,
    });

    const target = lower(privateKeyToAccount(generatePrivateKey()).address);
    const prepared = prepareKernelV4UserOperation({
      kind: "execution",
      grantId: "kernel-v4-local-proof",
      account: descriptor,
      nonce: { mode: "standard", validation: { kind: "root" }, nonceKey: "0", sequence: "0" },
      calls: [{ target, value: "12345", data: "0x" }],
      gas: {
        callGasLimit: "200000",
        verificationGasLimit: "3000000",
        preVerificationGas: "150000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    const send = async (
      operation: (typeof prepared)["userOperation"],
      hash: `0x${string}`,
      signer: { sign(input: { hash: `0x${string}` }): Promise<`0x${string}`> },
    ) => {
      const signature = await signer.sign({ hash });
      const packed = toPackedUserOperation({
        sender: operation.sender,
        nonce: BigInt(operation.nonce),
        callData: operation.callData,
        callGasLimit: BigInt(operation.callGasLimit),
        verificationGasLimit: BigInt(operation.verificationGasLimit),
        preVerificationGas: BigInt(operation.preVerificationGas),
        maxFeePerGas: BigInt(operation.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(operation.maxPriorityFeePerGas),
        ...(operation.factory
          ? { factory: operation.factory.address, factoryData: operation.factory.data }
          : {}),
        signature,
      });
      const handleOpsHash = await wallet.sendTransaction({
        account: submitter,
        chain: null,
        to: KERNEL_V4_ENTRY_POINT_V07,
        data: encodeFunctionData({
          abi: entryPoint07Abi,
          functionName: "handleOps",
          args: [[packed], submitter.address],
        }),
        gas: 8_000_000n,
      });
      return (await client.waitForTransactionReceipt({ hash: handleOpsHash })).status;
    };

    if (!prepared.userOperation.factory) {
      throw new Error("counterfactual factory evidence is missing");
    }
    const balanceBefore = await client.getBalance({ address: target });
    expect(await send(prepared.userOperation, prepared.userOperationHash, operator)).toBe(
      "success",
    );
    expect((await client.getBalance({ address: target })) - balanceBefore).toBe(12_345n);
    expect(
      await client.readContract({
        address: KERNEL_V4_ENTRY_POINT_V07,
        abi: entryPointReads,
        functionName: "getNonce",
        args: [account, 0n],
      }),
    ).toBe(1n);
    const deployedDescriptor = await bindKernelV4Account({
      chainId,
      initialPackages: packages,
      accountIndex: "0",
      reads,
    });
    expect(deployedDescriptor).toMatchObject({ state: "deployed", account });

    // Non-root proof: a root operation installs a second validator that
    // allow-lists execute(bytes32,bytes), then that validator authorizes an
    // executeUserOp-wrapped operation against the real Kernel.
    const executeSelector = KERNEL_V4_EXECUTE_SELECTOR;
    const nonRootValidator = await deployValidator();
    const nonRootOperator = privateKeyToAccount(generatePrivateKey());
    const blockedValidator = await deployValidator();
    const blockedOperator = privateKeyToAccount(generatePrivateKey());
    const installOp = prepareKernelV4UserOperation({
      kind: "execution",
      grantId: "kernel-v4-local-proof-install",
      account: deployedDescriptor,
      nonce: { mode: "standard", validation: { kind: "root" }, nonceKey: "0", sequence: "1" },
      calls: [
        {
          target: account,
          value: "0",
          data: encodeKernelV4InstallModules([
            {
              moduleType: 1,
              module: nonRootValidator,
              moduleData: lower(nonRootOperator.address),
              internalData: encodeKernelV4ValidatorData({
                hook: "none",
                selectors: [executeSelector],
              }),
            },
            {
              moduleType: 1,
              module: blockedValidator,
              moduleData: lower(blockedOperator.address),
              internalData: encodeKernelV4ValidatorData({ hook: "none", selectors: [] }),
            },
          ]),
        },
      ],
      gas: {
        callGasLimit: "900000",
        verificationGasLimit: "3000000",
        preVerificationGas: "150000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    expect(await send(installOp.userOperation, installOp.userOperationHash, operator)).toBe(
      "success",
    );

    const nonRootTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const nonRootOp = prepareKernelV4UserOperation({
      kind: "execution",
      grantId: "kernel-v4-local-proof-non-root",
      account: deployedDescriptor,
      nonce: {
        mode: "standard",
        validation: { kind: "validator", validator: nonRootValidator },
        nonceKey: "0",
        sequence: "0",
      },
      calls: [{ target: nonRootTarget, value: "777", data: "0x" }],
      gas: {
        callGasLimit: "900000",
        verificationGasLimit: "3000000",
        preVerificationGas: "150000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    expect(nonRootOp.userOperation.callData.startsWith("0x8dd7712f")).toBe(true);
    expect(await send(nonRootOp.userOperation, nonRootOp.userOperationHash, nonRootOperator)).toBe(
      "success",
    );
    expect(await client.getBalance({ address: nonRootTarget })).toBe(777n);

    // Negative: an installed non-root validator whose selector allow-list is
    // empty must not validate the same wrapped operation shape.
    const blockedOp = prepareKernelV4UserOperation({
      kind: "execution",
      grantId: "kernel-v4-local-proof-blocked",
      account: deployedDescriptor,
      nonce: {
        mode: "standard",
        validation: { kind: "validator", validator: blockedValidator },
        nonceKey: "0",
        sequence: "0",
      },
      calls: [{ target: nonRootTarget, value: "1", data: "0x" }],
      gas: {
        callGasLimit: "900000",
        verificationGasLimit: "3000000",
        preVerificationGas: "150000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    await expect(
      send(blockedOp.userOperation, blockedOp.userOperationHash, blockedOperator),
    ).resolves.not.toBe("success");
    expect(await client.getBalance({ address: nonRootTarget })).toBe(777n);
  }, 30_000);
});
