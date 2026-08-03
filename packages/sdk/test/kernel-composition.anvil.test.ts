import { type ChildProcess, spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import {
  concat,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  type Hex,
  http,
  parseEther,
} from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createKernelRuntime,
  createKernelV4Reads,
  ecdsaKey,
  encodeKernelV4InstallModules,
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_EXECUTE_USER_OP_SELECTOR,
  type KernelRuntime,
  kernelV4Deployment,
  ownerOperator,
  type PreparedUserOperation,
  sessionOperator,
} from "../src/index.js";

// ponytail: this anvil harness duplicates kernel-v4.anvil.test.ts; consolidate
// into @oaath/testing anvil.ts when that package's chain fixtures land.
const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
const chainId = 421_614;
const deployment = kernelV4Deployment(chainId);
const gas = Object.freeze({
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
});

interface DeploymentFixture {
  entryPoint: { deploymentSalt: Hex; artifact: string };
  kernelUups: { deploymentInput: Hex };
  kernelImmutableEcdsa: { deploymentInput: Hex };
  kernelFactory: { deploymentInput: Hex };
  ecdsaValidator: { bytecode: Hex };
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

function scrubbedEnvironment(): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(process.env).filter(([name]) => {
      const canonical = name.toUpperCase();
      return !(
        canonical.startsWith("INFURA_") ||
        canonical.startsWith("ALCHEMY_") ||
        canonical === "PARITY_RPC_URL" ||
        canonical === "ZERODEV_PROJECT_ID" ||
        /(?:^|_)RPC(?:_URL)?$/u.test(canonical)
      );
    }),
  );
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
    { env: scrubbedEnvironment(), stdio: "ignore" },
  );
  await waitForAnvil();
});

afterAll(() => {
  anvil?.kill("SIGTERM");
});

(requireAnvil ? describe : describe.skip)("Kernel composition local proof", () => {
  it("executes owner and session authorities through one composition factory", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL("./fixtures/kernel-v4-v0.7-deployments.json", import.meta.url),
        "utf8",
      ),
    ) as DeploymentFixture;
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

    const reads = createKernelV4Reads(client);
    const ownerAccount = privateKeyToAccount(generatePrivateKey());
    const ownerRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: ecdsaKey({ account: ownerAccount, validator: await deployValidator() }),
      }),
      reads,
    });
    const sessionAccount = privateKeyToAccount(generatePrivateKey());
    const sessionRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: ecdsaKey({ account: sessionAccount, validator: await deployValidator() }),
        hooks: [],
      }),
      reads,
    });

    const send = async (runtime: Readonly<KernelRuntime>, prepared: PreparedUserOperation) => {
      const operation = prepared.userOperation;
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
        signature: await runtime.signOperation(prepared),
      });
      const hash = await wallet.sendTransaction({
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
      return (await client.waitForTransactionReceipt({ hash })).status;
    };

    // Root authority: the composed owner runtime derives, deploys, and executes.
    const counterfactual = await ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    expect(counterfactual).toMatchObject({ state: "counterfactual", chainId });
    const account = counterfactual.account;
    const fundHash = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: account,
      value: parseEther("1"),
    });
    await client.waitForTransactionReceipt({ hash: fundHash });

    const ownerTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const deployAndExecute = ownerRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-owner",
      account: counterfactual,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: ownerTarget, value: "12345", data: "0x" }],
      gas,
    });
    expect(deployAndExecute.userOperation.factory?.address).toBe(deployment.factory);
    expect(
      deployAndExecute.userOperation.callData.startsWith(KERNEL_V4_EXECUTE_USER_OP_SELECTOR),
    ).toBe(false);
    expect(await send(ownerRuntime, deployAndExecute)).toBe("success");
    expect(await client.getBalance({ address: ownerTarget })).toBe(12_345n);

    // Session authority: the owner installs the session validator, then the
    // session runtime signs its own executeUserOp-wrapped operation.
    const deployed = await sessionRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: ownerRuntime.packages,
    });
    expect(deployed).toMatchObject({ state: "deployed", account });

    const install = ownerRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-install",
      account: deployed,
      nonceKey: "0",
      sequence: "1",
      calls: [
        {
          target: account,
          value: "0",
          data: encodeKernelV4InstallModules(sessionRuntime.packages),
        },
      ],
      gas,
    });
    expect(await send(ownerRuntime, install)).toBe("success");

    const sessionTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const sessionOperation = sessionRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-session",
      account: deployed,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: sessionTarget, value: "777", data: "0x" }],
      gas,
    });
    expect(
      sessionOperation.userOperation.callData.startsWith(KERNEL_V4_EXECUTE_USER_OP_SELECTOR),
    ).toBe(true);
    expect(await send(sessionRuntime, sessionOperation)).toBe("success");
    expect(await client.getBalance({ address: sessionTarget })).toBe(777n);

    // Authorities never borrow one another's operations: the owner runtime
    // refuses to sign a session-shaped operation before any submission exists.
    const foreign = sessionRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-foreign",
      account: deployed,
      nonceKey: "0",
      sequence: "1",
      calls: [{ target: sessionTarget, value: "1", data: "0x" }],
      gas,
    });
    await expect(send(ownerRuntime, foreign)).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    expect(await client.getBalance({ address: sessionTarget })).toBe(777n);
  }, 60_000);
});
