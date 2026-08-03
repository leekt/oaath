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
  captureRoutingCapabilities,
  classifyBundlerAcceptance,
  createKernelRuntime,
  createKernelV4Reads,
  decideExecution,
  deriveHandleOpsRequirement,
  ecdsaKey,
  encodeHandleOps,
  encodeKernelV4InstallModules,
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_EXECUTE_USER_OP_SELECTOR,
  type KernelRuntime,
  kernelV4Deployment,
  OAATH_HANDLE_OPS_OVERHEAD_GAS,
  ownerOperator,
  type PreparedUserOperation,
  pinnedSignerModule,
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

interface SignerModuleFixture {
  repository: string;
  commit: string;
  source: string;
  moduleType: 6;
  expectedAddress: `0x${string}`;
  deploymentInput: Hex;
}

interface DeploymentFixture {
  entryPoint: { deploymentSalt: Hex; artifact: string };
  kernelUups: { deploymentInput: Hex };
  kernelImmutableEcdsa: { deploymentInput: Hex };
  kernelFactory: { deploymentInput: Hex };
  ecdsaValidator: { bytecode: Hex };
  ecdsaSigner: SignerModuleFixture;
  webAuthnSigner: SignerModuleFixture;
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
  it("deploys the pinned permission signer modules at their chain-independent addresses", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL("./fixtures/kernel-v4-v0.7-deployments.json", import.meta.url),
        "utf8",
      ),
    ) as DeploymentFixture;
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

    // A CREATE2 address is derived from deployer, salt and init code alone, so
    // code landing on the pinned address proves the registry names exactly this
    // reviewed module and that nothing about the address depends on the chain.
    for (const [kind, module] of [
      ["ecdsa", fixture.ecdsaSigner],
      ["webauthn", fixture.webAuthnSigner],
    ] as const) {
      expect(module).toMatchObject({
        repository: "https://github.com/zerodevapp/kernel-7579-plugins",
        commit: "332deed6eeef3d6279cde50aa1d51eff53728bd4",
        moduleType: 6,
      });
      const pinned = pinnedSignerModule(kind);
      expect(pinned).toBe(module.expectedAddress);
      if (pinned === null) throw new Error(`no pinned ${kind} signer module`);
      expect(await client.getCode({ address: pinned })).toBeUndefined();
      const hash = await wallet.sendTransaction({
        account: submitter,
        chain: null,
        to: KERNEL_V4_CREATE2_DEPLOYER,
        data: module.deploymentInput,
        gas: 10_000_000n,
      });
      expect((await client.waitForTransactionReceipt({ hash })).status).toBe("success");
      expect(await client.getCode({ address: pinned })).toMatch(/^0x[0-9a-f]{2,}$/u);
    }

    // The reviewed plugin set ships no raw P-256 signer, so that axis stays
    // unbound instead of borrowing the WebAuthn module.
    expect(pinnedSignerModule("p256")).toBeNull();
  }, 60_000);

  it("executes owner and session authorities and falls back to handleOps without changing identity", async () => {
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

    // Routing fallback: a conclusive pre-acceptance rejection is the only
    // bundler evidence that authorizes EntryPoint.handleOps, and the fallback
    // submits the same signed operation identity the bundler would have taken.
    const capabilities = captureRoutingCapabilities({
      chainId,
      bundler: classifyBundlerAcceptance({ outcome: "rejected", code: -32505 }),
      sessionCoverage: "uncovered",
      feePayer: {
        address: lower(submitter.address),
        balance: (await client.getBalance({ address: submitter.address })).toString(10),
      },
    });
    expect(capabilities.bundler).toBe("unsupported");
    const decision = decideExecution({
      operationKind: "execution",
      sessionCoverage: capabilities.sessionCoverage,
      bundler: capabilities.bundler,
      feePayer: capabilities.feePayer,
    });
    expect(decision).toMatchObject({
      signer: "owner",
      route: "entrypoint-handleops",
      reasons: ["session_calls_uncovered", "bundler_unsupported", "fee_payer_configured"],
    });
    const decidedFeePayer = decision.feePayer;
    if (decidedFeePayer === null) throw new Error("handleOps decision carries no fee payer");

    const fallbackTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
    const fallback = ownerRuntime.prepareOperation({
      kind: "execution",
      grantId: "kernel-composition-fallback",
      account: deployed,
      nonceKey: "0",
      sequence: "2",
      calls: [{ target: fallbackTarget, value: "4321", data: "0x" }],
      gas,
    });
    const requirement = deriveHandleOpsRequirement({
      prepared: fallback,
      feePayer: decidedFeePayer,
      overheadGas: OAATH_HANDLE_OPS_OVERHEAD_GAS,
    });
    expect(requirement).toMatchObject({
      status: "funded",
      chainId,
      account,
      userOperationHash: fallback.userOperationHash,
    });

    // The signature is produced once, before the route is exercised.
    const fallbackSignature = await ownerRuntime.signOperation(fallback);
    const encoded = encodeHandleOps({
      prepared: fallback,
      signature: fallbackSignature,
      beneficiary: decidedFeePayer.address,
    });
    expect(encoded.userOperationHash).toBe(fallback.userOperationHash);
    const fallbackHash = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: encoded.entryPoint,
      data: encoded.data,
      gas: 8_000_000n,
    });
    const fallbackReceipt = await client.waitForTransactionReceipt({ hash: fallbackHash });
    expect(fallbackReceipt.status).toBe("success");
    // UserOperationEvent's first indexed topic is the userOpHash: the chain
    // itself confirms the fallback preserved the prepared identity.
    expect(
      fallbackReceipt.logs.some(
        (log) =>
          lower(log.address) === KERNEL_V4_ENTRY_POINT_V07 &&
          log.topics[1] === fallback.userOperationHash,
      ),
    ).toBe(true);
    expect(await client.getBalance({ address: fallbackTarget })).toBe(4_321n);
  }, 60_000);
});
