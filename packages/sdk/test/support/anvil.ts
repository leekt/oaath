/**
 * One local Anvil chain and the CREATE2 stack every Kernel proof shares,
 * parameterized by chain ID so a proof can run two chains at once.
 *
 * ponytail: extracted from kernel-composition.anvil.test.ts because the all-chain
 * proof needs two of these; move to @oaath/testing when that package's chain
 * fixtures land, and fold kernel-v4.anvil.test.ts's copy in then.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type ChildProcess, spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import {
  concat,
  createPublicClient,
  createWalletClient,
  type DecodeErrorResultReturnType,
  decodeErrorResult,
  encodeFunctionData,
  getCreate2Address,
  type Hex,
  type HttpTransport,
  http,
  type PublicClient,
  parseEther,
  type WalletClient,
} from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { generatePrivateKey, type PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";
import { expect } from "vitest";
// The deny list is repo-owned and spans packages; scripts/scrub-live-rpc-env.mjs
// is the other consumer. Importing it keeps one list rather than a stale copy.
import { scrubLiveProviderEnvironment } from "../../../../scripts/live-provider-environment.mjs";
import {
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  type KernelRuntime,
  type KernelV4AccountReadCapability,
  type PreparedUserOperation,
  createKernelV4Reads,
} from "../../src/kernel.js";

export interface ModuleFixture {
  repository: string;
  commit: string;
  source: string;
  moduleType: 1 | 5 | 6;
  expectedAddress: `0x${string}`;
  runtimeCodeHash: `0x${string}`;
  deploymentInput: Hex;
}

/** The pinned raw P-256 validator, which also names the precompile it needs. */
export interface P256ValidatorFixture extends ModuleFixture {
  moduleType: 1;
  precompile: `0x${string}`;
}

export interface DeploymentFixture {
  entryPoint: { deploymentSalt: Hex; artifact: string };
  kernelUups: { deploymentInput: Hex };
  kernelImmutableEcdsa: { deploymentInput: Hex };
  kernelFactory: { deploymentInput: Hex };
  ecdsaValidator: { bytecode: Hex };
  p256Validator: P256ValidatorFixture;
  ecdsaSigner: ModuleFixture;
  webAuthnSigner: ModuleFixture;
  callPolicy: ModuleFixture;
  timestampPolicy: ModuleFixture;
  rateLimitPolicy: ModuleFixture;
}

/**
 * Salt for the ECDSA validator's CREATE2 deployment. The fixture carries no
 * salted deployment input for it, because Kernel v4 pins no ECDSA validator, so a
 * proof that needs the same validator address on more than one chain deploys it
 * through the shared deployer under this salt.
 */
const VALIDATOR_SALT = `0x${"00".repeat(32)}` as const;

export interface AnvilChain {
  readonly chainId: number;
  readonly url: string;
  readonly stop: () => void;
}

export interface KernelHarness {
  readonly chain: AnvilChain;
  readonly fixture: DeploymentFixture;
  readonly client: PublicClient<HttpTransport>;
  readonly wallet: WalletClient<HttpTransport, undefined, PrivateKeyAccount>;
  readonly submitter: PrivateKeyAccount;
  readonly reads: KernelV4AccountReadCapability;
  readonly deployCreate2: (deploymentInput: Hex) => Promise<void>;
  readonly deployModule: (module: ModuleFixture) => Promise<void>;
  readonly deployValidator: () => Promise<`0x${string}`>;
  /** The ECDSA validator at its chain-independent CREATE2 address. */
  readonly deployValidatorCreate2: () => Promise<`0x${string}`>;
  readonly fund: (address: `0x${string}`, value: bigint) => Promise<void>;
  readonly send: (
    runtime: Readonly<KernelRuntime>,
    prepared: PreparedUserOperation,
  ) => Promise<"success" | "reverted">;
  /** Submits an operation whose signature the caller produced, envelope and all. */
  readonly sendSigned: (
    prepared: PreparedUserOperation,
    signature: `0x${string}`,
  ) => Promise<"success" | "reverted">;
  readonly rejection: (
    runtime: Readonly<KernelRuntime>,
    prepared: PreparedUserOperation,
  ) => Promise<DecodeErrorResultReturnType>;
  readonly rejectionOf: (
    prepared: PreparedUserOperation,
    signature: `0x${string}`,
  ) => Promise<DecodeErrorResultReturnType>;
}

export function lower(value: string): `0x${string}` {
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

async function waitForAnvil(process_: ChildProcess, url: string, chainId: number): Promise<void> {
  const client = createPublicClient({ transport: http(url, { retryCount: 0 }) });
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (process_.exitCode !== null) throw new Error("Anvil exited before readiness");
    try {
      if ((await client.getChainId()) === chainId) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("Anvil readiness deadline expired");
}

/**
 * Starts one loopback Anvil bound to the given chain ID.
 *
 * The hardfork is an argument because one module's dependency is a chain feature
 * rather than a deployment: the pinned raw P-256 validator staticcalls the
 * RIP-7212 / EIP-7951 precompile at 0x100, which Prague does not carry and Osaka
 * does, so its proof asks for a chain that has it. Every other proof keeps Prague,
 * the floor its evidence was taken on.
 */
export async function startAnvil(
  chainId: number,
  hardfork: "prague" | "osaka" = "prague",
): Promise<AnvilChain> {
  const port = await reservePort();
  const url = `http://127.0.0.1:${port}`;
  const process_ = spawn(
    process.env.ANVIL_PATH ?? "anvil",
    [
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--chain-id",
      String(chainId),
      "--hardfork",
      hardfork,
      "--accounts",
      "0",
      "--silent",
    ],
    { env: scrubLiveProviderEnvironment(process.env), stdio: "ignore" },
  );
  await waitForAnvil(process_, url, chainId);
  return Object.freeze({
    chainId,
    url,
    stop: () => {
      process_.kill("SIGTERM");
    },
  });
}

async function readFixture(): Promise<DeploymentFixture> {
  return JSON.parse(
    await readFile(new URL("../fixtures/kernel-v4-v0.7-deployments.json", import.meta.url), "utf8"),
  ) as DeploymentFixture;
}

/**
 * One funded submitter over one local chain, with the CREATE2 deployments every
 * proof shares. CREATE2 fixes each address, so a module or implementation an
 * earlier proof already deployed is reused rather than redeployed: the deployer
 * reverts on a second deployment to the same address.
 */
export async function createHarness(chain: AnvilChain): Promise<KernelHarness> {
  const fixture = await readFixture();
  const client = createPublicClient({ transport: http(chain.url, { retryCount: 0 }) });
  const submitter = privateKeyToAccount(generatePrivateKey());
  const wallet = createWalletClient({
    account: submitter,
    transport: http(chain.url, { retryCount: 0 }),
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

  const deployModule = async (module: ModuleFixture) => {
    if (!(await client.getCode({ address: module.expectedAddress }))) {
      await deployCreate2(module.deploymentInput);
    }
  };

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

  const deployValidatorCreate2 = async () => {
    const address = lower(
      getCreate2Address({
        from: KERNEL_V4_CREATE2_DEPLOYER,
        salt: VALIDATOR_SALT,
        bytecode: fixture.ecdsaValidator.bytecode,
      }),
    );
    if (!(await client.getCode({ address }))) {
      await deployCreate2(concat([VALIDATOR_SALT, fixture.ecdsaValidator.bytecode]));
    }
    return address;
  };

  const fund = async (address: `0x${string}`, value: bigint) => {
    const hash = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: address,
      value,
    });
    expect((await client.waitForTransactionReceipt({ hash })).status).toBe("success");
  };

  const handleOpsCalldata = (prepared: PreparedUserOperation, signature: `0x${string}`) => {
    const operation = prepared.userOperation;
    return encodeFunctionData({
      abi: entryPoint07Abi,
      functionName: "handleOps",
      args: [
        [
          toPackedUserOperation({
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
          }),
        ],
        submitter.address,
      ],
    });
  };

  const sendSigned = async (prepared: PreparedUserOperation, signature: `0x${string}`) => {
    const hash = await wallet.sendTransaction({
      account: submitter,
      chain: null,
      to: KERNEL_V4_ENTRY_POINT_V07,
      data: handleOpsCalldata(prepared, signature),
      gas: 8_000_000n,
    });
    return (await client.waitForTransactionReceipt({ hash })).status;
  };

  const send = async (runtime: Readonly<KernelRuntime>, prepared: PreparedUserOperation) =>
    sendSigned(prepared, await runtime.signOperation(prepared));

  /**
   * EntryPoint's own rejection for one operation, decoded. handleOps reverts
   * during validation, so the class of the refusal — not just "the transaction
   * failed" — is the evidence: `eth_call` carries the revert data back.
   */
  const rejectionOf = async (prepared: PreparedUserOperation, signature: `0x${string}`) => {
    const response = await fetch(chain.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_call",
        params: [
          {
            from: submitter.address,
            to: KERNEL_V4_ENTRY_POINT_V07,
            data: handleOpsCalldata(prepared, signature),
            gas: quantity(8_000_000n),
          },
          "latest",
        ],
      }),
    });
    const body = (await response.json()) as {
      readonly error?: { readonly data?: unknown };
      readonly result?: Hex;
    };
    const data = body.error?.data;
    if (typeof data !== "string" || !data.startsWith("0x") || data === "0x") {
      throw new Error(`EntryPoint accepted an operation it must reject: ${JSON.stringify(body)}`);
    }
    return decodeErrorResult({ abi: entryPoint07Abi, data: data as Hex });
  };

  const rejection = async (runtime: Readonly<KernelRuntime>, prepared: PreparedUserOperation) =>
    rejectionOf(prepared, await runtime.signOperation(prepared));

  return Object.freeze({
    chain,
    fixture,
    client,
    wallet,
    submitter,
    reads: createKernelV4Reads(client),
    deployCreate2,
    deployModule,
    deployValidator,
    deployValidatorCreate2,
    fund,
    send,
    sendSigned,
    rejection,
    rejectionOf,
  });
}

/** Deploys EntryPoint 0.7, the Kernel v4 implementations, and the factory. */
export async function deployKernelStack(harness: KernelHarness): Promise<void> {
  const entryPointArtifact = JSON.parse(
    await readFile(
      join(process.cwd(), "node_modules", harness.fixture.entryPoint.artifact),
      "utf8",
    ),
  ) as { bytecode: Hex };
  if (!(await harness.client.getCode({ address: KERNEL_V4_ENTRY_POINT_V07 }))) {
    await harness.deployCreate2(
      concat([harness.fixture.entryPoint.deploymentSalt, entryPointArtifact.bytecode]),
    );
    await harness.deployCreate2(harness.fixture.kernelUups.deploymentInput);
    await harness.deployCreate2(harness.fixture.kernelImmutableEcdsa.deploymentInput);
    await harness.deployCreate2(harness.fixture.kernelFactory.deploymentInput);
  }
}
