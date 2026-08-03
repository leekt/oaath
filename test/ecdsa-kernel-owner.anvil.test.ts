import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { encodeCallDataEpV07 } from "@zerodev/sdk";
import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  type Hex,
  http,
  keccak256,
  type PublicClient,
  parseAbi,
  parseEther,
} from "viem";
import {
  entryPoint07Abi,
  entryPoint07Address,
  toPackedUserOperation,
} from "viem/account-abstraction";
import { generatePrivateKey, type PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createEcdsaKernelOwnerRuntime,
  type EcdsaKernelOwnerRestorationReadRequest,
  type EcdsaKernelOwnerRuntime,
  prepareUserOperation,
} from "../src/index.js";

const requireAnvil = process.env.OGP_REQUIRE_ANVIL === "1";
const chainId = 31_337;
const implementationAddress = "0xd6cedde84be40893d153be9d467cd6ad37875b28" as const;
const factoryAddress = "0x2577507b78c2008ff367261cb6285d44ba5ef2e9" as const;
const validatorAddress = "0x845adb2c711129d4f3966735ed98a9f09fc4ce57" as const;
const fixedEntryPoint = entryPoint07Address.toLowerCase() as `0x${string}`;
const kernelAbi = parseAbi([
  "constructor(address _entryPoint)",
  "function initialize(bytes21 _rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
  "function rootValidator() view returns (bytes21)",
]);
const factoryAbi = parseAbi([
  "constructor(address _impl)",
  "function createAccount(bytes data, bytes32 salt) payable returns (address)",
  "function getAddress(bytes data, bytes32 salt) view returns (address)",
]);
const validatorAbi = parseAbi([
  "function ecdsaValidatorStorage(address account) view returns (address owner)",
]);

interface KernelArtifacts {
  provenance: { kernelVersion: string; kernelCommit: string };
  kernel: { keccak256: Hex; creationBytecode: Hex };
  factory: { keccak256: Hex; creationBytecode: Hex };
  ecdsaValidator: { keccak256: Hex; creationBytecode: Hex };
}

interface Harness {
  process: ChildProcess;
  url: string;
  publicClient: PublicClient;
  submitter: PrivateKeyAccount;
}

let harness: Harness;

function lower(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function paritySignature(signature: Hex): Hex {
  const recoveryByte = signature.slice(-2);
  if (recoveryByte === "1b") return `${signature.slice(0, -2)}00` as Hex;
  if (recoveryByte === "1c") return `${signature.slice(0, -2)}01` as Hex;
  throw new Error("unexpected recovery byte");
}

function quantity(value: bigint | number): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
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

async function waitForAnvil(client: PublicClient, process: ChildProcess): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (process.exitCode !== null) throw new Error("Anvil exited before readiness");
    try {
      if ((await client.getChainId()) === chainId) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("Anvil readiness deadline expired");
}

async function stopAnvil(process: ChildProcess): Promise<void> {
  if (process.exitCode !== null) return;
  const exited = new Promise<void>((resolve) => process.once("exit", () => resolve()));
  process.kill("SIGTERM");
  await exited;
}

async function deploy(
  bytecode: Hex,
  abi: readonly unknown[],
  args: readonly unknown[] = [],
): Promise<`0x${string}`> {
  const wallet = createWalletClient({
    account: harness.submitter,
    transport: http(harness.url, { retryCount: 0 }),
  });
  const hash = await wallet.deployContract({
    abi,
    bytecode,
    args,
    gas: 20_000_000n,
    account: harness.submitter,
    chain: null,
  });
  const receipt = await harness.publicClient.waitForTransactionReceipt({ hash });
  if (!receipt.contractAddress || receipt.status !== "success") {
    throw new Error("contract deployment failed");
  }
  return lower(receipt.contractAddress);
}

async function pinRuntime(source: `0x${string}`, target: `0x${string}`): Promise<void> {
  const code = await harness.publicClient.getCode({ address: source });
  if (!code || code === "0x") throw new Error("deployed runtime unavailable");
  await harness.publicClient.request({
    method: "anvil_setCode" as "eth_chainId",
    params: [target, code] as never,
  });
  expect(await harness.publicClient.getCode({ address: target })).toBe(code);
}

async function startHarness(): Promise<Harness> {
  const anvilPath = process.env.ANVIL_PATH ?? "anvil";
  const version = await new Promise<string>((resolve, reject) => {
    const child = spawn(anvilPath, ["--version"], { stdio: ["ignore", "pipe", "ignore"] });
    let output = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
    });
    child.once("error", reject);
    child.once("exit", (code) =>
      code === 0 ? resolve(output) : reject(new Error("Anvil version failed")),
    );
  });
  const versionMatch = /^anvil Version: ([0-9]+\.[0-9]+\.[0-9]+)(?:-|$)/mu.exec(version);
  if (versionMatch?.[1] !== "1.7.1") throw new Error("Anvil 1.7.1 is required");

  const port = await reservePort();
  const url = `http://127.0.0.1:${port}`;
  const anvilProcess = spawn(
    anvilPath,
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
    { stdio: "ignore" },
  );
  try {
    const publicClient = createPublicClient({ transport: http(url, { retryCount: 0 }) });
    await waitForAnvil(publicClient, anvilProcess);
    const submitter = privateKeyToAccount(generatePrivateKey());
    await publicClient.request({
      method: "anvil_setBalance" as "eth_chainId",
      params: [submitter.address, quantity(parseEther("100"))] as never,
    });
    return { process: anvilProcess, url, publicClient, submitter };
  } catch (error) {
    await stopAnvil(anvilProcess);
    throw error;
  }
}

async function installPinnedContracts(): Promise<void> {
  const fixtureRaw = await readFile(
    new URL("./fixtures/kernel-v3.3-bytecode.json", import.meta.url),
    "utf8",
  );
  const artifacts = JSON.parse(fixtureRaw) as KernelArtifacts;
  expect(artifacts.provenance).toMatchObject({
    kernelVersion: "0.3.3",
    kernelCommit: "cd697c7e21715d015e0643af22310a99aa17433b",
  });
  expect(keccak256(artifacts.kernel.creationBytecode)).toBe(artifacts.kernel.keccak256);
  expect(keccak256(artifacts.factory.creationBytecode)).toBe(artifacts.factory.keccak256);
  expect(keccak256(artifacts.ecdsaValidator.creationBytecode)).toBe(
    artifacts.ecdsaValidator.keccak256,
  );

  const entryPointArtifactPath = join(
    process.cwd(),
    "node_modules/@account-abstraction/contracts/artifacts/EntryPoint.json",
  );
  const entryPointArtifactRaw = await readFile(entryPointArtifactPath, "utf8");
  expect(createHash("sha256").update(entryPointArtifactRaw).digest("hex")).toBe(
    "952e7ce1e69354b9e80d0e68e0cbcc64f9304dd25c17170c3732114ea5421b04",
  );
  const entryPointArtifact = JSON.parse(entryPointArtifactRaw) as { bytecode: Hex };
  await pinRuntime(await deploy(entryPointArtifact.bytecode, entryPoint07Abi), fixedEntryPoint);
  await pinRuntime(
    await deploy(artifacts.kernel.creationBytecode, kernelAbi, [fixedEntryPoint]),
    implementationAddress,
  );
  await pinRuntime(
    await deploy(artifacts.factory.creationBytecode, factoryAbi, [implementationAddress]),
    factoryAddress,
  );
  await pinRuntime(
    await deploy(artifacts.ecdsaValidator.creationBytecode, validatorAbi),
    validatorAddress,
  );
}

function ownerRuntime(privateKey: Hex, signs: { count: number }) {
  const account = privateKeyToAccount(privateKey);
  const owner = lower(account.address);
  return createEcdsaKernelOwnerRuntime({
    profile: {
      version: "ogp.kernel-account-profile/v1",
      kind: "kernel",
      accountIndex: "7",
      kernelVersion: "0.3.3",
      factoryRoute: "kernel_factory",
      entryPoint: { version: "0.7" },
      ownerCredential: {
        version: "ogp.owner-credential-profile/v1",
        kind: "ecdsa",
        address: owner,
      },
    },
    chainId,
    signer: {
      address: owner,
      async signMessageHash({ hash }: { hash: Hex }) {
        signs.count += 1;
        return paritySignature(await account.signMessage({ message: { raw: hash } }));
      },
    },
  });
}

async function prepare(
  runtime: EcdsaKernelOwnerRuntime,
  nonce: bigint,
  factory: EcdsaKernelOwnerRuntime["factory"] | null,
) {
  return prepareUserOperation({
    kind: "execution",
    grantId: "grant-ecdsa-owner-anvil",
    chainId,
    entryPoint: { version: "0.7", address: fixedEntryPoint },
    userOperation: {
      sender: runtime.accountAddress,
      nonce: nonce.toString(10),
      callData: await encodeCallDataEpV07([
        { to: lower(harness.submitter.address), value: 0n, data: "0x" },
      ]),
      callGasLimit: "300000",
      verificationGasLimit: "1500000",
      preVerificationGas: "100000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
      factory,
      paymaster: null,
    },
  });
}

function signedUserOperation(prepared: Awaited<ReturnType<typeof prepare>>, signature: Hex) {
  const operation = prepared.userOperation;
  return {
    sender: operation.sender,
    nonce: BigInt(operation.nonce),
    callData: operation.callData,
    callGasLimit: BigInt(operation.callGasLimit),
    verificationGasLimit: BigInt(operation.verificationGasLimit),
    preVerificationGas: BigInt(operation.preVerificationGas),
    maxFeePerGas: BigInt(operation.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(operation.maxPriorityFeePerGas),
    signature,
    ...(operation.factory
      ? { factory: operation.factory.address, factoryData: operation.factory.data }
      : {}),
  };
}

async function submit(
  prepared: Awaited<ReturnType<typeof prepare>>,
  signature: Hex,
): Promise<void> {
  const calldata = encodeFunctionData({
    abi: entryPoint07Abi,
    functionName: "handleOps",
    args: [
      [toPackedUserOperation(signedUserOperation(prepared, signature))],
      lower(harness.submitter.address),
    ],
  });
  const wallet = createWalletClient({
    account: harness.submitter,
    transport: http(harness.url, { retryCount: 0 }),
  });
  const hash = await wallet.sendTransaction({
    account: harness.submitter,
    to: fixedEntryPoint,
    data: calldata,
    gas: 5_000_000n,
    maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    chain: null,
  });
  expect((await harness.publicClient.waitForTransactionReceipt({ hash })).status).toBe("success");
}

describe.skipIf(!requireAnvil)("ECDSA Kernel owner local acceptance", () => {
  beforeAll(async () => {
    harness = await startHarness();
    await installPinnedContracts();
  }, 30_000);

  afterAll(async () => {
    if (harness) await stopAnvil(harness.process);
  });

  it("recreates deployed owner evidence and signs another accepted UserOperation", async () => {
    const privateKey = generatePrivateKey();
    const firstSigns = { count: 0 };
    const first = await ownerRuntime(privateKey, firstSigns);
    expect(first.validatorAddress).toBe(validatorAddress);
    expect(first.factory.address).toBe(factoryAddress);
    await harness.publicClient.request({
      method: "anvil_setBalance" as "eth_chainId",
      params: [first.accountAddress, quantity(parseEther("10"))] as never,
    });

    const deployment = await prepare(first, 0n, first.factory);
    await submit(deployment, await first.signPreparedUserOperation(deployment));
    expect(firstSigns.count).toBe(1);
    expect(await harness.publicClient.getCode({ address: first.accountAddress })).not.toBe("0x");
    expect(
      lower(
        await harness.publicClient.readContract({
          address: first.accountAddress,
          abi: kernelAbi,
          functionName: "rootValidator",
        }),
      ),
    ).toBe(`0x01${validatorAddress.slice(2)}`);
    expect(
      lower(
        await harness.publicClient.readContract({
          address: validatorAddress,
          abi: validatorAbi,
          functionName: "ecdsaValidatorStorage",
          args: [first.accountAddress],
        }),
      ),
    ).toBe(lower(privateKeyToAccount(privateKey).address));

    const recreatedClient = createPublicClient({
      transport: http(harness.url, { retryCount: 0 }),
    });
    const recreatedSigns = { count: 0 };
    const recreated = await ownerRuntime(privateKey, recreatedSigns);
    expect(recreated.accountAddress).toBe(first.accountAddress);
    await recreated.restore({
      async read(request: EcdsaKernelOwnerRestorationReadRequest) {
        if (request.type === "chain_id") return recreatedClient.getChainId();
        if (request.type === "account_code") {
          return lower((await recreatedClient.getCode({ address: request.account })) ?? "0x");
        }
        if (request.type === "kernel_root_validator") {
          return lower(
            await recreatedClient.readContract({
              address: request.account,
              abi: kernelAbi,
              functionName: "rootValidator",
            }),
          );
        }
        return lower(
          await recreatedClient.readContract({
            address: request.validator,
            abi: validatorAbi,
            functionName: "ecdsaValidatorStorage",
            args: [request.account],
          }),
        );
      },
    });
    const nonce = await recreatedClient.readContract({
      address: fixedEntryPoint,
      abi: entryPoint07Abi,
      functionName: "getNonce",
      args: [recreated.accountAddress, 0n],
    });
    expect(nonce).toBe(1n);
    const restoredOperation = await prepare(recreated, nonce, null);
    await submit(restoredOperation, await recreated.signPreparedUserOperation(restoredOperation));
    expect(recreatedSigns.count).toBe(1);
    expect(
      await recreatedClient.readContract({
        address: fixedEntryPoint,
        abi: entryPoint07Abi,
        functionName: "getNonce",
        args: [recreated.accountAddress, 0n],
      }),
    ).toBe(2n);
  }, 30_000);
});
