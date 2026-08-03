import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { p256 } from "@noble/curves/nist.js";
import { encodeCallDataEpV07 } from "@zerodev/sdk";
import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  type Hex,
  hexToBytes,
  http,
  keccak256,
  type PublicClient,
  padHex,
  parseAbi,
  parseEther,
  toHex,
} from "viem";
import {
  entryPoint07Abi,
  entryPoint07Address,
  toPackedUserOperation,
} from "viem/account-abstraction";
import { generatePrivateKey, type PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createP256KernelOwnerRuntime,
  type P256KernelOwnerRestorationReadRequest,
  type P256KernelOwnerRuntime,
  prepareUserOperation,
} from "../src/index.js";

const requireAnvil = process.env.OGP_REQUIRE_ANVIL === "1";
const chainId = 31_337;
const implementationAddress = "0xd6cedde84be40893d153be9d467cd6ad37875b28" as const;
const factoryAddress = "0x2577507b78c2008ff367261cb6285d44ba5ef2e9" as const;
const validatorAddress = "0x9906ab44ff795883c5a725687a2705be4118b0f3" as const;
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
  "function publicKey(address account) view returns (uint256 x, uint256 y)",
]);

interface KernelArtifacts {
  provenance: { kernelVersion: string; kernelCommit: string };
  kernel: { keccak256: Hex; creationBytecode: Hex };
  factory: { keccak256: Hex; creationBytecode: Hex };
  p256Validator: {
    sourceCommit: string;
    runtimeKeccak256: Hex;
    runtimeByteLength: number;
    runtimeBytecode: Hex;
  };
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
  if (!/^anvil Version: 1\.7\.1(?:-|$)/mu.test(version)) {
    throw new Error("Anvil 1.7.1 is required");
  }

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
      "osaka",
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

async function setCode(target: `0x${string}`, code: Hex): Promise<void> {
  await harness.publicClient.request({
    method: "anvil_setCode" as "eth_chainId",
    params: [target, code] as never,
  });
  expect(await harness.publicClient.getCode({ address: target })).toBe(code);
}

async function pinRuntime(source: `0x${string}`, target: `0x${string}`): Promise<void> {
  const code = await harness.publicClient.getCode({ address: source });
  if (!code || code === "0x") throw new Error("deployed runtime unavailable");
  await setCode(target, code);
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
  expect(artifacts.p256Validator).toMatchObject({
    sourceCommit: "8f6a71992e297f2e7caa61df2c6eb0b6d9145d2d",
    runtimeKeccak256: "0xd7d9a5b1ddd1e22e7235268fd624c7c0714e5046b199d507bbfe5e03408e579d",
    runtimeByteLength: 1919,
  });
  expect((artifacts.p256Validator.runtimeBytecode.length - 2) / 2).toBe(1919);
  expect(keccak256(artifacts.p256Validator.runtimeBytecode)).toBe(
    artifacts.p256Validator.runtimeKeccak256,
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
  await setCode(validatorAddress, artifacts.p256Validator.runtimeBytecode);
}

function ownerRuntime(privateKey: Uint8Array, signs: { count: number }) {
  const publicKey = toHex(p256.getPublicKey(privateKey, false));
  return createP256KernelOwnerRuntime({
    profile: {
      version: "ogp.kernel-account-profile/v1",
      kind: "kernel",
      accountIndex: "7",
      kernelVersion: "0.3.3",
      factoryRoute: "kernel_factory",
      entryPoint: { version: "0.7" },
      ownerCredential: {
        version: "ogp.owner-credential-profile/v1",
        kind: "p256",
        publicKey,
      },
    },
    chainId,
    signer: {
      publicKey,
      async signMessageHash({ hash }: { hash: Hex }) {
        signs.count += 1;
        return toHex(
          p256
            .sign(hexToBytes(hash), privateKey, { lowS: true, prehash: false })
            .toCompactRawBytes(),
        );
      },
    },
  });
}

async function restore(runtime: P256KernelOwnerRuntime, client: PublicClient) {
  return runtime.restore({
    async read(request: P256KernelOwnerRestorationReadRequest) {
      if (request.type === "chain_id") return client.getChainId();
      if (request.type === "p256_validator_code" || request.type === "account_code") {
        const address =
          request.type === "p256_validator_code" ? request.validator : request.account;
        return lower((await client.getCode({ address })) ?? "0x");
      }
      if (request.type === "p256_precompile") {
        return (await client.call({ to: request.precompile, data: request.input })).data ?? "0x";
      }
      if (request.type === "kernel_root_validator") {
        return lower(
          await client.readContract({
            address: request.account,
            abi: kernelAbi,
            functionName: "rootValidator",
          }),
        );
      }
      const [x, y] = await client.readContract({
        address: request.validator,
        abi: validatorAbi,
        functionName: "publicKey",
        args: [request.account],
      });
      return `0x04${padHex(toHex(x), { size: 32 }).slice(2)}${padHex(toHex(y), {
        size: 32,
      }).slice(2)}`;
    },
  });
}

async function prepare(
  runtime: P256KernelOwnerRuntime,
  nonce: bigint,
  factory: P256KernelOwnerRuntime["factory"] | null,
) {
  return prepareUserOperation({
    kind: "execution",
    grantId: "grant-p256-owner-anvil",
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

function packed(prepared: Awaited<ReturnType<typeof prepare>>, signature: Hex) {
  const operation = prepared.userOperation;
  return toPackedUserOperation({
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
  });
}

async function submit(
  prepared: Awaited<ReturnType<typeof prepare>>,
  signature: Hex,
): Promise<void> {
  const wallet = createWalletClient({
    account: harness.submitter,
    transport: http(harness.url, { retryCount: 0 }),
  });
  const hash = await wallet.sendTransaction({
    account: harness.submitter,
    to: fixedEntryPoint,
    data: encodeFunctionData({
      abi: entryPoint07Abi,
      functionName: "handleOps",
      args: [[packed(prepared, signature)], lower(harness.submitter.address)],
    }),
    gas: 5_000_000n,
    maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    chain: null,
  });
  expect((await harness.publicClient.waitForTransactionReceipt({ hash })).status).toBe("success");
}

describe.skipIf(!requireAnvil)("P-256 Kernel owner local acceptance", () => {
  beforeAll(async () => {
    harness = await startHarness();
    await installPinnedContracts();
  }, 30_000);

  afterAll(async () => {
    if (harness) await stopAnvil(harness.process);
  });

  it("deploys, recreates exact owner evidence, and submits again without a live RPC", async () => {
    const privateKey = p256.utils.randomPrivateKey();
    const publicKey = toHex(p256.getPublicKey(privateKey, false));
    const firstSigns = { count: 0 };
    const first = await ownerRuntime(privateKey, firstSigns);
    expect(first.validatorAddress).toBe(validatorAddress);
    expect(first.factory.address).toBe(factoryAddress);
    expect(await restore(first, harness.publicClient)).toMatchObject({ status: "counterfactual" });
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
    const [x, y] = await harness.publicClient.readContract({
      address: validatorAddress,
      abi: validatorAbi,
      functionName: "publicKey",
      args: [first.accountAddress],
    });
    expect(
      `0x04${padHex(toHex(x), { size: 32 }).slice(2)}${padHex(toHex(y), { size: 32 }).slice(2)}`,
    ).toBe(publicKey);

    const recreatedClient = createPublicClient({
      transport: http(harness.url, { retryCount: 0 }),
    });
    const recreatedSigns = { count: 0 };
    const recreated = await ownerRuntime(privateKey, recreatedSigns);
    expect(recreated.accountAddress).toBe(first.accountAddress);
    expect(await restore(recreated, recreatedClient)).toMatchObject({ status: "deployed" });
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
