import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { p256 } from "@noble/curves/nist.js";
import { encodeCallDataEpV07 } from "@zerodev/sdk";
import {
  concatHex,
  createPublicClient,
  createWalletClient,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  hexToBytes,
  http,
  keccak256,
  type PublicClient,
  parseAbi,
  parseEther,
  sha256,
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
  createWebAuthnKernelOwnerRuntime,
  prepareUserOperation,
  type WebAuthnKernelOwnerRestorationReadRequest,
  type WebAuthnKernelOwnerRuntime,
} from "../src/index.js";

const requireAnvil = process.env.OGP_REQUIRE_ANVIL === "1";
const chainId = 31_337;
const implementationAddress = "0xd6cedde84be40893d153be9d467cd6ad37875b28" as const;
const factoryAddress = "0x2577507b78c2008ff367261cb6285d44ba5ef2e9" as const;
const validatorAddress = "0x7ab16ff354acb328452f1d445b3ddee9a91e9e69" as const;
const verifierAddress = "0xc2b78104907f722dabac4c69f826a522b2754de4" as const;
const fixedEntryPoint = entryPoint07Address.toLowerCase() as `0x${string}`;
const TEXT = new TextEncoder();
const assertionParameters = [
  { name: "authenticatorData", type: "bytes" },
  { name: "clientDataJSON", type: "string" },
  { name: "responseTypeLocation", type: "uint256" },
  { name: "r", type: "uint256" },
  { name: "s", type: "uint256" },
  { name: "usePrecompiled", type: "bool" },
] as const;
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
  "function isInitialized(address account) view returns (bool)",
  "function webAuthnValidatorStorage(address account) view returns (uint256 x, uint256 y)",
]);

interface Artifacts {
  provenance: { kernelVersion: string; kernelCommit: string };
  kernel: { keccak256: Hex; creationBytecode: Hex };
  factory: { keccak256: Hex; creationBytecode: Hex };
  webauthnValidator: {
    keccak256: Hex;
    runtimeKeccak256: Hex;
    runtimeByteLength: number;
    creationBytecode: Hex;
  };
  p256Verifier: {
    keccak256: Hex;
    runtimeKeccak256: Hex;
    runtimeByteLength: number;
    creationBytecode: Hex;
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

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
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
  if (!/^anvil Version: 1\.7\.1(?:-|$)/mu.test(version)) throw new Error("Anvil 1.7.1 is required");

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

async function deploy(bytecode: Hex, abi: readonly unknown[], args: readonly unknown[] = []) {
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

async function pinRuntime(
  source: Hex,
  target: Hex,
  expected?: { hash: Hex; length: number },
): Promise<void> {
  const code = await harness.publicClient.getCode({ address: source });
  if (!code || code === "0x") throw new Error("deployed runtime unavailable");
  if (expected) {
    expect(keccak256(code)).toBe(expected.hash);
    expect((code.length - 2) / 2).toBe(expected.length);
  }
  await harness.publicClient.request({
    method: "anvil_setCode" as "eth_chainId",
    params: [target, code] as never,
  });
  expect(await harness.publicClient.getCode({ address: target })).toBe(code);
}

async function installPinnedContracts(): Promise<void> {
  const artifacts = JSON.parse(
    await readFile(new URL("./fixtures/kernel-v3.3-bytecode.json", import.meta.url), "utf8"),
  ) as Artifacts;
  expect(artifacts.provenance).toMatchObject({
    kernelVersion: "0.3.3",
    kernelCommit: "cd697c7e21715d015e0643af22310a99aa17433b",
  });
  for (const artifact of [
    artifacts.kernel,
    artifacts.factory,
    artifacts.webauthnValidator,
    artifacts.p256Verifier,
  ]) {
    expect(keccak256(artifact.creationBytecode)).toBe(artifact.keccak256);
  }

  const entryPointArtifactRaw = await readFile(
    join(process.cwd(), "node_modules/@account-abstraction/contracts/artifacts/EntryPoint.json"),
    "utf8",
  );
  expect(createHash("sha256").update(entryPointArtifactRaw).digest("hex")).toBe(
    "952e7ce1e69354b9e80d0e68e0cbcc64f9304dd25c17170c3732114ea5421b04",
  );
  const entryPointArtifact = JSON.parse(entryPointArtifactRaw) as { bytecode: Hex };
  await pinRuntime(await deploy(entryPointArtifact.bytecode, entryPoint07Abi), fixedEntryPoint);
  const kernelSource = await deploy(artifacts.kernel.creationBytecode, kernelAbi, [
    fixedEntryPoint,
  ]);
  await pinRuntime(kernelSource, implementationAddress);
  const factorySource = await deploy(artifacts.factory.creationBytecode, factoryAbi, [
    implementationAddress,
  ]);
  await pinRuntime(factorySource, factoryAddress);
  await pinRuntime(
    await deploy(artifacts.webauthnValidator.creationBytecode, validatorAbi),
    validatorAddress,
    {
      hash: artifacts.webauthnValidator.runtimeKeccak256,
      length: artifacts.webauthnValidator.runtimeByteLength,
    },
  );
  await pinRuntime(await deploy(artifacts.p256Verifier.creationBytecode, []), verifierAddress, {
    hash: artifacts.p256Verifier.runtimeKeccak256,
    length: artifacts.p256Verifier.runtimeByteLength,
  });
}

function assertion(hash: Hex, privateKey: Uint8Array, rpId: string) {
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${base64url(hexToBytes(hash))}","origin":"https://example.test","crossOrigin":false}`;
  const authenticatorData = concatHex([sha256(toHex(TEXT.encode(rpId))), "0x05", "0x00000000"]);
  const messageHash = sha256(
    concatHex([authenticatorData, sha256(toHex(TEXT.encode(clientDataJSON)))]),
  );
  const signature = p256.sign(hexToBytes(messageHash), privateKey, { lowS: true });
  return {
    authenticatorData,
    clientDataJSON,
    responseTypeLocation: "1",
    r: toHex(signature.r, { size: 32 }),
    s: toHex(signature.s, { size: 32 }),
  };
}

function ownerRuntime(
  privateKey: Uint8Array,
  authenticatorBytes: Uint8Array,
  signs: { count: number },
) {
  const publicKey = lower(toHex(p256.getPublicKey(privateKey, false)));
  const authenticatorId = base64url(authenticatorBytes);
  const authenticatorIdHash = keccak256(toHex(authenticatorBytes));
  const rpId = "example.test";
  return createWebAuthnKernelOwnerRuntime({
    profile: {
      version: "ogp.kernel-account-profile/v1",
      kind: "kernel",
      accountIndex: "7",
      kernelVersion: "0.3.3",
      factoryRoute: "kernel_factory",
      entryPoint: { version: "0.7" },
      ownerCredential: {
        version: "ogp.owner-credential-profile/v1",
        kind: "webauthn",
        publicKey,
        authenticatorIdHash,
      },
    },
    chainId,
    signer: {
      publicKey,
      authenticatorId,
      authenticatorIdHash,
      rpId,
      async signMessageHash({ hash }: { hash: Hex }) {
        signs.count += 1;
        return assertion(hash, privateKey, rpId);
      },
    },
  });
}

async function prepare(runtime: WebAuthnKernelOwnerRuntime, nonce: bigint, deployed: boolean) {
  return prepareUserOperation({
    kind: "execution",
    grantId: "grant-webauthn-owner-anvil",
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
      factory: deployed ? null : runtime.factory,
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

async function submit(prepared: Awaited<ReturnType<typeof prepare>>, signature: Hex) {
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
  return harness.publicClient.waitForTransactionReceipt({ hash });
}

describe.skipIf(!requireAnvil)("WebAuthn Kernel owner local acceptance", () => {
  beforeAll(async () => {
    harness = await startHarness();
    await installPinnedContracts();
  }, 30_000);

  afterAll(async () => {
    if (harness) await stopAnvil(harness.process);
  });

  it("recreates exact deployed evidence and signs another accepted UserOperation", async () => {
    const privateKey = p256.utils.randomPrivateKey();
    const authenticatorBytes = crypto.getRandomValues(new Uint8Array(32));
    const firstSigns = { count: 0 };
    const first = await ownerRuntime(privateKey, authenticatorBytes, firstSigns);
    expect(first.validatorAddress).toBe(validatorAddress);
    await harness.publicClient.request({
      method: "anvil_setBalance" as "eth_chainId",
      params: [first.accountAddress, quantity(parseEther("10"))] as never,
    });

    const deployment = await prepare(first, 0n, false);
    const firstSignature = await first.signPreparedUserOperation(deployment);
    expect(decodeAbiParameters(assertionParameters, firstSignature)[5]).toBe(false);
    expect((await submit(deployment, firstSignature)).status).toBe("success");
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
      await harness.publicClient.readContract({
        address: validatorAddress,
        abi: validatorAbi,
        functionName: "isInitialized",
        args: [first.accountAddress],
      }),
    ).toBe(true);

    const recreatedSigns = { count: 0 };
    const recreated = await ownerRuntime(privateKey, authenticatorBytes, recreatedSigns);
    expect(recreated.accountAddress).toBe(first.accountAddress);
    await recreated.restore({
      async read(request: WebAuthnKernelOwnerRestorationReadRequest) {
        if (request.type === "chain_id") return harness.publicClient.getChainId();
        if (request.type === "account_code") {
          return lower((await harness.publicClient.getCode({ address: request.account })) ?? "0x");
        }
        if (request.type === "kernel_root_validator") {
          return lower(
            await harness.publicClient.readContract({
              address: request.account,
              abi: kernelAbi,
              functionName: "rootValidator",
            }),
          );
        }
        if (request.type === "runtime_code") {
          return lower((await harness.publicClient.getCode({ address: request.address })) ?? "0x");
        }
        if (request.type === "webauthn_validator_initialized") {
          return harness.publicClient.readContract({
            address: request.validator,
            abi: validatorAbi,
            functionName: "isInitialized",
            args: [request.account],
          });
        }
        const [x, y] = await harness.publicClient.readContract({
          address: request.validator,
          abi: validatorAbi,
          functionName: "webAuthnValidatorStorage",
          args: [request.account],
        });
        return lower(concatHex(["0x04", toHex(x, { size: 32 }), toHex(y, { size: 32 })]));
      },
    });
    const nonce = await harness.publicClient.readContract({
      address: fixedEntryPoint,
      abi: entryPoint07Abi,
      functionName: "getNonce",
      args: [recreated.accountAddress, 0n],
    });
    expect(nonce).toBe(1n);
    const restoredOperation = await prepare(recreated, nonce, true);
    const validSignature = await recreated.signPreparedUserOperation(restoredOperation);
    const decoded = decodeAbiParameters(assertionParameters, validSignature);
    const invalidSignature = encodeAbiParameters(assertionParameters, [
      decoded[0],
      decoded[1],
      decoded[2],
      decoded[3] + 1n,
      decoded[4],
      decoded[5],
    ]);
    expect((await submit(restoredOperation, invalidSignature)).status).toBe("reverted");
    expect((await submit(restoredOperation, validSignature)).status).toBe("success");
    expect(recreatedSigns.count).toBe(1);
    expect(
      await harness.publicClient.readContract({
        address: fixedEntryPoint,
        abi: entryPoint07Abi,
        functionName: "getNonce",
        args: [recreated.accountAddress, 0n],
      }),
    ).toBe(2n);
  }, 30_000);
});
