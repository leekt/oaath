import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  type Hex,
  http,
  keccak256,
  type PublicClient,
  parseEther,
  zeroAddress,
} from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { generatePrivateKey, type PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createLocalKernelHandleOpsAdapter,
  createOperationObserver,
  createOperationRunner,
  type OperationObserverReadRequest,
  OperationStore,
  type OperationStoreAdapter,
} from "../src/index.js";

const requireAnvil = process.env.OGP_REQUIRE_ANVIL === "1";
const chainId = 31_337;
const userOperationEvent = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";
const kernelAbi = [
  {
    type: "constructor",
    inputs: [{ name: "_entryPoint", type: "address" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "initialize",
    inputs: [
      { name: "_rootValidator", type: "bytes21" },
      { name: "hook", type: "address" },
      { name: "validatorData", type: "bytes" },
      { name: "hookData", type: "bytes" },
      { name: "initConfig", type: "bytes[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "rootValidator",
    inputs: [],
    outputs: [{ name: "", type: "bytes21" }],
    stateMutability: "view",
  },
] as const;
const factoryAbi = [
  {
    type: "constructor",
    inputs: [{ name: "_impl", type: "address" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "createAccount",
    inputs: [
      { name: "data", type: "bytes" },
      { name: "salt", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "getAddress",
    inputs: [
      { name: "data", type: "bytes" },
      { name: "salt", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
] as const;
const validatorAbi = [
  {
    type: "function",
    name: "ecdsaValidatorStorage",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "owner", type: "address" }],
    stateMutability: "view",
  },
] as const;

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
  entryPoint: `0x${string}`;
  factory: `0x${string}`;
  validator: `0x${string}`;
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

async function deploy(
  wallet: ReturnType<typeof createWalletClient>,
  client: PublicClient,
  bytecode: Hex,
  abi: readonly unknown[],
  args: readonly unknown[] = [],
): Promise<`0x${string}`> {
  const account = wallet.account;
  if (!account) throw new Error("deployment account unavailable");
  const hash = await wallet.deployContract({
    abi,
    bytecode,
    args,
    gas: 20_000_000n,
    account,
    chain: null,
  });
  const receipt = await client.waitForTransactionReceipt({ hash });
  if (!receipt.contractAddress || receipt.status !== "success")
    throw new Error("contract deployment failed");
  return lower(receipt.contractAddress);
}

async function startHarness(): Promise<Harness> {
  const anvilPath = globalThis.process.env.ANVIL_PATH ?? "anvil";
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
  if (!version.includes("1.7.1")) throw new Error("Anvil 1.7.1 is required");

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
  const publicClient = createPublicClient({ transport: http(url, { retryCount: 0 }) });
  await waitForAnvil(publicClient, anvilProcess);

  const submitter = privateKeyToAccount(generatePrivateKey());
  await publicClient.request({
    method: "anvil_setBalance" as "eth_chainId",
    params: [submitter.address, quantity(parseEther("100"))] as never,
  });
  const wallet = createWalletClient({
    account: submitter,
    transport: http(url, { retryCount: 0 }),
  });
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
  const entryPoint = await deploy(
    wallet,
    publicClient,
    entryPointArtifact.bytecode,
    entryPoint07Abi,
  );
  const implementation = await deploy(
    wallet,
    publicClient,
    artifacts.kernel.creationBytecode,
    kernelAbi,
    [entryPoint],
  );
  const factory = await deploy(
    wallet,
    publicClient,
    artifacts.factory.creationBytecode,
    factoryAbi,
    [implementation],
  );
  const validator = await deploy(
    wallet,
    publicClient,
    artifacts.ecdsaValidator.creationBytecode,
    [],
  );
  return { process: anvilProcess, url, publicClient, submitter, entryPoint, factory, validator };
}

async function createKernel(owner: `0x${string}`, salt: Hex): Promise<`0x${string}`> {
  const validationId = `0x01${harness.validator.slice(2)}` as Hex;
  const initialize = encodeFunctionData({
    abi: kernelAbi,
    functionName: "initialize",
    args: [validationId, zeroAddress, owner, "0x", []],
  });
  const account = lower(
    await harness.publicClient.readContract({
      address: harness.factory,
      abi: factoryAbi,
      functionName: "getAddress",
      args: [initialize, salt],
    }),
  );
  const wallet = createWalletClient({
    account: harness.submitter,
    transport: http(harness.url, { retryCount: 0 }),
  });
  const hash = await wallet.writeContract({
    address: harness.factory,
    abi: factoryAbi,
    functionName: "createAccount",
    args: [initialize, salt],
    account: harness.submitter,
    chain: null,
  });
  expect((await harness.publicClient.waitForTransactionReceipt({ hash })).status).toBe("success");
  await harness.publicClient.request({
    method: "anvil_setBalance" as "eth_chainId",
    params: [account, quantity(parseEther("10"))] as never,
  });
  return account;
}

function rawLog(log: {
  address: string;
  blockNumber: bigint | null;
  blockHash: Hex | null;
  transactionHash: Hex | null;
  transactionIndex: number | null;
  logIndex: number | null;
  removed: boolean;
  topics: readonly Hex[];
  data: Hex;
}) {
  if (
    log.blockNumber === null ||
    log.blockHash === null ||
    log.transactionHash === null ||
    log.transactionIndex === null ||
    log.logIndex === null
  ) {
    throw new Error("unmined log");
  }
  return {
    address: lower(log.address),
    blockNumber: quantity(log.blockNumber),
    blockHash: lower(log.blockHash),
    transactionHash: lower(log.transactionHash),
    transactionIndex: quantity(log.transactionIndex),
    logIndex: quantity(log.logIndex),
    removed: log.removed,
    topics: log.topics.map(lower),
    data: lower(log.data),
  };
}

async function rawBlock(parameters: {
  blockNumber?: bigint;
  blockHash?: Hex;
  blockTag?: "finalized";
}) {
  const block =
    parameters.blockNumber !== undefined
      ? await harness.publicClient.getBlock({
          blockNumber: parameters.blockNumber,
          includeTransactions: false,
        })
      : parameters.blockHash !== undefined
        ? await harness.publicClient.getBlock({
            blockHash: parameters.blockHash,
            includeTransactions: false,
          })
        : await harness.publicClient.getBlock({
            blockTag: parameters.blockTag ?? "finalized",
            includeTransactions: false,
          });
  if (block.hash === null) throw new Error("unmined block");
  return {
    number: quantity(block.number),
    hash: lower(block.hash),
    parentHash: lower(block.parentHash),
    transactions: block.transactions.map(lower),
  };
}

function observerCapabilities(entryPoint: `0x${string}`) {
  return {
    async read(request: OperationObserverReadRequest) {
      if (request.type === "chain_id") return harness.publicClient.getChainId();
      if (request.type === "replacement_candidate") return null;
      if (request.type === "user_operation_receipt") {
        const matches = (
          await harness.publicClient.getLogs({
            address: entryPoint,
            fromBlock: 0n,
            toBlock: "latest",
          })
        ).filter(
          (log) =>
            lower(log.topics[0] ?? "0x") === userOperationEvent &&
            lower(log.topics[1] ?? "0x") === request.userOperationHash,
        );
        if (matches.length === 0) return null;
        if (matches.length !== 1) throw new Error("duplicate UserOperation event");
        const log = matches[0];
        if (!log?.transactionHash) throw new Error("unmined UserOperation event");
        const receipt = await harness.publicClient.getTransactionReceipt({
          hash: log.transactionHash,
        });
        const decoded = decodeEventLog({
          abi: entryPoint07Abi,
          data: log.data,
          topics: log.topics,
        });
        const args = decoded.args as unknown as {
          userOpHash: Hex;
          sender: `0x${string}`;
          paymaster: `0x${string}`;
          nonce: bigint;
          success: boolean;
          actualGasCost: bigint;
          actualGasUsed: bigint;
        };
        return {
          userOperationHash: lower(args.userOpHash),
          entryPoint,
          sender: lower(args.sender),
          nonce: quantity(args.nonce),
          paymaster: lower(args.paymaster),
          actualGasCost: quantity(args.actualGasCost),
          actualGasUsed: quantity(args.actualGasUsed),
          success: args.success,
          transactionHash: lower(receipt.transactionHash),
          blockNumber: quantity(receipt.blockNumber),
          blockHash: lower(receipt.blockHash),
        };
      }
      if (request.type === "transaction_receipt") {
        const receipt = await harness.publicClient.getTransactionReceipt({
          hash: request.transactionHash,
        });
        return {
          transactionHash: lower(receipt.transactionHash),
          blockNumber: quantity(receipt.blockNumber),
          blockHash: lower(receipt.blockHash),
          transactionIndex: quantity(receipt.transactionIndex),
          status: receipt.status === "success" ? "0x1" : "0x0",
          logs: receipt.logs.map((log) => rawLog({ ...log, removed: false })),
        };
      }
      if (request.type === "transaction") {
        const transaction = await harness.publicClient.getTransaction({
          hash: request.transactionHash,
        });
        if (
          transaction.blockNumber === null ||
          transaction.blockHash === null ||
          transaction.transactionIndex === null
        ) {
          throw new Error("unmined transaction");
        }
        return {
          hash: lower(transaction.hash),
          to: transaction.to === null ? null : lower(transaction.to),
          blockNumber: quantity(transaction.blockNumber),
          blockHash: lower(transaction.blockHash),
          transactionIndex: quantity(transaction.transactionIndex),
        };
      }
      if (request.type === "canonical_block") {
        return rawBlock({ blockNumber: BigInt(request.blockNumber) });
      }
      if (request.type === "block_by_hash") return rawBlock({ blockHash: request.blockHash });
      if (request.type === "finalized_block") return rawBlock({ blockTag: "finalized" });
      throw new Error("unsupported observer request");
    },
    async close() {},
  };
}

function memoryStore(): OperationStore {
  let record: unknown;
  const adapter: OperationStoreAdapter = {
    async get() {
      return record;
    },
    async compareAndSwap(input) {
      const current = record as { storeRevision: number } | undefined;
      if (
        (input.expectedStoreRevision === null && current !== undefined) ||
        (input.expectedStoreRevision !== null &&
          current?.storeRevision !== input.expectedStoreRevision)
      ) {
        return false;
      }
      record = input.next;
      return true;
    },
    async close() {},
  };
  return new OperationStore(adapter);
}

async function execute(call: { target: `0x${string}`; data: Hex }, grantId: string) {
  const owner = privateKeyToAccount(generatePrivateKey());
  expect(lower(owner.address)).not.toBe(lower(harness.submitter.address));
  const account = await createKernel(lower(owner.address), keccak256(generatePrivateKey()));
  let signs = 0;
  let sends = 0;
  let signedHash: Hex | undefined;
  const adapter = createLocalKernelHandleOpsAdapter({
    profile: "kernel-v3.3-ecdsa-owner",
    key: { grantId, chainId },
    entryPoint: { version: "0.7", address: harness.entryPoint },
    kernel: { account, rootValidator: harness.validator, owner: lower(owner.address) },
    call: { target: call.target, value: "0", data: call.data },
    gas: {
      callGasLimit: "300000",
      verificationGasLimit: "500000",
      preVerificationGas: "100000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
    },
    handleOpsGasLimit: "2000000",
    preparationReads: {
      async read(request: { type: string; address?: `0x${string}` }) {
        if (request.type === "chain_id") return harness.publicClient.getChainId();
        if (request.type === "code") {
          if (!request.address) throw new Error("code address unavailable");
          return lower((await harness.publicClient.getCode({ address: request.address })) ?? "0x");
        }
        if (request.type === "kernel_root_validator") {
          return lower(
            await harness.publicClient.readContract({
              address: account,
              abi: kernelAbi,
              functionName: "rootValidator",
            }),
          );
        }
        if (request.type === "kernel_ecdsa_owner") {
          return lower(
            await harness.publicClient.readContract({
              address: harness.validator,
              abi: validatorAbi,
              functionName: "ecdsaValidatorStorage",
              args: [account],
            }),
          );
        }
        if (request.type === "entry_point_nonce") {
          return (
            await harness.publicClient.readContract({
              address: harness.entryPoint,
              abi: entryPoint07Abi,
              functionName: "getNonce",
              args: [account, 0n],
            })
          ).toString(10);
        }
        throw new Error("unexpected preparation read");
      },
      async close() {},
    },
    userOperationSigner: {
      address: lower(owner.address),
      async signDigest(request: { userOperationHash: Hex }) {
        signs += 1;
        signedHash = request.userOperationHash;
        return owner.sign({ hash: request.userOperationHash });
      },
      async close() {},
    },
    handleOpsSubmitter: {
      address: lower(harness.submitter.address),
      async sendHandleOps(request: {
        chainId: number;
        entryPoint: `0x${string}`;
        submitter: `0x${string}`;
        userOperationHash: Hex;
        calldata: Hex;
        gasLimit: string;
      }) {
        sends += 1;
        const wallet = createWalletClient({
          account: harness.submitter,
          transport: http(harness.url, { retryCount: 0 }),
        });
        const transactionHash = await wallet.sendTransaction({
          account: harness.submitter,
          to: request.entryPoint,
          data: request.calldata,
          gas: BigInt(request.gasLimit),
          maxFeePerGas: 2_000_000_000n,
          maxPriorityFeePerGas: 1_000_000_000n,
          chain: null,
        });
        await harness.publicClient.waitForTransactionReceipt({ hash: transactionHash });
        const transaction = await harness.publicClient.getTransaction({ hash: transactionHash });
        expect(lower(transaction.from)).toBe(lower(harness.submitter.address));
        expect(lower(transaction.to ?? zeroAddress)).toBe(harness.entryPoint);
        return {
          chainId: request.chainId,
          entryPoint: request.entryPoint,
          submitter: request.submitter,
          userOperationHash: request.userOperationHash,
          transactionHash: lower(transactionHash),
        };
      },
      async close() {},
    },
  });
  const runner = createOperationRunner({
    store: memoryStore(),
    observer: createOperationObserver(observerCapabilities(harness.entryPoint)),
    preparation: adapter.preparation,
    submission: adapter.submission,
  });
  const first = await runner.runOperation({
    kind: "execution",
    key: { grantId, chainId },
    preparedAt: 10,
    attemptedAt: 11,
    submittedAt: 12,
    observedAt: 13,
    timeoutMs: 60_000,
  });
  expect(first).toMatchObject({
    status: "observed",
    observation: { status: "unreadable", reason: "finality_unproven" },
    record: { value: { state: "included", identity: { chainId, account } } },
  });
  await harness.publicClient.request({
    method: "anvil_mine" as "eth_chainId",
    params: ["0x80"] as never,
  });
  const finalized = await runner.runOperation({
    kind: "execution",
    key: { grantId, chainId },
    preparedAt: 20,
    attemptedAt: 21,
    submittedAt: 22,
    observedAt: 23,
    timeoutMs: 60_000,
  });
  await runner.close();
  return { finalized, signs, sends, signedHash, account };
}

describe.skipIf(!requireAnvil)("local Kernel and EntryPoint execution", () => {
  beforeAll(async () => {
    harness = await startHarness();
  }, 60_000);

  afterAll(async () => {
    if (!harness?.process || harness.process.exitCode !== null) return;
    harness.process.kill("SIGTERM");
    await new Promise<void>((resolve) => harness.process.once("exit", () => resolve()));
  });

  it.each([
    ["success", () => ({ target: lower(harness.submitter.address), data: "0x" as Hex })],
    ["reverted", () => ({ target: harness.entryPoint, data: "0xffffffff" as Hex })],
  ] as const)(
    "finalizes an exact real UserOperation with inner outcome %s",
    async (outcome, call) => {
      const result = await execute(call(), `anvil-${outcome}`);
      expect(result.finalized).toMatchObject({
        status: "observed",
        observation: { status: "finalized", operation: { inclusion: { outcome } } },
        record: {
          value: {
            state: "finalized",
            identity: {
              chainId,
              entryPoint: harness.entryPoint,
              account: result.account,
              nonce: "0",
              userOperationHash: result.signedHash,
            },
            inclusion: { outcome },
          },
        },
      });
      expect(result.signedHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect({ signs: result.signs, sends: result.sends }).toEqual({ signs: 1, sends: 1 });
    },
    60_000,
  );
});
