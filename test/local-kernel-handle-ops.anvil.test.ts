import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  concat,
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  decodeFunctionResult,
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  http,
  keccak256,
  type PublicClient,
  pad,
  parseAbi,
  parseEther,
  slice,
  zeroAddress,
} from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { generatePrivateKey, type PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  advanceGrant,
  createGrant,
  createKernelPermissionRemovalObserver,
  createKernelPermissionRevocationCoordinator,
  createLocalKernelHandleOpsAdapter,
  createLocalKernelPermissionUninstallAdapter,
  createOperationObserver,
  createOperationRunner,
  type Grant,
  type GrantIdentity,
  type KernelPermissionStateReadRequest,
  type KernelPreparationReadRequest,
  type OperationObserverReadRequest,
  OperationStore,
  type OperationStoreAdapter,
} from "../src/index.js";
import { createSqliteGrantStore, createSqliteOperationStore } from "../src/testing.js";

const requireAnvil = process.env.OGP_REQUIRE_ANVIL === "1";
const chainId = 31_337;
const userOperationEvent = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";
const kernelAbi = parseAbi([
  "constructor(address _entryPoint)",
  "function initialize(bytes21 _rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
  "function rootValidator() view returns (bytes21)",
  "function installValidations(bytes21[] vIds, (uint32 nonce, address hook)[] configs, bytes[] validationData, bytes[] hookData)",
  "function grantAccess(bytes21 vId, bytes4 selector, bool allow)",
  "function validationConfig(bytes21 vId) view returns ((uint32 nonce, address hook) config)",
  "function permissionConfig(bytes4 pId) view returns ((bytes2 permissionFlag, address signer, bytes22[] policyData) config)",
  "function isAllowedSelector(bytes21 vId, bytes4 selector) view returns (bool)",
]);
const factoryAbi = parseAbi([
  "constructor(address _impl)",
  "function createAccount(bytes data, bytes32 salt) payable returns (address)",
  "function getAddress(bytes data, bytes32 salt) view returns (address)",
]);
const validatorAbi = parseAbi([
  "function ecdsaValidatorStorage(address account) view returns (address owner)",
]);
const multiChainSignerAbi = parseAbi([
  "function signer(bytes32 id, address wallet) view returns (address owner)",
]);

interface KernelArtifacts {
  provenance: { kernelVersion: string; kernelCommit: string };
  kernel: { keccak256: Hex; creationBytecode: Hex };
  factory: { keccak256: Hex; creationBytecode: Hex };
  ecdsaValidator: { keccak256: Hex; creationBytecode: Hex };
  multiChainSigner: { keccak256: Hex; runtimeKeccak256: Hex; creationBytecode: Hex };
}

interface Harness {
  process: ChildProcess;
  url: string;
  publicClient: PublicClient;
  submitter: PrivateKeyAccount;
  entryPoint: `0x${string}`;
  factory: `0x${string}`;
  validator: `0x${string}`;
  multiChainSigner: `0x${string}`;
  submitterPrivateKey: Hex;
}

let harness: Harness;
const temporaryDirectories: string[] = [];

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

async function stopAnvil(process: ChildProcess): Promise<void> {
  if (process.exitCode !== null) return;
  const exited = new Promise<void>((resolve) => process.once("exit", () => resolve()));
  process.kill("SIGTERM");
  await exited;
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

    const submitterPrivateKey = generatePrivateKey();
    const submitter = privateKeyToAccount(submitterPrivateKey);
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
    expect(keccak256(artifacts.multiChainSigner.creationBytecode)).toBe(
      artifacts.multiChainSigner.keccak256,
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
    const multiChainSigner = await deploy(
      wallet,
      publicClient,
      artifacts.multiChainSigner.creationBytecode,
      multiChainSignerAbi,
    );
    expect(keccak256((await publicClient.getCode({ address: multiChainSigner })) ?? "0x")).toBe(
      artifacts.multiChainSigner.runtimeKeccak256,
    );
    return {
      process: anvilProcess,
      url,
      publicClient,
      submitter,
      entryPoint,
      factory,
      validator,
      multiChainSigner,
      submitterPrivateKey,
    };
  } catch (error) {
    await stopAnvil(anvilProcess);
    throw error;
  }
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

function permissionProfile(signer: `0x${string}`, operator: `0x${string}`) {
  const policySetId = encodeAbiParameters([{ type: "bytes[]" }], [[]]);
  const signerId = encodeAbiParameters([{ type: "bytes" }], [concat([signer, operator])]);
  const permissionId = slice(
    keccak256(encodeAbiParameters([{ type: "bytes[]" }], [[policySetId, "0x0000", signerId]])),
    0,
    4,
  );
  return {
    permissionId,
    validationId: `0x02${permissionId.slice(2)}${"00".repeat(16)}` as Hex,
    enableData: encodeAbiParameters(
      [{ type: "bytes[]" }],
      [[concat(["0x0000", signer, operator])]],
    ),
  } as const;
}

async function createKernelWithPermission(
  owner: `0x${string}`,
  operator: `0x${string}`,
): Promise<{ account: `0x${string}`; blockNumber: string; blockHash: Hex }> {
  const rootValidationId = `0x01${harness.validator.slice(2)}` as Hex;
  const permission = permissionProfile(harness.multiChainSigner, operator);
  const initConfig = [
    encodeFunctionData({
      abi: kernelAbi,
      functionName: "installValidations",
      args: [
        [permission.validationId],
        [{ nonce: 1, hook: zeroAddress }],
        [permission.enableData],
        ["0x"],
      ],
    }),
    encodeFunctionData({
      abi: kernelAbi,
      functionName: "grantAccess",
      args: [permission.validationId, "0xe9ae5c53", true],
    }),
  ];
  const initialize = encodeFunctionData({
    abi: kernelAbi,
    functionName: "initialize",
    args: [rootValidationId, zeroAddress, owner, "0x", initConfig],
  });
  const salt = keccak256(generatePrivateKey());
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
  const receipt = await harness.publicClient.waitForTransactionReceipt({ hash });
  expect(receipt.status).toBe("success");
  await harness.publicClient.request({
    method: "anvil_setBalance" as "eth_chainId",
    params: [account, quantity(parseEther("10"))] as never,
  });
  return {
    account,
    blockNumber: receipt.blockNumber.toString(10),
    blockHash: lower(receipt.blockHash),
  };
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

async function rawBlock(
  parameters: {
    blockNumber?: bigint;
    blockHash?: Hex;
    blockTag?: "finalized";
  },
  client: PublicClient = harness.publicClient,
) {
  const block =
    parameters.blockNumber !== undefined
      ? await client.getBlock({
          blockNumber: parameters.blockNumber,
          includeTransactions: false,
        })
      : parameters.blockHash !== undefined
        ? await client.getBlock({
            blockHash: parameters.blockHash,
            includeTransactions: false,
          })
        : await client.getBlock({
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

function observerCapabilities(
  entryPoint: `0x${string}`,
  client: PublicClient = harness.publicClient,
) {
  return {
    async read(request: OperationObserverReadRequest) {
      if (request.type === "chain_id") return client.getChainId();
      if (request.type === "replacement_candidate") return null;
      if (request.type === "user_operation_receipt") {
        const matches = (
          await client.getLogs({
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
        const receipt = await client.getTransactionReceipt({
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
        const receipt = await client.getTransactionReceipt({
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
        const transaction = await client.getTransaction({
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
        return rawBlock({ blockNumber: BigInt(request.blockNumber) }, client);
      }
      if (request.type === "block_by_hash")
        return rawBlock({ blockHash: request.blockHash }, client);
      if (request.type === "finalized_block") return rawBlock({ blockTag: "finalized" }, client);
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

async function execute(
  call: { target: `0x${string}`; data: Hex },
  grantId: string,
  options: { loseAcknowledgment?: boolean } = {},
) {
  const ownerPrivateKey = generatePrivateKey();
  const ownerAddress = lower(privateKeyToAccount(ownerPrivateKey).address);
  expect(ownerAddress).not.toBe(lower(harness.submitter.address));
  const account = await createKernel(ownerAddress, keccak256(generatePrivateKey()));
  let signs = 0;
  let sends = 0;
  let signedHash: Hex | undefined;
  let sentTransactionHash: Hex | undefined;
  let loseAcknowledgment = options.loseAcknowledgment ?? false;

  function createAdapter(client: PublicClient) {
    const owner = privateKeyToAccount(ownerPrivateKey);
    const submitter = privateKeyToAccount(harness.submitterPrivateKey);
    return createLocalKernelHandleOpsAdapter({
      profile: "kernel-v3.3-ecdsa-owner",
      key: { grantId, chainId },
      entryPoint: { version: "0.7", address: harness.entryPoint },
      kernel: { account, rootValidator: harness.validator, owner: ownerAddress },
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
          if (request.type === "chain_id") return client.getChainId();
          if (request.type === "code") {
            if (!request.address) throw new Error("code address unavailable");
            return lower((await client.getCode({ address: request.address })) ?? "0x");
          }
          if (request.type === "kernel_root_validator") {
            return lower(
              await client.readContract({
                address: account,
                abi: kernelAbi,
                functionName: "rootValidator",
              }),
            );
          }
          if (request.type === "kernel_ecdsa_owner") {
            return lower(
              await client.readContract({
                address: harness.validator,
                abi: validatorAbi,
                functionName: "ecdsaValidatorStorage",
                args: [account],
              }),
            );
          }
          if (request.type === "entry_point_nonce") {
            return (
              await client.readContract({
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
        address: lower(submitter.address),
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
            account: submitter,
            transport: http(harness.url, { retryCount: 0 }),
          });
          const transactionHash = await wallet.sendTransaction({
            account: submitter,
            to: request.entryPoint,
            data: request.calldata,
            gas: BigInt(request.gasLimit),
            maxFeePerGas: 2_000_000_000n,
            maxPriorityFeePerGas: 1_000_000_000n,
            chain: null,
          });
          await client.waitForTransactionReceipt({ hash: transactionHash });
          const transaction = await client.getTransaction({ hash: transactionHash });
          sentTransactionHash = lower(transactionHash);
          expect(lower(transaction.from)).toBe(lower(submitter.address));
          expect(lower(transaction.to ?? zeroAddress)).toBe(harness.entryPoint);
          if (loseAcknowledgment) {
            loseAcknowledgment = false;
            throw new Error("loopback acknowledgement lost");
          }
          return {
            chainId: request.chainId,
            entryPoint: request.entryPoint,
            submitter: request.submitter,
            userOperationHash: request.userOperationHash,
            transactionHash: sentTransactionHash,
          };
        },
        async close() {},
      },
    });
  }

  const directory = options.loseAcknowledgment
    ? await mkdtemp(join(tmpdir(), "ogp-kernel-anvil-"))
    : undefined;
  if (directory) temporaryDirectories.push(directory);
  const storePath = directory ? join(directory, "operation.db") : undefined;
  const firstRuntimeClient = createPublicClient({
    transport: http(harness.url, { retryCount: 0 }),
  });
  let adapter = createAdapter(firstRuntimeClient);
  let runner = createOperationRunner({
    terminalBehavior: "replace",
    store: storePath ? createSqliteOperationStore(storePath) : memoryStore(),
    observer: createOperationObserver(observerCapabilities(harness.entryPoint, firstRuntimeClient)),
    preparation: adapter.preparation,
    submission: adapter.submission,
  });
  try {
    const first = await runner.runOperation({
      kind: "execution",
      key: { grantId, chainId },
      preparedAt: 10,
      attemptedAt: 11,
      submittedAt: 12,
      observedAt: 13,
      timeoutMs: 60_000,
    });
    if (!options.loseAcknowledgment) {
      expect(first).toMatchObject({
        status: "observed",
        observation: { status: "unreadable", reason: "finality_unproven" },
        record: { value: { state: "included", identity: { chainId, account } } },
      });
    }
    if (storePath) {
      await runner.close();
    }
    await harness.publicClient.request({
      method: "anvil_mine" as "eth_chainId",
      params: ["0x80"] as never,
    });
    if (storePath) {
      const recoveryClient = createPublicClient({
        transport: http(harness.url, { retryCount: 0 }),
      });
      adapter = createAdapter(recoveryClient);
      runner = createOperationRunner({
        terminalBehavior: "replace",
        store: createSqliteOperationStore(storePath),
        observer: createOperationObserver(observerCapabilities(harness.entryPoint, recoveryClient)),
        preparation: adapter.preparation,
        submission: adapter.submission,
      });
    }
    const finalized = await runner.runOperation({
      kind: "execution",
      key: { grantId, chainId },
      preparedAt: 20,
      attemptedAt: 21,
      submittedAt: 22,
      observedAt: 23,
      timeoutMs: 60_000,
    });
    const result = {
      first,
      finalized,
      signs,
      sends,
      signedHash,
      sentTransactionHash,
      account,
    };
    await runner.close();
    if (directory) await rm(directory, { recursive: true, force: true });
    return result;
  } catch (error) {
    await Promise.allSettled([
      runner.close(),
      directory ? rm(directory, { recursive: true, force: true }) : Promise.resolve(),
    ]);
    throw error;
  }
}

function activePermissionGrant(
  account: `0x${string}`,
  permissionId: Hex,
  installation: { blockNumber: string; blockHash: Hex },
): Grant {
  const identity: GrantIdentity = {
    grantId: "anvil-permission-revocation",
    chainScope: "all",
    application: {
      applicationId: "ogp-tests",
      clientId: "anvil-revocation",
      origin: "https://anvil.example",
      deviceId: "anvil-device",
    },
    logicalAccount: {
      kind: "kernel",
      accountIndex: "0",
      kernelVersion: "0.3.3",
      factoryRoute: "kernel_factory",
      ownerCredential: { kind: "ecdsa", publicIdentityHash: `0x${"aa".repeat(32)}` },
    },
    operatorCredential: { kind: "ecdsa", publicIdentityHash: `0x${"bb".repeat(32)}` },
    policyHash: `0x${"cc".repeat(32)}`,
  };
  const binding = { chainId, account, permissionId };
  let grant: Grant = createGrant({ identity, requestedAt: 10, expiresAt: 1_000 });
  grant = advanceGrant(grant, {
    type: "approve",
    identity,
    approval: {
      approvalHash: `0x${"dd".repeat(32)}`,
      capabilityHash: `0x${"ee".repeat(32)}`,
      approvedAt: 20,
    },
  });
  grant = advanceGrant(grant, { type: "activate", identity, activatedAt: 30 });
  grant = advanceGrant(grant, { type: "record_unmaterialized", identity, binding, recordedAt: 31 });
  grant = advanceGrant(grant, { type: "begin_materialization", identity, binding, startedAt: 32 });
  return advanceGrant(grant, {
    type: "record_installed",
    identity,
    binding,
    installation: {
      kind: "permission_present",
      ...binding,
      ...installation,
      observedAt: 33,
    },
  });
}

async function eip1898Call(
  client: PublicClient,
  account: `0x${string}`,
  blockHash: Hex,
  functionName: "validationConfig" | "permissionConfig",
  args: readonly [Hex],
) {
  const data = encodeFunctionData({ abi: kernelAbi, functionName, args } as never);
  const result = await client.request({
    method: "eth_call" as "eth_chainId",
    params: [
      { to: account, data },
      { blockHash, requireCanonical: true },
    ] as never,
  });
  return decodeFunctionResult({ abi: kernelAbi, functionName, data: result as Hex } as never);
}

function permissionStateReads(client: PublicClient) {
  return {
    async read(request: KernelPermissionStateReadRequest) {
      const common = {
        chainId: request.chainId,
        account: request.account,
        blockNumber: request.blockNumber,
        blockHash: request.blockHash,
        requireCanonical: true as const,
      };
      if (request.type === "code") {
        const code = await client.request({
          method: "eth_getCode" as "eth_chainId",
          params: [
            request.account,
            { blockHash: request.blockHash, requireCanonical: true },
          ] as never,
        });
        return { ...common, code: lower(code as string) };
      }
      if (request.type === "kernel_validation_config") {
        const config = (await eip1898Call(
          client,
          request.account,
          request.blockHash,
          "validationConfig",
          [request.validationId],
        )) as { nonce: number; hook: `0x${string}` };
        return {
          ...common,
          validationId: request.validationId,
          nonce: config.nonce.toString(10),
          hook: lower(config.hook),
        };
      }
      const config = (await eip1898Call(
        client,
        request.account,
        request.blockHash,
        "permissionConfig",
        [request.permissionId],
      )) as { permissionFlag: Hex; signer: `0x${string}`; policyData: readonly Hex[] };
      return {
        ...common,
        permissionId: request.permissionId,
        permissionFlag: lower(config.permissionFlag),
        signer: lower(config.signer),
        policyCount: config.policyData.length,
      };
    },
    async close() {},
  };
}

describe.skipIf(!requireAnvil)("local Kernel and EntryPoint execution", () => {
  beforeAll(async () => {
    harness = await startHarness();
  }, 60_000);

  afterAll(async () => {
    if (harness?.process) await stopAnvil(harness.process);
    await Promise.all(
      temporaryDirectories.map((directory) => rm(directory, { recursive: true, force: true })),
    );
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

  it("recovers observe-only after the real handleOps send loses its acknowledgement", async () => {
    const result = await execute(
      { target: lower(harness.submitter.address), data: "0x" },
      "anvil-ambiguous",
      { loseAcknowledgment: true },
    );
    expect(result.first).toMatchObject({
      status: "submission_uncertain",
      reason: "send_ambiguous",
      record: { value: { state: "submission_attempted" } },
    });
    expect(result.finalized).toMatchObject({
      status: "observed",
      observation: { status: "finalized" },
      record: {
        value: {
          state: "finalized",
          identity: { userOperationHash: result.signedHash },
          inclusion: { outcome: "success" },
        },
      },
    });
    if (result.first.status !== "submission_uncertain") {
      throw new Error("expected uncertain submission");
    }
    if (result.finalized.status !== "observed") throw new Error("expected observed recovery");
    expect(result.finalized.record.value.identity).toEqual(result.first.record.value.identity);
    expect(result.finalized.record.value.identity).toEqual({
      kind: "execution",
      grantId: "anvil-ambiguous",
      chainId,
      entryPoint: harness.entryPoint,
      account: result.account,
      nonce: "0",
      userOperationHash: result.signedHash,
    });
    if (!result.sentTransactionHash) throw new Error("missing submitted transaction identity");
    const transactionReceipt = await harness.publicClient.getTransactionReceipt({
      hash: result.sentTransactionHash,
    });
    const finalizedBlock = await harness.publicClient.getBlock({ blockTag: "finalized" });
    expect(result.finalized.record.value).toMatchObject({
      inclusion: {
        transactionHash: result.sentTransactionHash,
        blockNumber: transactionReceipt.blockNumber.toString(10),
        blockHash: lower(transactionReceipt.blockHash),
        outcome: "success",
        observedAt: 23,
      },
      finality: {
        blockNumber: finalizedBlock.number.toString(10),
        blockHash: lower(finalizedBlock.hash ?? "0x"),
        observedAt: 23,
      },
    });
    expect({ signs: result.signs, sends: result.sends }).toEqual({ signs: 1, sends: 1 });
  }, 60_000);

  it("revokes one exact permission after send-return crash and full recreation", async () => {
    const ownerPrivateKey = generatePrivateKey();
    const operator = privateKeyToAccount(generatePrivateKey());
    const owner = privateKeyToAccount(ownerPrivateKey);
    const installed = await createKernelWithPermission(
      lower(owner.address),
      lower(operator.address),
    );
    const permission = permissionProfile(harness.multiChainSigner, lower(operator.address));
    const directory = await mkdtemp(join(tmpdir(), "ogp-kernel-revoke-anvil-"));
    temporaryDirectories.push(directory);
    const storePath = join(directory, "state.db");
    const seed = createSqliteGrantStore(storePath);
    expect(
      await seed.compareAndSwap({
        grantId: "anvil-permission-revocation",
        expectedStoreRevision: null,
        next: activePermissionGrant(installed.account, permission.permissionId, installed),
      }),
    ).toMatchObject({ status: "committed" });
    await seed.close();

    const counters: {
      signs: number;
      sends: number;
      signedHash?: Hex;
      transactionHash?: Hex;
    } = { signs: 0, sends: 0 };
    let loseAcknowledgment = true;
    function coordinator(client: PublicClient) {
      const ownerAccount = privateKeyToAccount(ownerPrivateKey);
      const submitter = privateKeyToAccount(harness.submitterPrivateKey);
      const adapter = createLocalKernelPermissionUninstallAdapter({
        profile: "kernel-v3.3-permission-uninstall",
        key: { grantId: "anvil-permission-revocation", chainId },
        entryPoint: { version: "0.7", address: harness.entryPoint },
        kernel: {
          account: installed.account,
          rootValidator: harness.validator,
          owner: lower(ownerAccount.address),
        },
        permission: { signer: harness.multiChainSigner, operator: lower(operator.address) },
        gas: {
          callGasLimit: "400000",
          verificationGasLimit: "500000",
          preVerificationGas: "100000",
          maxFeePerGas: "2000000000",
          maxPriorityFeePerGas: "1000000000",
        },
        handleOpsGasLimit: "2500000",
        preparationReads: {
          async read(request: KernelPreparationReadRequest) {
            if (request.type === "chain_id") return client.getChainId();
            if (request.type === "code") {
              return lower((await client.getCode({ address: request.address })) ?? "0x");
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
            if (request.type === "kernel_ecdsa_owner") {
              return lower(
                await client.readContract({
                  address: request.validator,
                  abi: validatorAbi,
                  functionName: "ecdsaValidatorStorage",
                  args: [request.account],
                }),
              );
            }
            if (request.type === "kernel_validation_config") {
              const config = await client.readContract({
                address: request.account,
                abi: kernelAbi,
                functionName: "validationConfig",
                args: [request.validationId],
              });
              return { nonce: config.nonce.toString(10), hook: lower(config.hook) };
            }
            if (request.type === "kernel_permission_config") {
              const config = await client.readContract({
                address: request.account,
                abi: kernelAbi,
                functionName: "permissionConfig",
                args: [request.permissionId],
              });
              return {
                permissionFlag: lower(config.permissionFlag),
                signer: lower(config.signer),
                policyCount: config.policyData.length,
              };
            }
            if (request.type === "kernel_allowed_selector") {
              return client.readContract({
                address: request.account,
                abi: kernelAbi,
                functionName: "isAllowedSelector",
                args: [request.validationId, request.selector],
              });
            }
            if (request.type === "multi_chain_signer_owner") {
              return lower(
                await client.readContract({
                  address: request.signer,
                  abi: multiChainSignerAbi,
                  functionName: "signer",
                  args: [pad(request.permissionId, { dir: "right", size: 32 }), request.account],
                }),
              );
            }
            return (
              await client.readContract({
                address: request.entryPoint,
                abi: entryPoint07Abi,
                functionName: "getNonce",
                args: [request.account, 0n],
              })
            ).toString(10);
          },
          async close() {},
        },
        userOperationSigner: {
          address: lower(ownerAccount.address),
          async signDigest(request: { userOperationHash: Hex }) {
            counters.signs += 1;
            counters.signedHash = request.userOperationHash;
            return ownerAccount.sign({ hash: request.userOperationHash });
          },
          async close() {},
        },
        handleOpsSubmitter: {
          address: lower(submitter.address),
          async sendHandleOps(request: {
            chainId: number;
            entryPoint: `0x${string}`;
            submitter: `0x${string}`;
            userOperationHash: Hex;
            calldata: Hex;
            gasLimit: string;
          }) {
            counters.sends += 1;
            const wallet = createWalletClient({
              account: submitter,
              transport: http(harness.url, { retryCount: 0 }),
            });
            const transactionHash = await wallet.sendTransaction({
              account: submitter,
              to: request.entryPoint,
              data: request.calldata,
              gas: BigInt(request.gasLimit),
              maxFeePerGas: 2_000_000_000n,
              maxPriorityFeePerGas: 1_000_000_000n,
              chain: null,
            });
            expect((await client.waitForTransactionReceipt({ hash: transactionHash })).status).toBe(
              "success",
            );
            counters.transactionHash = lower(transactionHash);
            if (loseAcknowledgment) {
              loseAcknowledgment = false;
              throw new Error("loopback acknowledgement lost");
            }
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
      expect(adapter.descriptor).toMatchObject({
        kind: "kernel-v3.3-permission-uninstall",
        grantId: "anvil-permission-revocation",
        chainId,
        entryPoint: harness.entryPoint,
        account: installed.account,
        permissionId: permission.permissionId,
        validationId: permission.validationId,
        signer: harness.multiChainSigner,
        operator: lower(operator.address),
      });
      return createKernelPermissionRevocationCoordinator({
        grantStore: createSqliteGrantStore(storePath),
        operationStore: createSqliteOperationStore(storePath),
        operationObserver: createOperationObserver(
          observerCapabilities(harness.entryPoint, client),
        ),
        uninstall: adapter,
        permissionObserver: createKernelPermissionRemovalObserver(permissionStateReads(client)),
      });
    }

    const firstRuntimeClient = createPublicClient({
      transport: http(harness.url, { retryCount: 0 }),
    });
    let revoker = coordinator(firstRuntimeClient);
    const first = await revoker.revoke({
      revocationStartedAt: 40,
      chainRevocationStartedAt: 41,
      preparedAt: 42,
      attemptedAt: 43,
      submittedAt: 44,
      operationObservedAt: 45,
      permissionObservedAt: 46,
      timeoutMs: 60_000,
    });
    expect(first).toMatchObject({
      status: "submission_uncertain",
      reason: "send_ambiguous",
      grant: { value: { state: "revoking", materializations: [{ state: "revoking" }] } },
      operation: { value: { state: "submission_attempted" } },
    });
    if (first.status !== "submission_uncertain") throw new Error("expected uncertain submission");
    const firstIdentity = first.operation.value.identity;
    await revoker.close();
    await harness.publicClient.request({
      method: "anvil_mine" as "eth_chainId",
      params: ["0x80"] as never,
    });

    const recoveryClient = createPublicClient({ transport: http(harness.url, { retryCount: 0 }) });
    revoker = coordinator(recoveryClient);
    const recovered = await revoker.revoke({
      revocationStartedAt: 50,
      chainRevocationStartedAt: 51,
      preparedAt: 52,
      attemptedAt: 53,
      submittedAt: 54,
      operationObservedAt: 55,
      permissionObservedAt: 56,
      timeoutMs: 60_000,
    });
    expect(recovered).toMatchObject({
      status: "revoked",
      removal: {
        kind: "permission_absent",
        chainId,
        account: installed.account,
        permissionId: permission.permissionId,
      },
      grant: { value: { state: "revoking", materializations: [{ state: "revoked" }] } },
      operation: {
        value: {
          state: "finalized",
          identity: { kind: "revocation", chainId, account: installed.account },
          inclusion: { outcome: "success" },
        },
      },
    });
    if (recovered.status !== "revoked") throw new Error("expected revoked result");
    expect(recovered.operation.value.identity).toEqual(firstIdentity);
    expect(recovered.operation.value.identity).toEqual({
      kind: "revocation",
      grantId: "anvil-permission-revocation",
      chainId,
      entryPoint: harness.entryPoint,
      account: installed.account,
      nonce: "0",
      userOperationHash: counters.signedHash,
    });
    if (!counters.transactionHash) throw new Error("missing submitted transaction identity");
    const transactionReceipt = await recoveryClient.getTransactionReceipt({
      hash: counters.transactionHash,
    });
    const finalizedBlock = await recoveryClient.getBlock({ blockTag: "finalized" });
    expect(recovered.operation.value).toMatchObject({
      inclusion: {
        transactionHash: counters.transactionHash,
        blockNumber: transactionReceipt.blockNumber.toString(10),
        blockHash: lower(transactionReceipt.blockHash),
        outcome: "success",
        observedAt: 55,
      },
      finality: {
        blockNumber: finalizedBlock.number.toString(10),
        blockHash: lower(finalizedBlock.hash ?? "0x"),
        observedAt: 55,
      },
    });
    expect(counters).toMatchObject({ signs: 1, sends: 1 });
    await revoker.close();
  }, 60_000);
});
