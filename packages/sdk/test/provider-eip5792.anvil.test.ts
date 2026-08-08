/**
 * Public EIP-5792 provider evidence over one real local EntryPoint transaction.
 *
 * The local submission port behaves as the smallest bundler: it accepts the
 * exact prepared target UserOperation and places it between two independently
 * signed Kernel UserOperations in one handleOps transaction. Observation reads
 * only Anvil receipts and blocks. This proves the provider receipt window
 * without introducing a shared RPC, a fake receipt, or a second execution path.
 *
 * @author taek <leekt216@gmail.com>
 */
import { decodeEventLog, encodeFunctionData, parseEther, toEventSelector } from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import type {
  OaathChainCapability,
  OaathQuoteRequest,
  OaathSubmissionRequest,
  OperationObserverBlockEvidence,
  OperationObserverLogEvidence,
  OperationObserverReadRequest,
  OperationObserverTransactionEvidence,
  OperationObserverTransactionReceiptEvidence,
  OperationObserverUserOperationReceiptEvidence,
} from "../src/advanced.js";
import {
  createKernelRuntime,
  ecdsaKey,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  kernelV4Deployment,
  ownerOperator,
  type PreparedUserOperation,
} from "../src/kernel.js";
import { oaathProvider } from "../src/viem.js";
import {
  createHarness,
  deployKernelStack,
  type KernelHarness,
  startAnvil,
} from "./support/anvil.js";
import {
  type ChainFixture,
  createClock,
  createRealm,
  permissionInput,
  type SecondsClock,
} from "./support/browser.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
const CHAIN_ID = 421_614;
const CALL_SELECTOR = "0x12345678" as const;
const USER_OPERATION_EVENT = toEventSelector(
  "UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)",
);
const BEFORE_EXECUTION = toEventSelector("BeforeExecution()");
const UPGRADED = toEventSelector("Upgraded(address)");
const PERMISSION_INSTALLED = toEventSelector("PermissionInstalled(bytes4,uint32)");
const MODULE_INSTALLED = toEventSelector("ModuleInstalled(uint256,address)");
const REVERTING_CONTRACT_DEPLOYMENT = "0x6005600c60003960056000f360006000fd" as const;
const UINT64_MASK = (1n << 64n) - 1n;

const gas = Object.freeze({
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
});

interface SignedOperation {
  readonly prepared: Readonly<PreparedUserOperation>;
  readonly signature: `0x${string}`;
}

interface LiveProviderChain {
  readonly chain: ChainFixture;
  readonly harness: KernelHarness;
  readonly validator: `0x${string}`;
  readonly targetHashes: readonly `0x${string}`[];
  readonly opened: () => number;
  readonly submitted: () => number;
  readonly receiptForTarget: (
    index: number,
  ) => Promise<Readonly<OperationObserverTransactionReceiptEvidence>>;
  readonly stop: () => void;
}

interface TerminalStatus {
  readonly version: "2.0.0";
  readonly id: string;
  readonly chainId: `0x${string}`;
  readonly atomic: true;
  readonly status: 200 | 500;
  readonly receipts: readonly [
    Readonly<{
      readonly logs: readonly Readonly<{
        readonly address: `0x${string}`;
        readonly topics: readonly `0x${string}`[];
        readonly data: `0x${string}`;
      }>[];
      readonly status: "0x0" | "0x1";
      readonly transactionHash: `0x${string}`;
    }>,
  ];
}

function lower(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function quantity(value: bigint | number): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
}

function required<Value>(value: Value | null | undefined, label: string): Value {
  if (value === null || value === undefined) throw new Error(`${label} is unavailable`);
  return value;
}

function logEvidence(
  log: Awaited<ReturnType<KernelHarness["client"]["getTransactionReceipt"]>>["logs"][number],
): Readonly<OperationObserverLogEvidence> {
  return Object.freeze({
    address: lower(log.address),
    blockNumber: quantity(required(log.blockNumber, "log block number")),
    blockHash: lower(required(log.blockHash, "log block hash")),
    transactionHash: lower(required(log.transactionHash, "log transaction hash")),
    transactionIndex: quantity(required(log.transactionIndex, "log transaction index")),
    logIndex: quantity(required(log.logIndex, "log index")),
    removed: log.removed,
    topics: Object.freeze(log.topics.map(lower)),
    data: lower(log.data),
  });
}

function transactionReceiptEvidence(
  receipt: Awaited<ReturnType<KernelHarness["client"]["getTransactionReceipt"]>>,
): Readonly<OperationObserverTransactionReceiptEvidence> {
  return Object.freeze({
    transactionHash: lower(receipt.transactionHash),
    blockNumber: quantity(receipt.blockNumber),
    blockHash: lower(receipt.blockHash),
    transactionIndex: quantity(receipt.transactionIndex),
    status: receipt.status === "success" ? ("0x1" as const) : ("0x0" as const),
    gasUsed: quantity(receipt.gasUsed),
    logs: Object.freeze(receipt.logs.map(logEvidence)),
  });
}

function blockEvidence(
  block: Awaited<ReturnType<KernelHarness["client"]["getBlock"]>>,
): Readonly<OperationObserverBlockEvidence> {
  return Object.freeze({
    number: quantity(required(block.number, "block number")),
    hash: lower(required(block.hash, "block hash")),
    parentHash: lower(block.parentHash),
    transactions: Object.freeze(
      block.transactions.map((transaction) =>
        lower(typeof transaction === "string" ? transaction : transaction.hash),
      ),
    ),
  });
}

function packed(operation: Readonly<SignedOperation>) {
  const userOperation = operation.prepared.userOperation;
  if (userOperation.paymaster !== null) {
    throw new Error("the provider Anvil proof does not select a paymaster");
  }
  return toPackedUserOperation({
    sender: userOperation.sender,
    nonce: BigInt(userOperation.nonce),
    callData: userOperation.callData,
    callGasLimit: BigInt(userOperation.callGasLimit),
    verificationGasLimit: BigInt(userOperation.verificationGasLimit),
    preVerificationGas: BigInt(userOperation.preVerificationGas),
    maxFeePerGas: BigInt(userOperation.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(userOperation.maxPriorityFeePerGas),
    ...(userOperation.factory
      ? { factory: userOperation.factory.address, factoryData: userOperation.factory.data }
      : {}),
    signature: operation.signature,
  });
}

async function unrelatedOperation(
  harness: KernelHarness,
  validator: `0x${string}`,
  grantId: string,
  upgrade: boolean,
): Promise<Readonly<SignedOperation>> {
  const account = privateKeyToAccount(generatePrivateKey());
  const runtime = createKernelRuntime({
    deployment: kernelV4Deployment(CHAIN_ID),
    operator: ownerOperator({ key: ecdsaKey({ account, validator }) }),
    reads: harness.reads,
  });
  const descriptor = await runtime.bindAccount({
    accountIndex: "0",
    initialPackages: runtime.packages,
  });
  await harness.fund(descriptor.account, parseEther("1"));
  const calls = upgrade
    ? [
        {
          target: descriptor.account,
          value: "0",
          data: encodeFunctionData({
            abi: [
              {
                type: "function",
                name: "upgradeToAndCall",
                stateMutability: "payable",
                inputs: [{ type: "address" }, { type: "bytes" }],
                outputs: [],
              },
            ],
            functionName: "upgradeToAndCall",
            args: [KERNEL_V4_UUPS_IMPLEMENTATION_V07, "0x"],
          }),
        },
      ]
    : [
        {
          target: lower(privateKeyToAccount(generatePrivateKey()).address),
          value: "1",
          data: "0x" as const,
        },
      ];
  const prepared = runtime.prepareOperation({
    kind: "execution",
    grantId,
    account: descriptor,
    nonceKey: "0",
    sequence: "0",
    calls,
    gas,
  });
  return Object.freeze({ prepared, signature: await runtime.signOperation(prepared) });
}

async function createLiveProviderChain(clock: SecondsClock): Promise<Readonly<LiveProviderChain>> {
  // One slot per epoch makes Anvil's finalized tag advance behind inclusion,
  // so this proof observes actual finality instead of treating latest as final.
  const local = await startAnvil(CHAIN_ID, "prague", 1);
  try {
    const harness = await createHarness(local);
    await deployKernelStack(harness);
    await harness.deployModule(harness.fixture.callPolicy);
    await harness.deployModule(harness.fixture.validityPolicy);
    await harness.deployModule(harness.fixture.rateLimitPolicy);
    await harness.deployModule(harness.fixture.ecdsaSigner);
    const validator = await harness.deployValidatorCreate2();
    const unrelatedBefore = await unrelatedOperation(
      harness,
      validator,
      "provider-noise-before",
      true,
    );
    const unrelatedAfter = await unrelatedOperation(
      harness,
      validator,
      "provider-noise-after",
      false,
    );
    const targetTransactions = new Map<`0x${string}`, `0x${string}`>();
    const targetHashes: `0x${string}`[] = [];
    const funded = new Set<string>();
    let opened = 0;
    let submitted = 0;
    let quotes = 0;

    async function targetReceipt(
      userOperationHash: `0x${string}`,
    ): Promise<Awaited<ReturnType<KernelHarness["client"]["getTransactionReceipt"]>> | null> {
      const transactionHash = targetTransactions.get(userOperationHash);
      if (transactionHash === undefined) return null;
      return harness.client.getTransactionReceipt({ hash: transactionHash });
    }

    async function userOperationReceipt(
      userOperationHash: `0x${string}`,
    ): Promise<Readonly<OperationObserverUserOperationReceiptEvidence> | null> {
      const receipt = await targetReceipt(userOperationHash);
      if (receipt === null) return null;
      const raw = receipt.logs.find(
        (log) =>
          lower(log.address) === KERNEL_V4_ENTRY_POINT_V07 &&
          lower(log.topics[0] ?? "") === USER_OPERATION_EVENT &&
          lower(log.topics[1] ?? "") === userOperationHash,
      );
      if (raw === undefined) return null;
      const decoded = decodeEventLog({ abi: entryPoint07Abi, data: raw.data, topics: raw.topics });
      if (decoded.eventName !== "UserOperationEvent") return null;
      const args = decoded.args as Readonly<{
        sender: `0x${string}`;
        paymaster: `0x${string}`;
        nonce: bigint;
        success: boolean;
        actualGasCost: bigint;
        actualGasUsed: bigint;
      }>;
      return Object.freeze({
        userOperationHash,
        entryPoint: KERNEL_V4_ENTRY_POINT_V07,
        sender: lower(args.sender),
        nonce: quantity(args.nonce),
        paymaster: lower(args.paymaster),
        actualGasCost: quantity(args.actualGasCost),
        actualGasUsed: quantity(args.actualGasUsed),
        success: args.success,
        transactionHash: lower(receipt.transactionHash),
        blockNumber: quantity(receipt.blockNumber),
        blockHash: lower(receipt.blockHash),
      });
    }

    async function observe(request: OperationObserverReadRequest): Promise<unknown> {
      if (request.type === "chain_id") return CHAIN_ID;
      if (request.type === "user_operation_receipt") {
        return userOperationReceipt(request.userOperationHash);
      }
      if (request.type === "transaction_receipt") {
        return transactionReceiptEvidence(
          await harness.client.getTransactionReceipt({ hash: request.transactionHash }),
        );
      }
      if (request.type === "transaction") {
        const transaction = await harness.client.getTransaction({ hash: request.transactionHash });
        return Object.freeze({
          hash: lower(transaction.hash),
          to: transaction.to === null ? null : lower(transaction.to),
          blockNumber: quantity(required(transaction.blockNumber, "transaction block number")),
          blockHash: lower(required(transaction.blockHash, "transaction block hash")),
          transactionIndex: quantity(required(transaction.transactionIndex, "transaction index")),
        } satisfies OperationObserverTransactionEvidence);
      }
      if (request.type === "finalized_block") {
        return blockEvidence(await harness.client.getBlock({ blockTag: "finalized" }));
      }
      if (request.type === "canonical_block") {
        return blockEvidence(
          await harness.client.getBlock({ blockNumber: BigInt(request.blockNumber) }),
        );
      }
      if (request.type === "block_by_hash") {
        return blockEvidence(await harness.client.getBlock({ blockHash: request.blockHash }));
      }
      if (request.type === "replacement_candidate") return null;
      if (request.type === "entry_point_nonce") {
        const nonce = await harness.client.readContract({
          address: request.entryPoint,
          abi: entryPoint07Abi,
          functionName: "getNonce",
          args: [request.account, BigInt(request.nonce) >> 64n],
          blockNumber: BigInt(request.blockNumber),
        });
        return quantity(nonce);
      }
      if (request.type === "kernel_permission_installed") {
        return harness.client.readContract({
          address: request.account,
          abi: [
            {
              type: "function",
              name: "isModuleInstalled",
              stateMutability: "view",
              inputs: [{ type: "uint256" }, { type: "address" }, { type: "bytes" }],
              outputs: [{ type: "bool" }],
            },
          ],
          functionName: "isModuleInstalled",
          args: [6n, request.signer, request.permissionId],
          blockNumber: BigInt(request.blockNumber),
        });
      }
      throw new Error("unsupported provider observation");
    }

    async function finalizedTargetCount(): Promise<{
      count: number;
      block: Readonly<OperationObserverBlockEvidence>;
    }> {
      const block = blockEvidence(await harness.client.getBlock({ blockTag: "finalized" }));
      const height = BigInt(block.number);
      let count = 0;
      for (const transactionHash of targetTransactions.values()) {
        const receipt = await harness.client.getTransactionReceipt({ hash: transactionHash });
        if (receipt.blockNumber <= height) count += 1;
      }
      return { count, block };
    }

    const capability: Readonly<OaathChainCapability> = Object.freeze({
      chainId: CHAIN_ID,
      reads: harness.reads,
      observation: Object.freeze({ read: observe, async close() {} }),
      bundler: Object.freeze({
        async probe(request: { readonly chainId: number; readonly entryPoint: `0x${string}` }) {
          return Object.freeze({
            accepting: true,
            chainId: request.chainId,
            supportedEntryPoints: Object.freeze([request.entryPoint]),
          });
        },
      }),
      submission: Object.freeze({
        async open(request: Readonly<OaathSubmissionRequest>) {
          if (request.route !== "bundler" || request.feePayer !== null) {
            throw new Error("the local batching port was not selected as the bundler route");
          }
          opened += 1;
          let sent = false;
          return Object.freeze({
            async send() {
              if (sent) throw new Error("one submission session may send only once");
              sent = true;
              submitted += 1;
              const target = Object.freeze({
                prepared: request.prepared,
                signature: request.signature,
              });
              const operations =
                submitted === 1 ? [unrelatedBefore, target, unrelatedAfter] : [target];
              const transactionHash = await harness.wallet.sendTransaction({
                account: harness.submitter,
                chain: null,
                to: KERNEL_V4_ENTRY_POINT_V07,
                data: encodeFunctionData({
                  abi: entryPoint07Abi,
                  functionName: "handleOps",
                  args: [operations.map(packed), harness.submitter.address],
                }),
                gas: 29_000_000n,
              });
              const receipt = await harness.client.waitForTransactionReceipt({
                hash: transactionHash,
              });
              if (receipt.status !== "success") {
                throw new Error("the containing handleOps transaction reverted");
              }
              const targetHash = request.prepared.userOperationHash;
              targetHashes.push(targetHash);
              targetTransactions.set(targetHash, lower(transactionHash));
              await harness.client.request({
                method: "anvil_mine" as "eth_chainId",
                params: ["0x3"] as never,
              });
              return Object.freeze({ userOperationHash: targetHash });
            },
            async close() {},
          });
        },
      }),
      async quote(request: Readonly<OaathQuoteRequest>) {
        quotes += 1;
        if (!funded.has(request.account)) {
          await harness.fund(request.account, parseEther("2"));
          funded.add(request.account);
        }
        const nonce = await harness.client.readContract({
          address: KERNEL_V4_ENTRY_POINT_V07,
          abi: entryPoint07Abi,
          functionName: "getNonce",
          args: [request.account, 0n],
        });
        if (nonce >> 64n !== 0n) throw new Error("the provider proof expected nonce key zero");
        return Object.freeze({
          nonceKey: "0",
          sequence: (nonce & UINT64_MASK).toString(10),
          gas,
        });
      },
      async usage(request: Readonly<{ grantId: string; chainId: number }>) {
        const finalized = await finalizedTargetCount();
        return Object.freeze({
          version: "oaath.grant-policy-usage/v1" as const,
          status: "complete" as const,
          grantId: request.grantId,
          chainId: request.chainId,
          finalizedOperationCount: finalized.count.toString(10),
          through: Object.freeze({
            blockNumber: BigInt(finalized.block.number).toString(10),
            blockHash: finalized.block.hash,
            observedAt: clock.now(),
          }),
        });
      },
      feePayer: null,
      paymasterService: null,
      staticPaymasterConfigurationHash: null,
    });

    const fixtureSends: Readonly<PreparedUserOperation>[] = [];
    const fixtureSignatures: string[] = [];
    const fixture: ChainFixture = Object.freeze({
      capability,
      sends: fixtureSends,
      signatures: fixtureSignatures,
      get quotes() {
        return quotes;
      },
    });
    return Object.freeze({
      chain: fixture,
      harness,
      validator,
      targetHashes,
      opened: () => opened,
      submitted: () => submitted,
      async receiptForTarget(index: number) {
        const hash = targetHashes[index];
        if (hash === undefined) throw new Error("target UserOperation is unavailable");
        const receipt = await targetReceipt(hash);
        if (receipt === null) throw new Error("target transaction receipt is unavailable");
        return transactionReceiptEvidence(receipt);
      },
      stop: local.stop,
    });
  } catch (error) {
    local.stop();
    throw error;
  }
}

function walletBundle(
  account: `0x${string}`,
  id: string,
  calls: readonly Readonly<Record<string, unknown>>[],
) {
  return Object.freeze({
    version: "2.0.0",
    id,
    from: account,
    chainId: `0x${CHAIN_ID.toString(16)}`,
    atomicRequired: true,
    calls: Object.freeze([...calls]),
  });
}

function publicLog(log: Readonly<OperationObserverLogEvidence>) {
  return Object.freeze({ address: log.address, topics: log.topics, data: log.data });
}

(requireAnvil ? describe : describe.skip)("EIP-5792 provider local Anvil evidence", () => {
  it("proves atomic success/full revert, exact log filtering, and observation-only status", async () => {
    const clock = createClock(Math.floor(Date.now() / 1_000));
    let live: Readonly<LiveProviderChain> | undefined;
    let closeRealm: (() => Promise<void>) | undefined;
    try {
      live = await createLiveProviderChain(clock);
      const successA = lower(privateKeyToAccount(generatePrivateKey()).address);
      const successB = lower(privateKeyToAccount(generatePrivateKey()).address);
      const rollbackTarget = lower(privateKeyToAccount(generatePrivateKey()).address);
      const deploymentHash = await live.harness.wallet.deployContract({
        account: live.harness.submitter,
        chain: null,
        abi: [],
        bytecode: REVERTING_CONTRACT_DEPLOYMENT,
        gas: 500_000n,
      });
      const deploymentReceipt = await live.harness.client.waitForTransactionReceipt({
        hash: deploymentHash,
      });
      const revertingTarget = lower(
        required(deploymentReceipt.contractAddress, "reverting target address"),
      );
      const realm = createRealm({ clock, chain: live.chain, validator: live.validator });
      closeRealm = async () => realm.oaath.close();
      const connection = await realm.oaath.connect();
      const grant = await connection.requestPermission(
        permissionInput({
          permissions: [
            {
              calls: [
                { target: successA, selectors: [CALL_SELECTOR], valueLimit: "1" },
                { target: successB, selectors: [CALL_SELECTOR], valueLimit: "2" },
                { target: rollbackTarget, selectors: [CALL_SELECTOR], valueLimit: "1" },
                { target: revertingTarget, selectors: [CALL_SELECTOR], valueLimit: "0" },
              ].sort((left, right) => left.target.localeCompare(right.target)),
            },
          ],
        }),
      );
      const provider = oaathProvider({ grant, chain: CHAIN_ID });
      const account = await grant.account(CHAIN_ID);

      const successResult = (await provider.request({
        method: "wallet_sendCalls",
        params: [
          walletBundle(account, "provider-anvil-success", [
            { to: successA, value: "0x1", data: CALL_SELECTOR },
            { to: successB, value: "0x2", data: CALL_SELECTOR },
          ]),
        ],
      })) as Readonly<{ id: string }>;
      expect(successResult).toEqual({ id: "provider-anvil-success" });
      expect(await live.harness.client.getBalance({ address: successA })).toBe(1n);
      expect(await live.harness.client.getBalance({ address: successB })).toBe(2n);
      expect(live.opened()).toBe(1);
      expect(live.submitted()).toBe(1);

      const success = (await provider.request({
        method: "wallet_getCallsStatus",
        params: [successResult.id],
      })) as Readonly<TerminalStatus>;
      expect(success).toMatchObject({
        version: "2.0.0",
        id: successResult.id,
        chainId: `0x${CHAIN_ID.toString(16)}`,
        atomic: true,
        status: 200,
        receipts: [{ status: "0x1" }],
      });

      const successHash = required(live.targetHashes[0], "success UserOperation hash");
      const containing = await live.receiptForTarget(0);
      const eventIndices = containing.logs.flatMap((log, index) =>
        log.address === KERNEL_V4_ENTRY_POINT_V07 && log.topics[0] === USER_OPERATION_EVENT
          ? [index]
          : [],
      );
      expect(eventIndices).toHaveLength(3);
      const targetIndex = containing.logs.findIndex(
        (log) => log.topics[0] === USER_OPERATION_EVENT && log.topics[1] === successHash,
      );
      expect(targetIndex).toBe(eventIndices[1]);
      const precedingIndex = required(eventIndices[0], "preceding UserOperation event");
      const followingIndex = required(eventIndices[2], "following UserOperation event");
      expect(precedingIndex).toBeLessThan(targetIndex);
      expect(followingIndex).toBeGreaterThan(targetIndex);
      expect(success.receipts[0].transactionHash).toBe(containing.transactionHash);
      expect(success.receipts[0].logs).toEqual(
        containing.logs.slice(precedingIndex + 1, targetIndex + 1).map(publicLog),
      );

      const beforeExecutionIndex = containing.logs.findIndex(
        (log) => log.address === KERNEL_V4_ENTRY_POINT_V07 && log.topics[0] === BEFORE_EXECUTION,
      );
      expect(beforeExecutionIndex).toBeGreaterThanOrEqual(0);
      expect(beforeExecutionIndex).toBeLessThan(precedingIndex);
      const unrelatedActivity = containing.logs
        .slice(0, precedingIndex + 1)
        .map((log) => log.topics[0]);
      expect(unrelatedActivity).toContain(UPGRADED);
      expect(
        unrelatedActivity.some(
          (topic) => topic === PERMISSION_INSTALLED || topic === MODULE_INSTALLED,
        ),
      ).toBe(true);
      expect(
        success.receipts[0].logs.some(
          (log) =>
            log.topics[0] === UPGRADED ||
            log.topics[0] === PERMISSION_INSTALLED ||
            log.topics[0] === MODULE_INSTALLED,
        ),
      ).toBe(false);

      const beforeRollback = await live.harness.client.getBalance({ address: rollbackTarget });
      const revertResult = (await provider.request({
        method: "wallet_sendCalls",
        params: [
          walletBundle(account, "provider-anvil-revert", [
            { to: rollbackTarget, value: "0x1", data: CALL_SELECTOR },
            { to: revertingTarget, data: CALL_SELECTOR },
          ]),
        ],
      })) as Readonly<{ id: string }>;
      const reverted = (await provider.request({
        method: "wallet_getCallsStatus",
        params: [revertResult.id],
      })) as Readonly<TerminalStatus>;
      expect(reverted).toMatchObject({
        id: revertResult.id,
        atomic: true,
        status: 500,
        receipts: [{ status: "0x0" }],
      });
      expect(await live.harness.client.getBalance({ address: rollbackTarget })).toBe(
        beforeRollback,
      );
      expect(live.opened()).toBe(2);
      expect(live.submitted()).toBe(2);

      const beforeStatusReads = Object.freeze({
        opened: live.opened(),
        submitted: live.submitted(),
        targets: live.targetHashes.length,
      });
      await expect(
        provider.request({ method: "wallet_getCallsStatus", params: [successResult.id] }),
      ).resolves.toMatchObject({ status: 200 });
      await expect(
        provider.request({ method: "wallet_getCallsStatus", params: [revertResult.id] }),
      ).resolves.toMatchObject({ status: 500 });
      expect({
        opened: live.opened(),
        submitted: live.submitted(),
        targets: live.targetHashes.length,
      }).toEqual(beforeStatusReads);

      await connection.close();
    } finally {
      await closeRealm?.().catch(() => undefined);
      live?.stop();
    }
  }, 90_000);
});
