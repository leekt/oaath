import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  advanceOperation,
  createOperation,
  type Operation,
  type OperationIdentity,
} from "@oaath/protocol";
import { createSqliteOperationStore } from "@oaath/testing";
import { afterEach, describe, expect, it } from "vitest";
import {
  createOperationObserver,
  OaathOperationObserverError,
  type OperationObserverBlockEvidence,
  type OperationObserverCapabilities,
  type OperationObserverReadRequest,
  type OperationObserverTransactionEvidence,
  type OperationObserverTransactionReceiptEvidence,
  type OperationObserverUserOperationReceiptEvidence,
} from "../src/advanced.js";

const identity: OperationIdentity = {
  kind: "execution",
  grantId: "observed-grant",
  chainId: 31_337,
  entryPoint: `0x${"11".repeat(20)}`,
  account: `0x${"22".repeat(20)}`,
  nonce: "7",
  userOperationHash: `0x${"33".repeat(32)}`,
};
const targetTransactionHash = `0x${"44".repeat(32)}` as const;
const targetBlockHash = `0x${"55".repeat(32)}` as const;
const finalityBlockHash = `0x${"66".repeat(32)}` as const;
const replacementHash = `0x${"77".repeat(32)}` as const;
const replacementTransactionHash = `0x${"88".repeat(32)}` as const;
const replacementBlockHash = `0x${"99".repeat(32)}` as const;
const parentHash = `0x${"aa".repeat(32)}` as const;
const eventSelector = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f" as const;
const zeroAddress = `0x${"00".repeat(20)}` as const;
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function quantity(value: bigint | number): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
}

function word(value: bigint | number): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

function submitted(): Operation {
  const prepared = createOperation({ identity, preparedAt: 10 });
  const attempted = advanceOperation(prepared, {
    type: "mark_submission_attempted",
    identity,
    attemptedAt: 11,
  });
  return advanceOperation(attempted, {
    type: "mark_submitted",
    identity,
    returnedUserOperationHash: identity.userOperationHash,
    submittedAt: 12,
  });
}

interface Occurrence {
  receipt: OperationObserverUserOperationReceiptEvidence;
  transactionReceipt: OperationObserverTransactionReceiptEvidence;
  transaction: OperationObserverTransactionEvidence;
  block: OperationObserverBlockEvidence;
}

function occurrence(input: {
  hash: `0x${string}`;
  transactionHash: `0x${string}`;
  blockNumber: number;
  blockHash: `0x${string}`;
  success: boolean;
}): Occurrence {
  const blockNumber = quantity(input.blockNumber);
  const transactionIndex = "0x0" as const;
  const topics = [
    eventSelector,
    input.hash,
    `0x${"0".repeat(24)}${identity.account.slice(2)}` as const,
    `0x${"0".repeat(24)}${zeroAddress.slice(2)}` as const,
  ];
  const log = {
    address: identity.entryPoint,
    blockNumber,
    blockHash: input.blockHash,
    transactionHash: input.transactionHash,
    transactionIndex,
    logIndex: "0x0" as const,
    removed: false,
    topics,
    data: `0x${word(7)}${word(input.success ? 1 : 0)}${word(9)}${word(10)}` as const,
  };
  return {
    receipt: {
      userOperationHash: input.hash,
      entryPoint: identity.entryPoint,
      sender: identity.account,
      nonce: "0x7",
      paymaster: zeroAddress,
      actualGasCost: "0x9",
      actualGasUsed: "0xa",
      success: input.success,
      transactionHash: input.transactionHash,
      blockNumber,
      blockHash: input.blockHash,
    },
    transactionReceipt: {
      transactionHash: input.transactionHash,
      blockNumber,
      blockHash: input.blockHash,
      transactionIndex,
      status: "0x1",
      logs: [log],
    },
    transaction: {
      hash: input.transactionHash,
      to: identity.entryPoint,
      blockNumber,
      blockHash: input.blockHash,
      transactionIndex,
    },
    block: {
      number: blockNumber,
      hash: input.blockHash,
      parentHash,
      transactions: [input.transactionHash],
    },
  };
}

const target = occurrence({
  hash: identity.userOperationHash,
  transactionHash: targetTransactionHash,
  blockNumber: 20,
  blockHash: targetBlockHash,
  success: true,
});
const replacement = occurrence({
  hash: replacementHash,
  transactionHash: replacementTransactionHash,
  blockNumber: 21,
  blockHash: replacementBlockHash,
  success: false,
});
function finalityChain(
  inclusion: Occurrence,
  hashSeed: number,
): {
  finalized: OperationObserverBlockEvidence;
  byHash: ReadonlyMap<string, OperationObserverBlockEvidence>;
} {
  const byHash = new Map<string, OperationObserverBlockEvidence>();
  byHash.set(inclusion.block.hash, inclusion.block);
  let previous = inclusion.block;
  for (
    let blockNumber = Number(BigInt(inclusion.block.number)) + 1;
    blockNumber <= 30;
    blockNumber += 1
  ) {
    const block: OperationObserverBlockEvidence = {
      number: quantity(blockNumber),
      hash:
        blockNumber === 30
          ? finalityBlockHash
          : (`0x${(hashSeed + blockNumber).toString(16).padStart(64, "0")}` as const),
      parentHash: previous.hash,
      transactions: [],
    };
    byHash.set(block.hash, block);
    previous = block;
  }
  return { finalized: previous, byHash };
}

const targetFinality = finalityChain(target, 1_000);
const replacementFinality = finalityChain(replacement, 2_000);
const finalizedBlock = targetFinality.finalized;

type FixtureOptions = {
  targetReceipt?: unknown;
  replacementCandidate?: unknown;
  replacementReceipt?: unknown;
  finality?: unknown;
  mutate?: (request: OperationObserverReadRequest, value: unknown) => unknown;
};

function fixture(options: FixtureOptions = {}): {
  capabilities: OperationObserverCapabilities;
  requests: OperationObserverReadRequest[];
  closeCalls: () => number;
} {
  const requests: OperationObserverReadRequest[] = [];
  let closes = 0;
  const targetReceipt =
    options.targetReceipt === undefined ? target.receipt : options.targetReceipt;
  const replacementCandidate = options.replacementCandidate ?? null;
  const replacementReceipt =
    options.replacementReceipt === undefined ? replacement.receipt : options.replacementReceipt;
  const selectedFinality = replacementCandidate === null ? targetFinality : replacementFinality;
  const finality = options.finality === undefined ? selectedFinality.finalized : options.finality;

  function response(request: OperationObserverReadRequest): unknown {
    if (request.type === "chain_id") return identity.chainId;
    if (request.type === "replacement_candidate") return replacementCandidate;
    if (request.type === "user_operation_receipt") {
      return request.userOperationHash === identity.userOperationHash
        ? targetReceipt
        : replacementReceipt;
    }
    const selected =
      "transactionHash" in request && request.transactionHash === replacementTransactionHash
        ? replacement
        : target;
    if (request.type === "transaction_receipt") return selected.transactionReceipt;
    if (request.type === "transaction") return selected.transaction;
    if (request.type === "finalized_block") return finality;
    if (request.type === "block_by_hash") return selectedFinality.byHash.get(request.blockHash);
    if (request.type === "canonical_block") {
      if (request.blockNumber === "30") return selectedFinality.finalized;
      return request.blockNumber === "21" ? replacement.block : target.block;
    }
    throw new Error("unsupported request");
  }

  return {
    capabilities: {
      async read(request) {
        requests.push(request);
        const value = response(request);
        return options.mutate ? options.mutate(request, value) : value;
      },
      async close() {
        closes += 1;
      },
    },
    requests,
    closeCalls: () => closes,
  };
}

function expectObserverError(
  action: () => unknown,
  code: OaathOperationObserverError["code"],
): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathOperationObserverError);
    expect((error as OaathOperationObserverError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

describe("OperationObserver", () => {
  it.each([
    [true, "success"],
    [false, "reverted"],
  ] as const)(
    "verifies canonical finalized inclusion with event success=%s",
    async (success, outcome) => {
      const occurrenceValue = occurrence({
        hash: identity.userOperationHash,
        transactionHash: targetTransactionHash,
        blockNumber: 20,
        blockHash: targetBlockHash,
        success,
      });
      const adapter = fixture({
        targetReceipt: occurrenceValue.receipt,
        mutate(request, value) {
          if (request.type === "transaction_receipt") return occurrenceValue.transactionReceipt;
          return value;
        },
      });
      const observer = createOperationObserver(adapter.capabilities);

      const result = await observer.observeOperation({
        operation: submitted(),
        observedAt: 13,
        timeoutMs: 1_000,
      });

      expect(result).toMatchObject({
        status: "finalized",
        operation: {
          state: "finalized",
          inclusion: { outcome, transactionHash: targetTransactionHash },
          finality: { blockNumber: "30", blockHash: finalityBlockHash },
        },
      });
      expect(adapter.requests.every((request) => request.chainId === identity.chainId)).toBe(true);
      expect(
        adapter.requests
          .map((request) => request.type)
          .every((type) =>
            [
              "chain_id",
              "user_operation_receipt",
              "transaction_receipt",
              "transaction",
              "canonical_block",
              "block_by_hash",
              "finalized_block",
            ].includes(type),
          ),
      ).toBe(true);
    },
  );

  it("selects the exact target event from a multi-operation bundle", async () => {
    const other = occurrence({
      hash: `0x${"ab".repeat(32)}`,
      transactionHash: targetTransactionHash,
      blockNumber: 20,
      blockHash: targetBlockHash,
      success: true,
    });
    const adapter = fixture({
      mutate(request, value) {
        if (request.type !== "transaction_receipt") return value;
        return {
          ...target.transactionReceipt,
          logs: [other.transactionReceipt.logs[0], target.transactionReceipt.logs[0]],
        };
      },
    });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({ status: "finalized", operation: { state: "finalized" } });
  });

  it("retains verified inclusion when finality cannot be proven", async () => {
    const adapter = fixture({ finality: null });
    const observer = createOperationObserver(adapter.capabilities);
    const result = await observer.observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({
      status: "unreadable",
      reason: "finality_unproven",
      operation: {
        state: "included",
        inclusion: { transactionHash: targetTransactionHash },
        observation: { status: "unreadable", reason: "finality_unproven" },
      },
    });
  });

  it("rejects a finalized child whose parent is not the inclusion block", async () => {
    const adapter = fixture({
      finality: {
        number: "0x15",
        hash: finalityBlockHash,
        parentHash,
        transactions: [],
      },
      mutate(request, value) {
        return request.type === "block_by_hash" ? target.block : value;
      },
    });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({
      status: "unreadable",
      reason: "finality_unproven",
      operation: { state: "included" },
    });
  });

  it("keeps missing receipts pending and never infers a drop", async () => {
    const adapter = fixture({ targetReceipt: null });
    const observer = createOperationObserver(adapter.capabilities);
    const result = await observer.observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({
      status: "pending",
      reason: "receipt_missing",
      operation: { state: "submitted" },
    });
    expect(adapter.requests.map((request) => request.type)).toContain("replacement_candidate");
  });

  it("retains prior inclusion across a later missing receipt", async () => {
    const first = await createOperationObserver(
      fixture({ finality: null }).capabilities,
    ).observeOperation({ operation: submitted(), observedAt: 13, timeoutMs: 1_000 });
    const second = await createOperationObserver(
      fixture({ targetReceipt: null }).capabilities,
    ).observeOperation({ operation: first.operation, observedAt: 14, timeoutMs: 1_000 });
    expect(second).toMatchObject({
      status: "pending",
      operation: { state: "included", inclusion: { transactionHash: targetTransactionHash } },
    });
  });

  it("uses only a distinct fully verified finalized same-lane replacement to drop", async () => {
    const adapter = fixture({
      targetReceipt: null,
      replacementCandidate: { userOperationHash: replacementHash },
    });
    const observer = createOperationObserver(adapter.capabilities);
    const result = await observer.observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({
      status: "dropped",
      operation: {
        state: "dropped",
        drop: {
          replacement: {
            identity: {
              chainId: identity.chainId,
              entryPoint: identity.entryPoint,
              account: identity.account,
              nonce: identity.nonce,
              userOperationHash: replacementHash,
            },
            inclusion: { outcome: "reverted" },
          },
        },
      },
    });
  });

  it.each([
    ["entryPoint", `0x${"ab".repeat(20)}`],
    ["sender", `0x${"bc".repeat(20)}`],
    ["nonce", "0x8"],
    ["userOperationHash", `0x${"cd".repeat(32)}`],
    ["transactionHash", `0x${"de".repeat(32)}`],
    ["blockHash", `0x${"ef".repeat(32)}`],
  ] as const)("rejects %s substitution in receipt evidence", async (field, value) => {
    const adapter = fixture({ targetReceipt: { ...target.receipt, [field]: value } });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({ status: "unreadable", reason: "receipt_invalid" });
    expect(result.operation.state).toBe("submitted");
  });

  it("requires the bundle transaction to call the exact EntryPoint", async () => {
    const adapter = fixture({
      mutate(request, value) {
        return request.type === "transaction" ? { ...target.transaction, to: null } : value;
      },
    });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({ status: "unreadable", reason: "receipt_invalid" });
  });

  it.each([
    [
      "duplicate event",
      (receipt: OperationObserverTransactionReceiptEvidence) => ({
        ...receipt,
        logs: [receipt.logs[0], { ...receipt.logs[0], logIndex: "0x1" }],
      }),
    ],
    [
      "removed event",
      (receipt: OperationObserverTransactionReceiptEvidence) => ({
        ...receipt,
        logs: [{ ...receipt.logs[0], removed: true }],
      }),
    ],
    [
      "outer transaction revert",
      (receipt: OperationObserverTransactionReceiptEvidence) => ({ ...receipt, status: "0x0" }),
    ],
    [
      "trailing event data",
      (receipt: OperationObserverTransactionReceiptEvidence) => ({
        ...receipt,
        logs: [{ ...receipt.logs[0], data: `${receipt.logs[0]?.data}${word(0)}` }],
      }),
    ],
  ] as const)("rejects %s", async (_label, mutateReceipt) => {
    const adapter = fixture({
      mutate(request, value) {
        return request.type === "transaction_receipt"
          ? mutateReceipt(value as OperationObserverTransactionReceiptEvidence)
          : value;
      },
    });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({ status: "unreadable", reason: "receipt_invalid" });
  });

  it("reports canonicality failure without accepting provider-located evidence", async () => {
    const adapter = fixture({
      mutate(request, value) {
        return request.type === "canonical_block" && request.blockNumber === "20"
          ? { ...target.block, hash: `0x${"fe".repeat(32)}` }
          : value;
      },
    });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({ status: "unreadable", reason: "canonicality_unproven" });
    expect(result.operation.state).toBe("submitted");
  });

  it("rejects duplicate transaction membership in the canonical block", async () => {
    const adapter = fixture({
      mutate(request, value) {
        return request.type === "canonical_block" && request.blockNumber === "20"
          ? { ...target.block, transactions: [targetTransactionHash, targetTransactionHash] }
          : value;
      },
    });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({ status: "unreadable", reason: "canonicality_unproven" });
  });

  it("maps provider failure to a structured unreadable observation without diagnostics", async () => {
    const secret = "private-provider-error";
    const adapter = fixture({
      mutate(request, value) {
        if (request.type === "transaction") throw new Error(secret);
        return value;
      },
    });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({ status: "unreadable", reason: "provider_unavailable" });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("rejects a provider chain substitution before reading operation evidence", async () => {
    const adapter = fixture({
      mutate(request, value) {
        return request.type === "chain_id" ? identity.chainId + 1 : value;
      },
    });
    const result = await createOperationObserver(adapter.capabilities).observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(result).toMatchObject({ status: "unreadable", reason: "receipt_invalid" });
    expect(adapter.requests.map((request) => request.type)).toEqual(["chain_id"]);
  });

  it("rejects accessor-backed evidence without invoking the accessor", async () => {
    let reads = 0;
    const hostileReceipt = Object.defineProperty({ ...target.receipt }, "sender", {
      enumerable: true,
      get() {
        reads += 1;
        return identity.account;
      },
    });
    const result = await createOperationObserver(
      fixture({ targetReceipt: hostileReceipt }).capabilities,
    ).observeOperation({ operation: submitted(), observedAt: 13, timeoutMs: 1_000 });
    expect(result).toMatchObject({ status: "unreadable", reason: "receipt_invalid" });
    expect(reads).toBe(0);
  });

  it("owns a bounded timeout and performs no retry or submission", async () => {
    const requests: OperationObserverReadRequest[] = [];
    const observer = createOperationObserver({
      async read(request: OperationObserverReadRequest) {
        requests.push(request);
        if (request.type === "chain_id") return identity.chainId;
        return new Promise<never>(() => {});
      },
      async close() {},
    });
    const result = await observer.observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 5,
    });
    expect(result).toMatchObject({ status: "pending", reason: "timeout" });
    expect(requests.map((request) => request.type)).toEqual(["chain_id", "user_operation_receipt"]);
  });

  it("returns terminal operations without reads and exposes no send capability", async () => {
    const adapter = fixture();
    const observer = createOperationObserver(adapter.capabilities);
    const finalized = (
      await observer.observeOperation({
        operation: submitted(),
        observedAt: 13,
        timeoutMs: 1_000,
      })
    ).operation;
    const reads = adapter.requests.length;
    const again = await observer.observeOperation({
      operation: finalized,
      observedAt: 14,
      timeoutMs: 1_000,
    });
    expect(again.status).toBe("finalized");
    expect(adapter.requests).toHaveLength(reads);
    expect(Object.keys(observer).sort()).toEqual(["close", "observeOperation"]);
  });

  it("continues finality from a durable Operation after recreating store and observer", async () => {
    const directory = await mkdtemp(join(tmpdir(), "oaath-observer-reload-"));
    temporaryDirectories.push(directory);
    const filePath = join(directory, "store.db");
    const key = { grantId: identity.grantId, chainId: identity.chainId };
    const firstStore = createSqliteOperationStore(filePath);
    await firstStore.compareAndSwap({
      key,
      expectedStoreRevision: null,
      next: submitted(),
    });
    const firstObserver = createOperationObserver(fixture({ finality: null }).capabilities);
    const included = await firstObserver.observeOperation({
      operation: (await firstStore.get(key))?.value,
      observedAt: 13,
      timeoutMs: 1_000,
    });
    expect(included.operation.state).toBe("included");
    await firstStore.compareAndSwap({
      key,
      expectedStoreRevision: 0,
      next: included.operation,
    });
    await Promise.all([firstObserver.close(), firstStore.close()]);

    const restoredStore = createSqliteOperationStore(filePath);
    const restored = await restoredStore.get(key);
    const restoredObserver = createOperationObserver(fixture().capabilities);
    const finalized = await restoredObserver.observeOperation({
      operation: restored?.value,
      observedAt: 14,
      timeoutMs: 1_000,
    });
    expect(finalized).toMatchObject({
      status: "finalized",
      operation: { state: "finalized", inclusion: { transactionHash: targetTransactionHash } },
    });
    await Promise.all([restoredObserver.close(), restoredStore.close()]);
  });

  it("captures exact capabilities and rejects hostile or expanded surfaces", () => {
    expectObserverError(
      () =>
        createOperationObserver({
          read: async () => null,
          close: async () => {},
          supportedChains: [identity.chainId],
        }),
      "operation_observer_capability_invalid",
    );
    expectObserverError(
      () =>
        createOperationObserver(
          Object.defineProperty({ close: async () => {} }, "read", {
            enumerable: true,
            get() {
              throw new Error("secret provider material");
            },
          }),
        ),
      "operation_observer_capability_invalid",
    );
  });

  it("drains admitted observations before closing their read adapter", async () => {
    let releaseChain: (() => void) | undefined;
    let signalChainStarted: (() => void) | undefined;
    const chainStarted = new Promise<void>((resolve) => {
      signalChainStarted = resolve;
    });
    const chainGate = new Promise<void>((resolve) => {
      releaseChain = resolve;
    });
    let adapterClosed = false;
    let readsAfterClose = 0;
    const requests: OperationObserverReadRequest[] = [];
    const observer = createOperationObserver({
      async read(request: OperationObserverReadRequest) {
        if (adapterClosed) readsAfterClose += 1;
        requests.push(request);
        if (request.type === "chain_id") {
          signalChainStarted?.();
          await chainGate;
          return identity.chainId;
        }
        return null;
      },
      async close() {
        adapterClosed = true;
      },
    });
    const observation = observer.observeOperation({
      operation: submitted(),
      observedAt: 13,
      timeoutMs: 1_000,
    });
    await chainStarted;
    let closeFinished = false;
    const closing = observer.close().then(() => {
      closeFinished = true;
    });
    await Promise.resolve();
    expect(closeFinished).toBe(false);
    releaseChain?.();
    await expect(observation).resolves.toMatchObject({ status: "pending" });
    await closing;
    expect(requests.map((request) => request.type)).toEqual([
      "chain_id",
      "user_operation_receipt",
      "replacement_candidate",
      // The supersession upgrade attempts its anchor read; the unusable block
      // falls the observation back to weak pending instead of failing it.
      "finalized_block",
    ]);
    expect(readsAfterClose).toBe(0);
  });

  it("coalesces close, stays closed after success, and retries after close failure", async () => {
    let release: (() => void) | undefined;
    let attempts = 0;
    const observer = createOperationObserver({
      async read() {
        return null;
      },
      async close() {
        attempts += 1;
        if (attempts === 1) throw new Error("private close failure");
        await new Promise<void>((resolve) => {
          release = resolve;
        });
      },
    });
    await expect(observer.close()).rejects.toMatchObject({
      code: "operation_observer_close_failed",
    });
    const left = observer.close();
    const right = observer.close();
    await Promise.resolve();
    expect(attempts).toBe(2);
    release?.();
    await Promise.all([left, right]);
    expect(attempts).toBe(2);
    await observer.close();
    await expect(
      observer.observeOperation({ operation: submitted(), observedAt: 13, timeoutMs: 1_000 }),
    ).rejects.toMatchObject({ code: "operation_observer_closed" });
  });
});
