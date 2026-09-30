import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  advanceOperation,
  applyVerifiedOperationObservation,
  createOperation,
  type Operation,
  type OperationIdentity,
  type OperationSubmissionEvidence,
} from "@oaath/protocol";
import { createSqliteOperationStore } from "@oaath/testing";
import { afterEach, describe, expect, it } from "vitest";
import {
  createOperationObserver,
  createUserOperationObserver,
  OaathOperationObserverError,
  type OperationObserverBlockEvidence,
  type OperationObserverCapabilities,
  type OperationObserverLogEvidence,
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
  requestHash: null,
};
const targetTransactionHash = `0x${"44".repeat(32)}` as const;
const targetBlockHash = `0x${"55".repeat(32)}` as const;
const finalityBlockHash = `0x${"66".repeat(32)}` as const;
const replacementHash = `0x${"77".repeat(32)}` as const;
const replacementTransactionHash = `0x${"88".repeat(32)}` as const;
const replacementBlockHash = `0x${"99".repeat(32)}` as const;
const parentHash = `0x${"aa".repeat(32)}` as const;
const eventSelector = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f" as const;
const beforeExecutionSelector =
  "0xbb47ee3e183a558b1a2ff0874b079f3fc5478b7454eacf2bfc5af2ff5878f972" as const;
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

function submitted(submission: OperationSubmissionEvidence | null = null): Operation {
  const prepared = createOperation({ identity, preparedAt: 10 });
  const attempted = advanceOperation(prepared, {
    type: "mark_submission_attempted",
    identity,
    attemptedAt: 11,
  });
  return advanceOperation(attempted, {
    type: "mark_submitted",
    submission,
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
  boundary: OperationObserverLogEvidence;
  event: OperationObserverLogEvidence;
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
  const boundary = {
    address: identity.entryPoint,
    blockNumber,
    blockHash: input.blockHash,
    transactionHash: input.transactionHash,
    transactionIndex,
    logIndex: "0x0" as const,
    removed: false,
    topics: [beforeExecutionSelector],
    data: "0x" as const,
  };
  const event = {
    address: identity.entryPoint,
    blockNumber,
    blockHash: input.blockHash,
    transactionHash: input.transactionHash,
    transactionIndex,
    logIndex: "0x1" as const,
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
      gasUsed: "0x2a",
      logs: [boundary, event],
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
    boundary,
    event,
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
const finalizedBlock: OperationObserverBlockEvidence = {
  number: "0x1e",
  hash: finalityBlockHash,
  parentHash,
  transactions: [],
};

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
  const finality = options.finality === undefined ? finalizedBlock : options.finality;

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
    if (request.type === "canonical_block") {
      if (request.blockNumber === "30") return finalizedBlock;
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
  it("uses the direct transaction hint only for its own identity, never a nonce replacement", async () => {
    const adapter = fixture({
      targetReceipt: null,
      replacementCandidate: { userOperationHash: replacementHash },
    });
    const observer = createOperationObserver(adapter.capabilities);
    const result = await observer.observeOperation({
      operation: submitted({
        route: "erc4337-handleops",
        transactionHash: targetTransactionHash,
      }),
      observedAt: 100,
      timeoutMs: 1000,
    });
    expect(result.status).toBe("dropped");
    const receipts = adapter.requests.filter(
      (request) => request.type === "user_operation_receipt",
    );
    expect(receipts).toEqual([
      {
        type: "user_operation_receipt",
        chainId: identity.chainId,
        userOperationHash: identity.userOperationHash,
        transaction: { hash: targetTransactionHash, entryPoint: identity.entryPoint },
      },
      {
        type: "user_operation_receipt",
        chainId: identity.chainId,
        userOperationHash: replacementHash,
      },
    ]);
    await observer.close();
  });

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
          logs: [
            target.boundary,
            { ...other.event, logIndex: "0x1" },
            { ...target.event, logIndex: "0x2" },
          ],
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
        logs: [target.boundary, target.event, { ...target.event, logIndex: "0x2" }],
      }),
    ],
    [
      "removed event",
      (receipt: OperationObserverTransactionReceiptEvidence) => ({
        ...receipt,
        logs: [target.boundary, { ...target.event, removed: true }],
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
        logs: [target.boundary, { ...target.event, data: `${target.event.data}${word(0)}` }],
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

    // A superseded record is terminal too: re-observation returns it directly
    // instead of re-running the evidence path, which could only downgrade a
    // conclusive lane release into an inconclusive read failure.
    const superseded = applyVerifiedOperationObservation(submitted(), {
      type: "record_superseded",
      identity,
      supersession: {
        kind: "entry_point_nonce_advanced",
        observedNonce: "8",
        blockNumber: "32",
        blockHash: finalityBlockHash,
        observedAt: 13,
      },
    });
    const supersededAgain = await observer.observeOperation({
      operation: superseded,
      observedAt: 14,
      timeoutMs: 1_000,
    });
    expect(supersededAgain).toMatchObject({
      status: "superseded",
      operation: { state: "superseded" },
    });
    expect(adapter.requests).toHaveLength(reads);
  });

  it("returns exact abandoned terminal evidence with zero provider reads", async () => {
    const adapter = fixture();
    const observer = createOperationObserver(adapter.capabilities);
    const abandoned = advanceOperation(createOperation({ identity, preparedAt: 10 }), {
      type: "mark_abandoned",
      identity,
      abandonedAt: 11,
      reason: "submission_not_attempted",
    });

    const result = await observer.observeOperation({
      operation: abandoned,
      observedAt: 12,
      timeoutMs: 1_000,
    });

    expect(result).toEqual({ status: "abandoned", operation: abandoned });
    expect(adapter.requests).toEqual([]);
    await observer.close();
  });

  it("continues finality from a durable Operation after recreating store and observer", async () => {
    const directory = await mkdtemp(join(tmpdir(), "oaath-observer-reload-"));
    temporaryDirectories.push(directory);
    const filePath = join(directory, "store.db");
    const key = { grantId: identity.grantId, chainId: identity.chainId, kind: identity.kind };
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

  it.each([
    ["matching", finalityBlockHash, "superseded"],
    ["fork-swapped", replacementBlockHash, "pending"],
  ] as const)(
    "binds supersession to the finalized block hash (%s rebind)",
    async (_label, reboundHash, expected) => {
      // The nonce is read by block number alone, so the block at that number
      // must still be the exact finalized block the supersession records. A
      // provider answering the nonce from another fork frees no lane.
      const finalizedBlock = {
        number: quantity(0x20),
        hash: finalityBlockHash,
        parentHash,
        transactions: [],
      };
      const observer = createOperationObserver({
        async read(request: OperationObserverReadRequest) {
          if (request.type === "chain_id") return identity.chainId;
          if (request.type === "user_operation_receipt") return null;
          if (request.type === "replacement_candidate") return null;
          if (request.type === "finalized_block") return finalizedBlock;
          if (request.type === "entry_point_nonce") return quantity(8);
          if (request.type === "canonical_block") {
            return { ...finalizedBlock, hash: reboundHash };
          }
          throw new Error(`unexpected read ${request.type}`);
        },
        async close() {},
      });
      await expect(
        observer.observeOperation({ operation: submitted(), observedAt: 13, timeoutMs: 1_000 }),
      ).resolves.toMatchObject(
        expected === "superseded"
          ? { status: "superseded", operation: { state: "superseded" } }
          : { status: "pending", reason: "receipt_missing" },
      );
      await observer.close();
    },
  );

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

const reference = Object.freeze({
  chainId: identity.chainId,
  entryPoint: identity.entryPoint,
  account: identity.account,
  nonce: identity.nonce,
  userOperationHash: identity.userOperationHash,
});
const referenceInput = { reference, observedAt: 100, timeoutMs: 1000 };

describe("bounded canonical finality", () => {
  it.each(["journal", "reference"] as const)(
    "recovers an old receipt through the %s reader within twelve reads",
    async (kind) => {
      const finalized = { ...finalizedBlock, number: "0xf4240" };
      let reads = 0;
      const adapter = fixture({
        finality: finalized,
        mutate(request, value) {
          if (++reads > 12) throw new Error("observation request budget exhausted");
          if (request.type === "canonical_block" && request.blockNumber === "1000000")
            return finalized;
          return value;
        },
      });
      if (kind === "journal") {
        const observer = createOperationObserver(adapter.capabilities);
        try {
          expect(
            await observer.observeOperation({
              operation: submitted(),
              observedAt: 100,
              timeoutMs: 1000,
            }),
          ).toMatchObject({
            status: "finalized",
            operation: { finality: { blockNumber: "1000000" } },
          });
        } finally {
          await observer.close();
        }
      } else {
        const observer = createUserOperationObserver(adapter.capabilities);
        try {
          expect(await observer.observeReference(referenceInput)).toMatchObject({
            status: "finalized",
            finality: { blockNumber: "1000000" },
          });
        } finally {
          await observer.close();
        }
      }
      expect(reads).toBeLessThanOrEqual(12);
    },
  );

  it.each(["finalized-rebind", "inclusion-rebind", "wrong-chain"] as const)(
    "leaves old receipt recovery unresolved after %s",
    async (fault) => {
      const finalized = { ...finalizedBlock, number: "0xf4240" };
      let inclusionReads = 0,
        chainReads = 0;
      const adapter = fixture({
        finality: finalized,
        mutate(request, value) {
          if (request.type === "canonical_block" && request.blockNumber === "1000000")
            return fault === "finalized-rebind"
              ? { ...finalized, hash: replacementHash }
              : finalized;
          if (
            request.type === "canonical_block" &&
            request.blockNumber === "20" &&
            ++inclusionReads > 1 &&
            fault === "inclusion-rebind"
          )
            return { ...target.block, hash: replacementBlockHash };
          if (request.type === "chain_id" && ++chainReads > 1 && fault === "wrong-chain")
            return identity.chainId + 1;
          return value;
        },
      });
      const observer = createUserOperationObserver(adapter.capabilities);
      try {
        const result = await observer.observeReference(referenceInput);
        expect(result.status).toBe("unreadable");
        if (result.status === "unreadable")
          expect(result.reason).toBe(
            fault === "wrong-chain" ? "receipt_invalid" : "finality_unproven",
          );
        expect(adapter.requests.some((request) => request.type === "replacement_candidate")).toBe(
          false,
        );
      } finally {
        await observer.close();
      }
    },
  );
});

describe("reference-only UserOperation observation", () => {
  it("normalizes reference checksums and refuses a bad checksum before reads", async () => {
    const adapter = fixture({ targetReceipt: null });
    const observer = createUserOperationObserver(adapter.capabilities);
    const checked = {
      ...reference,
      entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
      account: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    } as const;
    for (const field of ["entryPoint", "account"] as const) {
      const value = checked[field];
      const index = value.search(/[A-F]/u);
      const invalid = value.slice(0, index) + value[index]!.toLowerCase() + value.slice(index + 1);
      await expect(
        observer.observeReference({
          ...referenceInput,
          reference: { ...checked, [field]: invalid },
        }),
      ).rejects.toMatchObject({ code: "operation_observer_address_checksum_invalid" });
    }
    expect(adapter.requests).toEqual([]);
    expect(
      await observer.observeReference({ ...referenceInput, reference: checked }),
    ).toMatchObject({
      status: "pending",
      reference: {
        ...checked,
        entryPoint: checked.entryPoint.toLowerCase(),
        account: checked.account.toLowerCase(),
      },
    });
    await observer.close();
  });

  it("returns canonical inclusion before finality and rechecks after observer recreation", async () => {
    const adapter = fixture({ finality: { ...finalizedBlock, number: "0x13" } });
    const observer = createUserOperationObserver(adapter.capabilities);
    const included = await observer.observeReference(referenceInput);
    expect(included).toMatchObject({
      status: "included",
      reference,
      receipt: { transactionHash: targetTransactionHash, blockHash: targetBlockHash },
      block: target.block,
    });
    await observer.close();
    const saved = JSON.parse(JSON.stringify(included.reference));
    const recovered = createUserOperationObserver(fixture().capabilities);
    expect(await recovered.observeReference({ ...referenceInput, reference: saved })).toMatchObject(
      {
        status: "finalized",
        receipt: { blockHash: targetBlockHash },
      },
    );
    await recovered.close();
  });

  it("does not report inclusion when its block changes during the finality read", async () => {
    let reads = 0;
    const adapter = fixture({
      finality: { ...finalizedBlock, number: "0x13" },
      mutate: (request, value) =>
        request.type === "canonical_block" && ++reads > 1
          ? { ...target.block, hash: replacementBlockHash }
          : value,
    });
    const observer = createUserOperationObserver(adapter.capabilities);
    expect(await observer.observeReference(referenceInput)).toMatchObject({ status: "unreadable" });
    await observer.close();
  });

  it.each([true, false])(
    "only reports a drop for a finalized exact-nonce replacement (%s)",
    async (finalized) => {
      const adapter = fixture({
        targetReceipt: null,
        replacementCandidate: { userOperationHash: replacementHash },
        ...(finalized ? {} : { finality: { ...finalizedBlock, number: "0x13" } }),
      });
      const observer = createUserOperationObserver(adapter.capabilities);
      expect(await observer.observeReference(referenceInput)).toMatchObject(
        finalized
          ? {
              status: "dropped",
              reference,
              replacement: {
                reference: { ...reference, userOperationHash: replacementHash },
                receipt: { outcome: "reverted" },
              },
            }
          : { status: "pending", reference },
      );
      await observer.close();
    },
  );

  it("verifies the exact receipt without manufacturing a Grant or journal transition", async () => {
    const adapter = fixture();
    const observer = createUserOperationObserver(adapter.capabilities);
    const captured = { ...reference };
    const pending = observer.observeReference({ ...referenceInput, reference: captured });
    captured.nonce = "8";
    const result = await pending;
    expect(result.status).toBe("finalized");
    expect(result.reference).toEqual(reference);
    expect(Object.isFrozen(result.reference)).toBe(true);
    if (result.status === "finalized") {
      expect(result.receipt).toMatchObject({
        transactionHash: targetTransactionHash,
        blockHash: targetBlockHash,
        outcome: "success",
      });
      expect(result.receipt.logs).toEqual([target.event]);
      expect(result.finality.blockHash).toBe(finalityBlockHash);
    }
    expect(result).not.toHaveProperty("operation");
    expect(
      adapter.requests.some(
        (request) =>
          request.type === "replacement_candidate" || request.type === "entry_point_nonce",
      ),
    ).toBe(false);
    await observer.close();
    expect(adapter.closeCalls()).toBe(1);
    await expect(observer.observeReference(referenceInput)).rejects.toMatchObject({
      code: "operation_observer_closed",
    });
  });

  it("does not drop on an unverified replacement nonce", async () => {
    const adapter = fixture({
      targetReceipt: null,
      replacementCandidate: { userOperationHash: replacementHash },
      replacementReceipt: { ...replacement.receipt, nonce: "0x8" },
    });
    const observer = createUserOperationObserver(adapter.capabilities);
    expect(await observer.observeReference(referenceInput)).toMatchObject({
      status: "unreadable",
      reason: "receipt_invalid",
      reference,
    });
    await observer.close();
  });

  it("missing evidence with no replacement stays pending", async () => {
    const adapter = fixture({ targetReceipt: null });
    const observer = createUserOperationObserver(adapter.capabilities);
    expect(await observer.observeReference(referenceInput)).toMatchObject({
      status: "pending",
      reason: "receipt_missing",
      reference,
    });
    expect(adapter.requests.map((request) => request.type)).toEqual([
      "chain_id",
      "user_operation_receipt",
      "replacement_candidate",
      "chain_id",
    ]);
    await observer.close();
  });

  it("rejects another sender, nonce, operation, containing transaction or changed chain", async () => {
    for (const change of [
      { sender: zeroAddress },
      { nonce: "0x8" },
      { userOperationHash: replacementHash },
    ]) {
      const adapter = fixture({ targetReceipt: { ...target.receipt, ...change } });
      const observer = createUserOperationObserver(adapter.capabilities);
      expect(await observer.observeReference(referenceInput)).toMatchObject({
        status: "unreadable",
        reason: "receipt_invalid",
        receipt: null,
      });
      await observer.close();
    }
    let chainReads = 0;
    const adapter = fixture({
      mutate: (request, value) => (request.type === "chain_id" && ++chainReads > 1 ? 1 : value),
    });
    const observer = createUserOperationObserver(adapter.capabilities);
    expect(await observer.observeReference(referenceInput)).toMatchObject({
      status: "unreadable",
      reason: "receipt_invalid",
      receipt: null,
    });
    await observer.close();
  });

  it("retains verified inclusion when finality is unavailable, but not when the event is invalid", async () => {
    const adapter = fixture({ finality: null });
    const observer = createUserOperationObserver(adapter.capabilities);
    const result = await observer.observeReference(referenceInput);
    expect(result).toMatchObject({
      status: "unreadable",
      reason: "finality_unproven",
      receipt: { transactionHash: targetTransactionHash, outcome: "success" },
    });
    await observer.close();
    const invalid = fixture({
      mutate: (request, value) =>
        request.type === "transaction_receipt"
          ? { ...target.transactionReceipt, logs: [target.boundary] }
          : value,
    });
    const invalidObserver = createUserOperationObserver(invalid.capabilities);
    expect(await invalidObserver.observeReference(referenceInput)).toMatchObject({
      status: "unreadable",
      receipt: null,
    });
    await invalidObserver.close();
  });

  it("binds a direct transaction hint to the same operation and exact containing transaction", async () => {
    const adapter = fixture();
    const observer = createUserOperationObserver(adapter.capabilities);
    expect(
      (
        await observer.observeReference({
          ...referenceInput,
          transactionHash: targetTransactionHash,
        })
      ).status,
    ).toBe("finalized");
    expect(
      adapter.requests.find((request) => request.type === "user_operation_receipt"),
    ).toMatchObject({
      transaction: { hash: targetTransactionHash, entryPoint: reference.entryPoint },
    });
    expect(
      await observer.observeReference({
        ...referenceInput,
        transactionHash: replacementTransactionHash,
      }),
    ).toMatchObject({ status: "unreadable", receipt: null });
    await observer.close();
  });

  it("captures exact bounded input before any RPC and drops raw provider failures", async () => {
    const adapter = fixture();
    const observer = createUserOperationObserver(adapter.capabilities);
    for (const input of [
      { ...referenceInput, reference: identity },
      { ...referenceInput, reference: { ...reference, nonce: "07" } },
      { ...referenceInput, timeoutMs: 0 },
      { ...referenceInput, timeoutMs: 60001 },
      { ...referenceInput, observedAt: -1 },
      { ...referenceInput, transactionHash: "0x01" },
      { ...referenceInput, extra: true },
    ]) {
      await expect(observer.observeReference(input)).rejects.toMatchObject({
        code: "operation_observer_input_invalid",
      });
    }
    expect(adapter.requests).toEqual([]);
    await observer.close();
    const unavailable = createUserOperationObserver({
      read: async () => {
        throw Error("secret-provider-cause");
      },
      close: async () => {},
    });
    const result = await unavailable.observeReference(referenceInput);
    expect(result).toMatchObject({
      status: "unreadable",
      reason: "provider_unavailable",
      receipt: null,
    });
    expect(JSON.stringify(result)).not.toContain("secret-provider-cause");
    await unavailable.close();
  });

  it("bounds stalled reads and lets close drain the outstanding observation", async () => {
    const requests: OperationObserverReadRequest[] = [];
    const observer = createUserOperationObserver({
      read: async (request: OperationObserverReadRequest) => {
        requests.push(request);
        return new Promise(() => {});
      },
      close: async () => {},
    });
    const pending = observer.observeReference({ ...referenceInput, timeoutMs: 5 });
    const closing = observer.close();
    expect(await pending).toMatchObject({ status: "pending", reason: "timeout" });
    await closing;
    expect(requests).toHaveLength(1);
  });
});
