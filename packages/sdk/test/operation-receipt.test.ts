import {
  advanceOperation,
  applyVerifiedOperationObservation,
  createOperation,
  type Operation,
  type OperationIdentity,
  type OperationInclusion,
} from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import { createOperationHandle } from "../src/client/operation-handle.js";
import {
  type ObserveOperationResult,
  type OperationObserverCapabilities,
  type OperationObserverLogEvidence,
  type OperationObserverTransactionReceiptEvidence,
  type OperationObserverUserOperationReceiptEvidence,
  verifyOperationReceiptEvidence,
} from "../src/operation-observer.js";
import type { OperationObserveResult, OperationRunner } from "../src/operation-runner.js";
import { OAATH_OPERATION_STORE_RECORD_VERSION } from "../src/store.js";

const ENTRY_POINT = `0x${"11".repeat(20)}` as const;
const ACCOUNT = `0x${"22".repeat(20)}` as const;
const TARGET = `0x${"33".repeat(20)}` as const;
const NESTED_TARGET = `0x${"34".repeat(20)}` as const;
const UPGRADE_TARGET = `0x${"35".repeat(20)}` as const;
const ZERO_ADDRESS = `0x${"00".repeat(20)}` as const;
const USER_OPERATION_HASH = `0x${"44".repeat(32)}` as const;
const PRIOR_USER_OPERATION_HASH = `0x${"45".repeat(32)}` as const;
const FOLLOWING_USER_OPERATION_HASH = `0x${"46".repeat(32)}` as const;
const TRANSACTION_HASH = `0x${"55".repeat(32)}` as const;
const BLOCK_HASH = `0x${"66".repeat(32)}` as const;
const USER_OPERATION_EVENT =
  "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f" as const;
const BEFORE_EXECUTION =
  "0xbb47ee3e183a558b1a2ff0874b079f3fc5478b7454eacf2bfc5af2ff5878f972" as const;
const CALL_TOPIC = `0x${"77".repeat(32)}` as const;
const NESTED_TOPIC = `0x${"78".repeat(32)}` as const;
const UPGRADE_TOPIC = `0x${"79".repeat(32)}` as const;

const identity: Readonly<OperationIdentity> = Object.freeze({
  kind: "execution",
  grantId: "receipt-grant",
  chainId: 31_337,
  entryPoint: ENTRY_POINT,
  account: ACCOUNT,
  nonce: "7",
  userOperationHash: USER_OPERATION_HASH,
  requestHash: null,
});

const inclusion: Readonly<OperationInclusion> = Object.freeze({
  transactionHash: TRANSACTION_HASH,
  blockNumber: "20",
  blockHash: BLOCK_HASH,
  outcome: "success",
  observedAt: 100,
});

function quantity(value: bigint | number): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
}

function word(value: bigint | number): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

function log(
  logIndex: number,
  input: Readonly<{
    address?: `0x${string}`;
    topics?: readonly `0x${string}`[];
    data?: `0x${string}`;
    blockNumber?: `0x${string}`;
    blockHash?: `0x${string}`;
    transactionHash?: `0x${string}`;
    transactionIndex?: `0x${string}`;
    removed?: boolean;
  }> = {},
): OperationObserverLogEvidence {
  return {
    address: input.address ?? TARGET,
    blockNumber: input.blockNumber ?? "0x14",
    blockHash: input.blockHash ?? BLOCK_HASH,
    transactionHash: input.transactionHash ?? TRANSACTION_HASH,
    transactionIndex: input.transactionIndex ?? "0x2",
    logIndex: quantity(logIndex),
    removed: input.removed ?? false,
    topics: input.topics ?? [CALL_TOPIC],
    data: input.data ?? "0x0102",
  };
}

function beforeExecution(logIndex: number): OperationObserverLogEvidence {
  return log(logIndex, {
    address: ENTRY_POINT,
    topics: [BEFORE_EXECUTION],
    data: "0x",
  });
}

function userOperationEvent(
  logIndex: number,
  input: Readonly<{
    hash?: `0x${string}`;
    nonce?: bigint;
    success?: boolean;
    actualGasCost?: bigint;
    actualGasUsed?: bigint;
    sender?: `0x${string}`;
  }> = {},
): OperationObserverLogEvidence {
  const sender = input.sender ?? ACCOUNT;
  return log(logIndex, {
    address: ENTRY_POINT,
    topics: [
      USER_OPERATION_EVENT,
      input.hash ?? USER_OPERATION_HASH,
      `0x${"0".repeat(24)}${sender.slice(2)}`,
      `0x${"0".repeat(24)}${ZERO_ADDRESS.slice(2)}`,
    ],
    data: `0x${word(input.nonce ?? 7n)}${word(input.success === false ? 0n : 1n)}${word(
      input.actualGasCost ?? 9n,
    )}${word(input.actualGasUsed ?? 10n)}`,
  });
}

function operationReceipt(
  overrides: Partial<OperationObserverUserOperationReceiptEvidence> = {},
): OperationObserverUserOperationReceiptEvidence {
  return {
    userOperationHash: USER_OPERATION_HASH,
    entryPoint: ENTRY_POINT,
    sender: ACCOUNT,
    nonce: "0x7",
    paymaster: ZERO_ADDRESS,
    actualGasCost: "0x9",
    actualGasUsed: "0xa",
    success: true,
    transactionHash: TRANSACTION_HASH,
    blockNumber: "0x14",
    blockHash: BLOCK_HASH,
    ...overrides,
  };
}

function transactionReceipt(
  logs: readonly OperationObserverLogEvidence[],
  overrides: Partial<OperationObserverTransactionReceiptEvidence> = {},
): OperationObserverTransactionReceiptEvidence {
  return {
    transactionHash: TRANSACTION_HASH,
    blockNumber: "0x14",
    blockHash: BLOCK_HASH,
    transactionIndex: "0x2",
    status: "0x1",
    gasUsed: "0x2a",
    logs,
    ...overrides,
  };
}

function verify(
  logs: readonly OperationObserverLogEvidence[],
  input: Readonly<{
    identity?: Readonly<OperationIdentity>;
    inclusion?: Readonly<OperationInclusion>;
    operationReceipt?: OperationObserverUserOperationReceiptEvidence;
    transactionReceipt?: unknown;
  }> = {},
) {
  return verifyOperationReceiptEvidence({
    identity: input.identity ?? identity,
    inclusion: input.inclusion ?? inclusion,
    userOperationReceipt: input.operationReceipt ?? operationReceipt(),
    transactionReceipt: input.transactionReceipt ?? transactionReceipt(logs),
  });
}

function expectInvalid(action: () => unknown): void {
  expect(action).toThrowError(expect.objectContaining({ message: "receipt_invalid" }));
}

function submittedOperation(): Operation {
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

function finalizedOperation(): Operation {
  const included = applyVerifiedOperationObservation(submittedOperation(), {
    type: "record_included",
    identity,
    inclusion,
  });
  return applyVerifiedOperationObservation(included, {
    type: "record_finalized",
    identity,
    finality: {
      blockNumber: inclusion.blockNumber,
      blockHash: inclusion.blockHash,
      observedAt: inclusion.observedAt + 1,
    },
  });
}

function droppedOperation(): Operation {
  return applyVerifiedOperationObservation(submittedOperation(), {
    type: "record_dropped",
    identity,
    drop: {
      kind: "finalized_nonce_replacement",
      replacement: {
        identity: {
          chainId: identity.chainId,
          entryPoint: identity.entryPoint,
          account: identity.account,
          nonce: identity.nonce,
          userOperationHash: PRIOR_USER_OPERATION_HASH,
        },
        inclusion: {
          transactionHash: `0x${"89".repeat(32)}`,
          blockNumber: "21",
          blockHash: `0x${"90".repeat(32)}`,
          outcome: "success",
          observedAt: 101,
        },
        finality: {
          blockNumber: "21",
          blockHash: `0x${"90".repeat(32)}`,
          observedAt: 102,
        },
      },
    },
  });
}

function observedResult(operation: Operation): OperationObserveResult {
  let observation: ObserveOperationResult;
  if (operation.state === "finalized") {
    observation = Object.freeze({ status: "finalized", operation });
  } else if (operation.state === "dropped") {
    observation = Object.freeze({ status: "dropped", operation });
  } else {
    throw new Error("test operation must be terminal");
  }
  return Object.freeze({
    status: "observed",
    observation,
    record: Object.freeze({
      version: OAATH_OPERATION_STORE_RECORD_VERSION,
      storeRevision: 0,
      updatedAt: operation.updatedAt,
      value: operation,
    }),
  });
}

function inertRunner(result: OperationObserveResult): OperationRunner {
  return Object.freeze({
    async startOperation() {
      throw new Error("not used");
    },
    async abandonPreparedOperation() {
      throw new Error("not used");
    },
    async observeOperation() {
      return result;
    },
    async runOperation() {
      return result;
    },
    async close() {},
  });
}

function operationHandle(operation: Operation, observation: OperationObserverCapabilities["read"]) {
  const initial = observedResult(operation);
  return createOperationHandle({
    runner: inertRunner(initial),
    key: { grantId: identity.grantId, chainId: identity.chainId, kind: identity.kind },
    kind: identity.kind,
    timeoutMs: 1_000,
    now: () => 200,
    initial,
    observation,
  });
}

describe("exact UserOperation receipt evidence", () => {
  it("excludes pre-execution setup while retaining target and nested call logs in order", () => {
    const accountSetup = log(0, { address: ACCOUNT, topics: [`0x${"80".repeat(32)}`] });
    const permissionSetup = log(1, { address: ACCOUNT, topics: [`0x${"81".repeat(32)}`] });
    const boundary = beforeExecution(2);
    const targetCall = log(3);
    const nestedCall = log(4, { address: NESTED_TARGET, topics: [NESTED_TOPIC] });
    const event = userOperationEvent(5);

    const result = verify([accountSetup, permissionSetup, boundary, targetCall, nestedCall, event]);

    expect(result.logs).toEqual([targetCall, nestedCall, event]);
    expect(result.logs).not.toContain(accountSetup);
    expect(result.logs).not.toContain(permissionSetup);
    expect(result.logs).not.toContain(boundary);
    expect(result).toMatchObject({
      transactionHash: TRANSACTION_HASH,
      blockNumber: "20",
      blockHash: BLOCK_HASH,
      gasUsed: "42",
      transactionStatus: "success",
      outcome: "success",
    });
  });

  it("isolates a middle operation and retains an upgrade explicitly emitted by its calls", () => {
    const priorUpgrade = log(1, { address: UPGRADE_TARGET, topics: [UPGRADE_TOPIC] });
    const priorEvent = userOperationEvent(2, {
      hash: PRIOR_USER_OPERATION_HASH,
      nonce: 6n,
    });
    const targetCall = log(3);
    const nestedCall = log(4, { address: NESTED_TARGET, topics: [NESTED_TOPIC] });
    const relevantUpgrade = log(5, { address: UPGRADE_TARGET, topics: [UPGRADE_TOPIC] });
    const targetEvent = userOperationEvent(6);
    const followingUpgrade = log(7, { address: UPGRADE_TARGET, topics: [UPGRADE_TOPIC] });
    const followingEvent = userOperationEvent(8, {
      hash: FOLLOWING_USER_OPERATION_HASH,
      nonce: 8n,
    });

    const result = verify([
      beforeExecution(0),
      priorUpgrade,
      priorEvent,
      targetCall,
      nestedCall,
      relevantUpgrade,
      targetEvent,
      followingUpgrade,
      followingEvent,
    ]);

    expect(result.logs).toEqual([targetCall, nestedCall, relevantUpgrade, targetEvent]);
    expect(result.logs).not.toContain(priorUpgrade);
    expect(result.logs).not.toContain(priorEvent);
    expect(result.logs).not.toContain(followingUpgrade);
    expect(result.logs).not.toContain(followingEvent);
  });

  it("fails closed when no preceding EntryPoint execution boundary exists", () => {
    expectInvalid(() => verify([log(0), userOperationEvent(1)]));
  });

  it.each([
    ["removed", [beforeExecution(0), log(1, { removed: true }), userOperationEvent(2)]],
    ["duplicate index", [beforeExecution(0), log(1), userOperationEvent(1)]],
    ["out-of-order index", [beforeExecution(0), log(2), userOperationEvent(1)]],
    [
      "wrong block number",
      [beforeExecution(0), log(1, { blockNumber: "0x15" }), userOperationEvent(2)],
    ],
    [
      "wrong block hash",
      [beforeExecution(0), log(1, { blockHash: `0x${"82".repeat(32)}` }), userOperationEvent(2)],
    ],
    [
      "wrong transaction",
      [
        beforeExecution(0),
        log(1, { transactionHash: `0x${"83".repeat(32)}` }),
        userOperationEvent(2),
      ],
    ],
    [
      "wrong transaction index",
      [beforeExecution(0), log(1, { transactionIndex: "0x3" }), userOperationEvent(2)],
    ],
  ] as const)("rejects a %s log", (_label, logs) => {
    expectInvalid(() => verify(logs));
  });

  it("requires exactly one target UserOperationEvent", () => {
    expectInvalid(() => verify([beforeExecution(0), userOperationEvent(1), userOperationEvent(2)]));
  });

  it.each([
    ["event outcome", userOperationEvent(2, { success: false }), operationReceipt(), inclusion],
    [
      "event gas cost",
      userOperationEvent(2, { actualGasCost: 11n }),
      operationReceipt(),
      inclusion,
    ],
    [
      "event gas used",
      userOperationEvent(2, { actualGasUsed: 11n }),
      operationReceipt(),
      inclusion,
    ],
    ["receipt outcome", userOperationEvent(2), operationReceipt({ success: false }), inclusion],
    [
      "inclusion outcome",
      userOperationEvent(2),
      operationReceipt(),
      Object.freeze({ ...inclusion, outcome: "reverted" as const }),
    ],
  ] as const)("rejects %s disagreement", (_label, event, receipt, targetInclusion) => {
    expectInvalid(() =>
      verify([beforeExecution(0), log(1), event], {
        operationReceipt: receipt,
        inclusion: targetInclusion,
      }),
    );
  });

  it.each([
    ["hash", { userOperationHash: `0x${"84".repeat(32)}` }],
    ["EntryPoint", { entryPoint: `0x${"85".repeat(20)}` }],
    ["sender", { sender: `0x${"86".repeat(20)}` }],
    ["nonce", { nonce: "0x8" }],
    ["transaction", { transactionHash: `0x${"87".repeat(32)}` }],
    ["block number", { blockNumber: "0x15" }],
    ["block hash", { blockHash: `0x${"88".repeat(32)}` }],
  ] as const)("rejects operation receipt %s substitution", (_label, override) => {
    expectInvalid(() =>
      verify([beforeExecution(0), log(1), userOperationEvent(2)], {
        operationReceipt: operationReceipt(override),
      }),
    );
  });

  it("rejects an outer transaction revert", () => {
    const logs = [beforeExecution(0), log(1), userOperationEvent(2)];
    expectInvalid(() =>
      verify(logs, { transactionReceipt: transactionReceipt(logs, { status: "0x0" }) }),
    );
  });

  it.each([
    ["missing", undefined],
    ["noncanonical", "0x02a"],
    ["non-quantity", "42"],
  ] as const)("rejects %s transaction gasUsed", (_label, gasUsed) => {
    const logs = [beforeExecution(0), log(1), userOperationEvent(2)];
    const receipt: Record<string, unknown> = { ...transactionReceipt(logs) };
    if (gasUsed === undefined) delete receipt.gasUsed;
    else receipt.gasUsed = gasUsed;
    expectInvalid(() => verify(logs, { transactionReceipt: receipt }));
  });
});

describe("operation handle receipt binding", () => {
  it("never follows a finalized replacement lane", async () => {
    const operation = droppedOperation();
    if (operation.state !== "dropped") throw new Error("expected a dropped operation");
    expect(operation.priorInclusion).toBeNull();
    let reads = 0;
    const handle = operationHandle(operation, async () => {
      reads += 1;
      return null;
    });

    await expect(handle.receipt()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_observation_unavailable",
    });
    expect(handle.outcome.transactionHash).toBeNull();
    expect(reads).toBe(0);
  });

  it("maps provider failures to observation-unavailable without leaking diagnostics", async () => {
    const secret = "private receipt provider failure";
    const handle = operationHandle(finalizedOperation(), async () => {
      throw new Error(secret);
    });

    const error = await handle.receipt().then(
      () => null,
      (reason: unknown) => reason,
    );
    expect(error).toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_observation_unavailable",
      source: "provider_unavailable",
    });
    if (!(error instanceof Error)) throw new Error("expected a receipt error");
    expect(error.message).not.toContain(secret);
  });

  it("maps hostile receipt evidence to observation-unavailable", async () => {
    const logs = [beforeExecution(0), log(1), userOperationEvent(2)];
    const handle = operationHandle(finalizedOperation(), async (request) =>
      request.type === "user_operation_receipt"
        ? operationReceipt({ userOperationHash: PRIOR_USER_OPERATION_HASH })
        : transactionReceipt(logs),
    );

    await expect(handle.receipt()).rejects.toMatchObject({
      name: "OaathClientError",
      code: "oaath_client_observation_unavailable",
      source: "receipt_invalid",
    });
  });
});
