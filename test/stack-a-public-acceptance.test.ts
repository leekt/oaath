import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  advanceGrant,
  advanceOperation,
  createGrant,
  createKernelPermissionRemovalObserver,
  createKernelPermissionRevocationCoordinator,
  createOperation,
  createOperationObserver,
  createOperationRunner,
  type FinalizedOperation,
  type Grant,
  type GrantIdentity,
  type KernelPermissionStateReadRequest,
  type KernelPermissionUninstallDescriptor,
  type ObserveOperationResult,
  type Operation,
  type OperationIdentity,
  type OperationKind,
  type OperationObserver,
  type OperationObserverBlockEvidence,
  type OperationObserverReadRequest,
  operationOccupiesLane,
  type PreparedUserOperation,
  prepareUserOperation,
} from "../src/index.js";
import { createSqliteGrantStore, createSqliteOperationStore } from "../src/testing.js";

const entryPoint = `0x${"11".repeat(20)}` as const;
const account = `0x${"22".repeat(20)}` as const;
const zeroAddress = `0x${"00".repeat(20)}` as const;
const userOperationEvent =
  "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f" as const;
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function hash(value: number): `0x${string}` {
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function quantity(value: bigint | number): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
}

function word(value: bigint | number): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

function prepared(kind: OperationKind, grantId: string, chainId: number): PreparedUserOperation {
  return prepareUserOperation({
    kind,
    grantId,
    chainId,
    entryPoint: { version: "0.7", address: entryPoint },
    userOperation: {
      sender: account,
      nonce: "7",
      callData: "0x1234",
      callGasLimit: "100000",
      verificationGasLimit: "200000",
      preVerificationGas: "50000",
      maxFeePerGas: "1000000000",
      maxPriorityFeePerGas: "100000000",
      factory: null,
      paymaster: null,
    },
  });
}

function identity(snapshot: PreparedUserOperation): OperationIdentity {
  return {
    kind: snapshot.kind,
    grantId: snapshot.grantId,
    chainId: snapshot.chainId,
    entryPoint: snapshot.entryPoint.address,
    account: snapshot.userOperation.sender,
    nonce: snapshot.userOperation.nonce,
    userOperationHash: snapshot.userOperationHash,
  };
}

function finalizedObserver(expected: OperationIdentity): OperationObserver {
  const transactionHash = hash(400);
  const inclusionBlockNumber = 20;
  const inclusionBlockHash = hash(inclusionBlockNumber);
  const blocksByHash = new Map<string, OperationObserverBlockEvidence>();
  const blocksByNumber = new Map<string, OperationObserverBlockEvidence>();
  let previous: OperationObserverBlockEvidence = {
    number: quantity(inclusionBlockNumber),
    hash: inclusionBlockHash,
    parentHash: hash(inclusionBlockNumber - 1),
    transactions: [transactionHash],
  };
  blocksByHash.set(previous.hash, previous);
  blocksByNumber.set(String(inclusionBlockNumber), previous);
  for (let blockNumber = inclusionBlockNumber + 1; blockNumber <= 30; blockNumber += 1) {
    const block: OperationObserverBlockEvidence = {
      number: quantity(blockNumber),
      hash: hash(blockNumber),
      parentHash: previous.hash,
      transactions: [],
    };
    blocksByHash.set(block.hash, block);
    blocksByNumber.set(String(blockNumber), block);
    previous = block;
  }
  const finalizedBlock = previous;
  const transactionIndex = "0x0" as const;
  const log = {
    address: expected.entryPoint,
    blockNumber: quantity(inclusionBlockNumber),
    blockHash: inclusionBlockHash,
    transactionHash,
    transactionIndex,
    logIndex: "0x0" as const,
    removed: false,
    topics: [
      userOperationEvent,
      expected.userOperationHash,
      `0x${"0".repeat(24)}${expected.account.slice(2)}` as const,
      `0x${"0".repeat(64)}` as const,
    ],
    data: `0x${word(BigInt(expected.nonce))}${word(1)}${word(9)}${word(10)}` as const,
  };
  return createOperationObserver({
    async read(request: OperationObserverReadRequest) {
      if (request.type === "chain_id") return expected.chainId;
      if (request.type === "replacement_candidate") return null;
      if (request.type === "user_operation_receipt") {
        return {
          userOperationHash: expected.userOperationHash,
          entryPoint: expected.entryPoint,
          sender: expected.account,
          nonce: quantity(BigInt(expected.nonce)),
          paymaster: zeroAddress,
          actualGasCost: "0x9",
          actualGasUsed: "0xa",
          success: true,
          transactionHash,
          blockNumber: quantity(inclusionBlockNumber),
          blockHash: inclusionBlockHash,
        };
      }
      if (request.type === "transaction_receipt") {
        return {
          transactionHash,
          blockNumber: quantity(inclusionBlockNumber),
          blockHash: inclusionBlockHash,
          transactionIndex,
          status: "0x1",
          logs: [log],
        };
      }
      if (request.type === "transaction") {
        return {
          hash: transactionHash,
          to: expected.entryPoint,
          blockNumber: quantity(inclusionBlockNumber),
          blockHash: inclusionBlockHash,
          transactionIndex,
        };
      }
      if (request.type === "canonical_block") return blocksByNumber.get(request.blockNumber);
      if (request.type === "block_by_hash") return blocksByHash.get(request.blockHash);
      if (request.type === "finalized_block") return finalizedBlock;
      throw new Error("unexpected observation request");
    },
    async close() {},
  });
}

type ObservationMode = "missing" | "timeout" | "unavailable";

function negativeObserver(mode: ObservationMode, chainId: number): OperationObserver {
  return createOperationObserver({
    async read(request: OperationObserverReadRequest) {
      if (request.type === "chain_id") return chainId;
      if (request.type === "replacement_candidate") return null;
      if (request.type === "user_operation_receipt") {
        if (mode === "timeout") return new Promise<never>(() => {});
        if (mode === "unavailable") throw new Error("private provider failure");
        return null;
      }
      throw new Error("unexpected observation request");
    },
    async close() {},
  });
}

interface Counters {
  prepares: number;
  opens: number;
  sends: number;
}

function counters(): Counters {
  return { prepares: 0, opens: 0, sends: 0 };
}

function runner(input: {
  path: string;
  snapshot: PreparedUserOperation;
  observer: OperationObserver;
  state: Counters;
}) {
  return createOperationRunner({
    terminalBehavior: "replace",
    store: createSqliteOperationStore(input.path),
    observer: input.observer,
    preparation: {
      async prepare() {
        input.state.prepares += 1;
        return input.snapshot;
      },
      async close() {},
    },
    submission: {
      async openSubmission(snapshot: PreparedUserOperation) {
        input.state.opens += 1;
        expect(snapshot).toEqual(input.snapshot);
        return {
          async submit() {
            input.state.sends += 1;
            return { userOperationHash: input.snapshot.userOperationHash };
          },
          async close() {},
        };
      },
      async close() {},
    },
  });
}

function runInput(kind: OperationKind, grantId: string, chainId: number, observedAt = 13) {
  return {
    kind,
    key: { grantId, chainId },
    preparedAt: 10,
    attemptedAt: 11,
    submittedAt: 12,
    observedAt,
    timeoutMs: 10,
  } as const;
}

async function database(label: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), `ogp-stack-a-${label}-`));
  temporaryDirectories.push(directory);
  return join(directory, "state.db");
}

const permissionSigner = `0x${"66".repeat(20)}` as const;
const permissionOperator = `0x${"77".repeat(20)}` as const;
const noHook = `0x${"00".repeat(19)}01` as const;
const permissionDescriptor: KernelPermissionUninstallDescriptor = {
  kind: "kernel-v3.3-permission-uninstall",
  grantId: "permission-negative-grant",
  chainId: 31_337,
  entryPoint,
  account,
  permissionId: "0x6eea81c7",
  validationId: "0x026eea81c700000000000000000000000000000000",
  signer: permissionSigner,
  operator: permissionOperator,
};

function submittedOperation(expected: OperationIdentity): Operation {
  let value: Operation = createOperation({ identity: expected, preparedAt: 10 });
  value = advanceOperation(value, {
    type: "mark_submission_attempted",
    identity: expected,
    attemptedAt: 11,
  });
  return advanceOperation(value, {
    type: "mark_submitted",
    identity: expected,
    returnedUserOperationHash: expected.userOperationHash,
    submittedAt: 12,
  });
}

async function finalizedOperation(snapshot: PreparedUserOperation): Promise<FinalizedOperation> {
  const observer = finalizedObserver(identity(snapshot));
  const result = await observer.observeOperation({
    operation: submittedOperation(identity(snapshot)),
    observedAt: 13,
    timeoutMs: 1_000,
  });
  await observer.close();
  if (result.status !== "finalized") throw new Error("expected verified final operation");
  return result.operation;
}

type PermissionMode =
  | "present"
  | "provider_unavailable"
  | "timeout"
  | "hostile"
  | "canonicality_unproven"
  | "wrong_chain"
  | "missing_code"
  | "partial";

function permissionObserver(mode: PermissionMode) {
  return createKernelPermissionRemovalObserver({
    async read(request: KernelPermissionStateReadRequest) {
      if (mode === "provider_unavailable") throw new Error("private provider failure");
      if (mode === "timeout") return new Promise<never>(() => {});
      if (mode === "hostile") {
        return new Proxy(
          {},
          {
            ownKeys() {
              throw new Error("private hostile evidence");
            },
          },
        );
      }
      const common = {
        chainId: mode === "wrong_chain" ? request.chainId + 1 : request.chainId,
        account: request.account,
        blockNumber: request.blockNumber,
        blockHash: mode === "canonicality_unproven" ? hash(999) : request.blockHash,
        requireCanonical: true as const,
      };
      if (request.type === "code") {
        return { ...common, code: mode === "missing_code" ? "0x" : "0x01" };
      }
      if (request.type === "kernel_validation_config") {
        return {
          ...common,
          validationId: request.validationId,
          nonce: "1",
          hook: noHook,
        };
      }
      return {
        ...common,
        permissionId: request.permissionId,
        permissionFlag: "0x0000",
        signer: mode === "partial" ? zeroAddress : permissionSigner,
        policyCount: 0,
      };
    },
    async close() {},
  });
}

const grantIdentity: GrantIdentity = {
  grantId: permissionDescriptor.grantId,
  chainScope: "all",
  application: {
    applicationId: "ogp-tests",
    clientId: "stack-a-acceptance",
    origin: "https://stack-a.example",
    deviceId: "stack-a-device",
  },
  logicalAccount: {
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.3.3",
    factoryRoute: "kernel_factory",
    ownerCredential: { kind: "ecdsa", publicIdentityHash: hash(501) },
  },
  operatorCredential: { kind: "ecdsa", publicIdentityHash: hash(502) },
  policyHash: hash(503),
};

function installedGrant(): Grant {
  const binding = {
    chainId: permissionDescriptor.chainId,
    account: permissionDescriptor.account,
    permissionId: permissionDescriptor.permissionId,
  };
  let grant: Grant = createGrant({ identity: grantIdentity, requestedAt: 1, expiresAt: 1_000 });
  grant = advanceGrant(grant, {
    type: "approve",
    identity: grantIdentity,
    approval: { approvalHash: hash(504), capabilityHash: hash(505), approvedAt: 2 },
  });
  grant = advanceGrant(grant, { type: "activate", identity: grantIdentity, activatedAt: 3 });
  grant = advanceGrant(grant, {
    type: "record_unmaterialized",
    identity: grantIdentity,
    binding,
    recordedAt: 4,
  });
  grant = advanceGrant(grant, {
    type: "begin_materialization",
    identity: grantIdentity,
    binding,
    startedAt: 5,
  });
  return advanceGrant(grant, {
    type: "record_installed",
    identity: grantIdentity,
    binding,
    installation: {
      kind: "permission_present",
      ...binding,
      blockNumber: "6",
      blockHash: hash(506),
      observedAt: 6,
    },
  });
}

function uninstallAdapter(snapshot: PreparedUserOperation, state: Counters) {
  return {
    descriptor: permissionDescriptor,
    preparation: {
      async prepare() {
        state.prepares += 1;
        return snapshot;
      },
      async close() {},
    },
    submission: {
      async openSubmission(preparedSnapshot: PreparedUserOperation) {
        state.opens += 1;
        expect(preparedSnapshot).toEqual(snapshot);
        return {
          async submit() {
            state.sends += 1;
            return { userOperationHash: snapshot.userOperationHash };
          },
          async close() {},
        };
      },
      async close() {},
    },
  };
}

function revocationInput(offset = 0) {
  return {
    revocationStartedAt: 40 + offset,
    chainRevocationStartedAt: 41 + offset,
    preparedAt: 42 + offset,
    attemptedAt: 43 + offset,
    submittedAt: 44 + offset,
    operationObservedAt: 45 + offset,
    permissionObservedAt: 46 + offset,
    timeoutMs: 1_000,
  } as const;
}

describe("Stack A packed public acceptance", () => {
  it.each([
    ["execution", "missing"],
    ["execution", "timeout"],
    ["execution", "unavailable"],
    ["revocation", "missing"],
    ["revocation", "timeout"],
    ["revocation", "unavailable"],
  ] as const)(
    "keeps the %s lane occupied and observe-only after %s evidence",
    async (kind, mode) => {
      const chainId = 31_337;
      const grantId = `${kind}-${mode}`;
      const path = await database(`${kind}-${mode}`);
      const snapshot = prepared(kind, grantId, chainId);
      const firstCounters = counters();
      const first = runner({
        path,
        snapshot,
        observer: negativeObserver(mode, chainId),
        state: firstCounters,
      });
      const firstResult = await first.runOperation(runInput(kind, grantId, chainId));
      expect(firstResult).toMatchObject({
        status: "observed",
        record: { value: { state: "submitted", identity: { kind, chainId } } },
      });
      expect(firstCounters).toEqual({ prepares: 1, opens: 1, sends: 1 });
      await first.close();

      const recreatedCounters = counters();
      const recreated = runner({
        path,
        snapshot,
        observer: negativeObserver(mode, chainId),
        state: recreatedCounters,
      });
      const recovered = await recreated.runOperation(runInput(kind, grantId, chainId, 14));
      expect(recovered.record.value.identity).toEqual(firstResult.record.value.identity);
      expect(operationOccupiesLane(recovered.record.value)).toBe(true);
      expect(recreatedCounters).toEqual({ prepares: 0, opens: 0, sends: 0 });
      expect(firstCounters.sends + recreatedCounters.sends).toBe(1);
      await recreated.close();
    },
  );

  it.each(["execution", "revocation"] as const)(
    "rejects another concrete chain's finalized %s evidence without resubmission",
    async (kind) => {
      const grantId = `cross-chain-${kind}`;
      const sourceChainId = 31_337;
      const targetChainId = 31_338;
      const path = await database(`cross-chain-${kind}`);
      const sourceSnapshot = prepared(kind, grantId, sourceChainId);
      const sourceCounters = counters();
      const source = runner({
        path,
        snapshot: sourceSnapshot,
        observer: finalizedObserver(identity(sourceSnapshot)),
        state: sourceCounters,
      });
      const sourceResult = await source.runOperation(runInput(kind, grantId, sourceChainId));
      if (sourceResult.status !== "observed") throw new Error("source observation failed");
      expect(sourceResult.observation.status).toBe("finalized");
      await source.close();

      const borrowed: OperationObserver = {
        async observeOperation(): Promise<ObserveOperationResult> {
          return sourceResult.observation;
        },
        async close() {},
      };
      const targetSnapshot = prepared(kind, grantId, targetChainId);
      const targetCounters = counters();
      const target = runner({
        path,
        snapshot: targetSnapshot,
        observer: borrowed,
        state: targetCounters,
      });
      const rejected = await target.runOperation(runInput(kind, grantId, targetChainId));
      expect(rejected).toMatchObject({
        status: "observation_unavailable",
        reason: "identity_mismatch",
        record: {
          value: { state: "submitted", identity: { kind, chainId: targetChainId } },
        },
      });
      expect(targetCounters).toEqual({ prepares: 1, opens: 1, sends: 1 });
      await target.close();

      const recreatedCounters = counters();
      const recreated = runner({
        path,
        snapshot: targetSnapshot,
        observer: borrowed,
        state: recreatedCounters,
      });
      const recovered = await recreated.runOperation(runInput(kind, grantId, targetChainId, 14));
      expect(recovered).toMatchObject({
        status: "observation_unavailable",
        reason: "identity_mismatch",
      });
      expect(operationOccupiesLane(recovered.record.value)).toBe(true);
      expect(recreatedCounters).toEqual({ prepares: 0, opens: 0, sends: 0 });

      const inspection = createSqliteOperationStore(path);
      const sourceRecord = await inspection.get({ grantId, chainId: sourceChainId });
      const targetRecord = await inspection.get({ grantId, chainId: targetChainId });
      expect(sourceRecord?.value).toMatchObject({
        state: "finalized",
        identity: { kind, chainId: sourceChainId },
      });
      expect(targetRecord?.value).toMatchObject({
        state: "submitted",
        identity: { kind, chainId: targetChainId },
      });
      await Promise.all([recreated.close(), inspection.close()]);
    },
  );

  it.each(["execution", "revocation"] as const)(
    "lets only one independent same-lane %s runner submit",
    async (kind) => {
      const grantId = `same-lane-${kind}`;
      const chainId = 31_337;
      const path = await database(`same-lane-${kind}`);
      const snapshot = prepared(kind, grantId, chainId);
      const leftState = counters();
      const rightState = counters();
      const left = runner({
        path,
        snapshot,
        observer: negativeObserver("missing", chainId),
        state: leftState,
      });
      const right = runner({
        path,
        snapshot,
        observer: negativeObserver("missing", chainId),
        state: rightState,
      });

      await Promise.all([
        left.runOperation(runInput(kind, grantId, chainId)),
        right.runOperation(runInput(kind, grantId, chainId)),
      ]);

      expect(leftState.sends + rightState.sends).toBe(1);
      expect(leftState.opens + rightState.opens).toBe(1);
      const inspection = createSqliteOperationStore(path);
      const record = await inspection.get({ grantId, chainId });
      expect(record?.value).toMatchObject({ state: "submitted", identity: { kind, chainId } });
      expect(record && operationOccupiesLane(record.value)).toBe(true);
      await Promise.all([left.close(), right.close(), inspection.close()]);
    },
  );

  it("fails closed before send when the durable operation commit is indeterminate", async () => {
    const grantId = "indeterminate-operation-write";
    const chainId = 31_337;
    const path = await database("indeterminate-operation-write");
    const initialized = createSqliteOperationStore(path);
    await initialized.close();
    const state = counters();
    const operationRunner = runner({
      path,
      snapshot: prepared("execution", grantId, chainId),
      observer: negativeObserver("missing", chainId),
      state,
    });
    const blocker = new DatabaseSync(path);
    blocker.exec("BEGIN IMMEDIATE");
    try {
      await expect(
        operationRunner.runOperation(runInput("execution", grantId, chainId)),
      ).rejects.toMatchObject({
        name: "OgpOperationRunnerError",
        code: "operation_runner_store_uncertain",
      });
      expect(state).toEqual({ prepares: 1, opens: 0, sends: 0 });
    } finally {
      blocker.exec("ROLLBACK");
      blocker.close();
      await operationRunner.close();
    }
  });

  it("rejects malformed durable evidence instead of treating it as absent", async () => {
    const path = await database("malformed-durable-row");
    const store = createSqliteGrantStore(path);
    expect(
      await store.compareAndSwap({
        grantId: permissionDescriptor.grantId,
        expectedStoreRevision: null,
        next: installedGrant(),
      }),
    ).toMatchObject({ status: "committed" });
    await store.close();

    const rawDatabase = new DatabaseSync(path);
    rawDatabase
      .prepare("UPDATE ogp_test_grant_store_v1 SET payload = ? WHERE grant_id = ?")
      .run("{}", permissionDescriptor.grantId);
    rawDatabase.close();

    const restored = createSqliteGrantStore(path);
    await expect(restored.get(permissionDescriptor.grantId)).rejects.toMatchObject({
      name: "OgpStoreError",
      code: "store_record_invalid",
    });
    await restored.close();
  });

  it.each([
    ["provider_unavailable", "provider_unavailable"],
    ["timeout", "provider_unavailable"],
    ["hostile", "state_invalid"],
    ["canonicality_unproven", "canonicality_unproven"],
    ["wrong_chain", "state_invalid"],
    ["missing_code", "state_invalid"],
    ["partial", "state_invalid"],
  ] as const)(
    "keeps finalized receipt success non-authoritative when permission state is %s",
    async (mode, reason) => {
      const snapshot = prepared(
        "revocation",
        permissionDescriptor.grantId,
        permissionDescriptor.chainId,
      );
      const operation = await finalizedOperation(snapshot);
      expect(operation).toMatchObject({
        state: "finalized",
        inclusion: { outcome: "success" },
      });
      const observer = permissionObserver(mode);
      const result = await observer.observeRemoval({
        descriptor: permissionDescriptor,
        operation,
        observedAt: 14,
        timeoutMs: mode === "timeout" ? 5 : 1_000,
      });
      expect(result).toMatchObject({
        status: "unreadable",
        reason,
        operation: { state: "finalized", inclusion: { outcome: "success" } },
      });
      await observer.close();
    },
  );

  it("keeps the Grant revoking after successful inclusion until exact absence is observed", async () => {
    const path = await database("permission-present");
    const seed = createSqliteGrantStore(path);
    expect(
      await seed.compareAndSwap({
        grantId: permissionDescriptor.grantId,
        expectedStoreRevision: null,
        next: installedGrant(),
      }),
    ).toMatchObject({ status: "committed" });
    await seed.close();

    const snapshot = prepared(
      "revocation",
      permissionDescriptor.grantId,
      permissionDescriptor.chainId,
    );
    const state = counters();
    let coordinator = createKernelPermissionRevocationCoordinator({
      grantStore: createSqliteGrantStore(path),
      operationStore: createSqliteOperationStore(path),
      operationObserver: finalizedObserver(identity(snapshot)),
      uninstall: uninstallAdapter(snapshot, state),
      permissionObserver: permissionObserver("present"),
    });
    const present = await coordinator.revoke(revocationInput());
    expect(present).toMatchObject({
      status: "permission_present",
      grant: { value: { state: "revoking", materializations: [{ state: "revoking" }] } },
      operation: {
        value: {
          state: "finalized",
          identity: {
            kind: "revocation",
            grantId: permissionDescriptor.grantId,
            chainId: permissionDescriptor.chainId,
            entryPoint: permissionDescriptor.entryPoint,
            account: permissionDescriptor.account,
            nonce: "7",
            userOperationHash: snapshot.userOperationHash,
          },
          inclusion: { outcome: "success" },
        },
      },
    });
    expect(state).toEqual({ prepares: 1, opens: 1, sends: 1 });
    await coordinator.close();

    coordinator = createKernelPermissionRevocationCoordinator({
      grantStore: createSqliteGrantStore(path),
      operationStore: createSqliteOperationStore(path),
      operationObserver: finalizedObserver(identity(snapshot)),
      uninstall: uninstallAdapter(snapshot, state),
      permissionObserver: permissionObserver("provider_unavailable"),
    });
    const unreadable = await coordinator.revoke(revocationInput(10));
    expect(unreadable).toMatchObject({
      status: "permission_unreadable",
      reason: "provider_unavailable",
      grant: {
        value: {
          state: "revoking",
          materializations: [
            { state: "unreadable", priorState: "revoking", reason: "provider_unavailable" },
          ],
        },
      },
      operation: { value: { state: "finalized", identity: identity(snapshot) } },
    });
    expect(state).toEqual({ prepares: 1, opens: 1, sends: 1 });
    await coordinator.close();
  });

  it("lets only one independent revocation coordinator submit the occupied chain lane", async () => {
    const path = await database("concurrent-revocation");
    const seed = createSqliteGrantStore(path);
    await seed.compareAndSwap({
      grantId: permissionDescriptor.grantId,
      expectedStoreRevision: null,
      next: installedGrant(),
    });
    await seed.close();

    const snapshot = prepared(
      "revocation",
      permissionDescriptor.grantId,
      permissionDescriptor.chainId,
    );
    const state = counters();
    const left = createKernelPermissionRevocationCoordinator({
      grantStore: createSqliteGrantStore(path),
      operationStore: createSqliteOperationStore(path),
      operationObserver: finalizedObserver(identity(snapshot)),
      uninstall: uninstallAdapter(snapshot, state),
      permissionObserver: permissionObserver("present"),
    });
    const right = createKernelPermissionRevocationCoordinator({
      grantStore: createSqliteGrantStore(path),
      operationStore: createSqliteOperationStore(path),
      operationObserver: finalizedObserver(identity(snapshot)),
      uninstall: uninstallAdapter(snapshot, state),
      permissionObserver: permissionObserver("present"),
    });

    const results = await Promise.all([
      left.revoke(revocationInput()),
      right.revoke(revocationInput()),
    ]);

    expect(state).toMatchObject({ opens: 1, sends: 1 });
    expect(state.prepares).toBeGreaterThanOrEqual(1);
    expect(state.prepares).toBeLessThanOrEqual(2);
    expect(results.every((result) => result.grant.value.state === "revoking")).toBe(true);
    const operations = createSqliteOperationStore(path);
    const operation = await operations.get({
      grantId: permissionDescriptor.grantId,
      chainId: permissionDescriptor.chainId,
    });
    expect(operation?.value).toMatchObject({
      state: "finalized",
      identity: { kind: "revocation", chainId: permissionDescriptor.chainId },
    });
    await Promise.all([left.close(), right.close(), operations.close()]);
  });
});
