import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  advanceGrant,
  advanceOperation,
  applyVerifiedOperationObservation,
  createGrant,
  createOperation,
  type Grant,
  type GrantIdentity,
  type Operation,
  type OperationIdentity,
} from "@oaath/protocol";
import { type GrantStore, OaathStoreError, type OperationStore } from "@oaath/sdk/advanced";
import { afterEach, describe, expect, it } from "vitest";
import { createSqliteGrantStore, createSqliteOperationStore } from "../src/index.js";

const grantIdentity: GrantIdentity = {
  grantId: "durable-grant",
  chainScope: "all",
  application: {
    applicationId: "oaath-tests",
    clientId: "sqlite-store",
    origin: "https://sqlite.example",
    deviceId: "sqlite-device",
  },
  logicalAccount: {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "meta_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"11".repeat(20)}`,
    },
  },
  operatorCredential: {
    version: "oaath.operator-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"22".repeat(20)}`,
  },
  policyHash: `0x${"33".repeat(32)}`,
};

const temporaryDirectories: string[] = [];

async function databasePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "oaath-sqlite-store-"));
  temporaryDirectories.push(directory);
  return join(directory, "store.db");
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function requestedGrant(): Grant {
  return createGrant({ identity: grantIdentity, requestedAt: 10, expiresAt: 100 });
}

function approvedGrant(): Grant {
  return advanceGrant(requestedGrant(), {
    type: "approve",
    identity: grantIdentity,
    approval: {
      approvalHash: `0x${"44".repeat(32)}`,
      capabilityHash: `0x${"55".repeat(32)}`,
      approvedAt: 20,
    },
  });
}

function rejectedGrant(): Grant {
  return advanceGrant(requestedGrant(), {
    type: "reject",
    identity: grantIdentity,
    rejectedAt: 20,
  });
}

function operationIdentity(chainId: number, seed: string): OperationIdentity {
  return {
    kind: "execution",
    grantId: grantIdentity.grantId,
    chainId,
    entryPoint: `0x${"11".repeat(20)}`,
    account: `0x${"22".repeat(20)}`,
    nonce: seed,
    userOperationHash: `0x${seed.repeat(64)}`,
  };
}

function preparedOperation(chainId: number, seed: string): Operation {
  return createOperation({ identity: operationIdentity(chainId, seed), preparedAt: 10 });
}

function operationStoreKey(grantId: string, chainId: number) {
  return { grantId, chainId, kind: "execution" } as const;
}

async function commitOperation(
  store: OperationStore,
  operation: Operation,
  expectedStoreRevision: number | null,
): Promise<number> {
  const result = await store.compareAndSwap({
    key: operationStoreKey(operation.identity.grantId, operation.identity.chainId),
    expectedStoreRevision,
    next: operation,
  });
  expect(result.status).toBe("committed");
  if (result.status !== "committed") throw new Error("Expected committed Operation");
  return result.record.storeRevision;
}

async function expectStoreError(
  action: () => Promise<unknown>,
  code: OaathStoreError["code"],
): Promise<void> {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathStoreError);
    expect((error as OaathStoreError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

function expectStoreConstructorError(action: () => unknown, code: OaathStoreError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathStoreError);
    expect((error as OaathStoreError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

describe("test-only durable SQLite stores", () => {
  it("allows exactly one same-revision Grant writer across independent connections", async () => {
    const filePath = await databasePath();
    const left = createSqliteGrantStore(filePath);
    const right = createSqliteGrantStore(filePath);

    const insertion = await Promise.all([
      left.compareAndSwap({
        grantId: grantIdentity.grantId,
        expectedStoreRevision: null,
        next: requestedGrant(),
      }),
      right.compareAndSwap({
        grantId: grantIdentity.grantId,
        expectedStoreRevision: null,
        next: requestedGrant(),
      }),
    ]);
    expect(insertion.map((result) => result.status).sort()).toEqual(["committed", "conflict"]);

    const update = await Promise.all([
      left.compareAndSwap({
        grantId: grantIdentity.grantId,
        expectedStoreRevision: 0,
        next: approvedGrant(),
      }),
      right.compareAndSwap({
        grantId: grantIdentity.grantId,
        expectedStoreRevision: 0,
        next: rejectedGrant(),
      }),
    ]);
    expect(update.map((result) => result.status).sort()).toEqual(["committed", "conflict"]);
    expect((await left.get(grantIdentity.grantId))?.storeRevision).toBe(1);
    expect(await right.get(grantIdentity.grantId)).toEqual(await left.get(grantIdentity.grantId));

    await Promise.all([left.close(), right.close()]);
  });

  it("keeps same-chain Operation writers exclusive and different chains independent", async () => {
    const filePath = await databasePath();
    const left = createSqliteOperationStore(filePath);
    const right = createSqliteOperationStore(filePath);
    const chainOneA = preparedOperation(1, "6");
    const chainOneB = preparedOperation(1, "7");

    const sameLane = await Promise.all([
      left.compareAndSwap({
        key: operationStoreKey(grantIdentity.grantId, 1),
        expectedStoreRevision: null,
        next: chainOneA,
      }),
      right.compareAndSwap({
        key: operationStoreKey(grantIdentity.grantId, 1),
        expectedStoreRevision: null,
        next: chainOneB,
      }),
    ]);
    expect(sameLane.map((result) => result.status).sort()).toEqual(["committed", "conflict"]);
    await expectStoreError(
      () =>
        left.compareAndSwap({
          key: operationStoreKey(grantIdentity.grantId, 1),
          expectedStoreRevision: 0,
          next: preparedOperation(1, "5"),
        }),
      "store_lane_occupied",
    );
    const winner = sameLane.find((result) => result.status === "committed");
    if (!winner || winner.status !== "committed") throw new Error("Expected one lane winner");
    expect((await left.get(operationStoreKey(grantIdentity.grantId, 1)))?.value).toEqual(
      winner.record.value,
    );

    const otherChains = await Promise.all([
      left.compareAndSwap({
        key: operationStoreKey(grantIdentity.grantId, 10),
        expectedStoreRevision: null,
        next: preparedOperation(10, "8"),
      }),
      right.compareAndSwap({
        key: operationStoreKey(grantIdentity.grantId, 11),
        expectedStoreRevision: null,
        next: preparedOperation(11, "9"),
      }),
    ]);
    expect(otherChains.map((result) => result.status)).toEqual(["committed", "committed"]);

    await Promise.all([left.close(), right.close()]);
  });

  it("releases a terminal lane for a new aggregate without resetting its store revision", async () => {
    const filePath = await databasePath();
    const store = createSqliteOperationStore(filePath);
    const identity = operationIdentity(31_337, "6");
    let first = preparedOperation(identity.chainId, "6");
    let storeRevision = await commitOperation(store, first, null);

    first = advanceOperation(first, {
      type: "mark_submission_attempted",
      identity,
      attemptedAt: 11,
    });
    storeRevision = await commitOperation(store, first, storeRevision);
    first = advanceOperation(first, {
      type: "mark_submitted",
      identity,
      returnedUserOperationHash: identity.userOperationHash,
      submittedAt: 12,
    });
    storeRevision = await commitOperation(store, first, storeRevision);
    first = applyVerifiedOperationObservation(first, {
      type: "record_included",
      identity,
      inclusion: {
        transactionHash: `0x${"44".repeat(32)}`,
        blockNumber: "20",
        blockHash: `0x${"55".repeat(32)}`,
        outcome: "success",
        observedAt: 13,
      },
    });
    storeRevision = await commitOperation(store, first, storeRevision);
    first = applyVerifiedOperationObservation(first, {
      type: "record_finalized",
      identity,
      finality: {
        blockNumber: "25",
        blockHash: `0x${"66".repeat(32)}`,
        observedAt: 14,
      },
    });
    storeRevision = await commitOperation(store, first, storeRevision);
    expect(storeRevision).toBe(4);
    expect(first).toMatchObject({ state: "finalized", revision: 4 });

    const second = preparedOperation(identity.chainId, "7");
    const secondRevision = await commitOperation(store, second, storeRevision);
    expect(secondRevision).toBe(5);
    expect(second.revision).toBe(0);

    const stale = await store.compareAndSwap({
      key: operationStoreKey(grantIdentity.grantId, identity.chainId),
      expectedStoreRevision: storeRevision,
      next: first,
    });
    expect(stale).toMatchObject({
      status: "conflict",
      current: {
        storeRevision: 5,
        value: { identity: { userOperationHash: second.identity.userOperationHash } },
      },
    });

    await store.close();
  });

  it("survives complete instance recreation", async () => {
    const filePath = await databasePath();
    const grant = createSqliteGrantStore(filePath);
    const operation = createSqliteOperationStore(filePath);
    const expectedGrant = requestedGrant();
    const expectedOperation = preparedOperation(31_337, "6");
    await grant.compareAndSwap({
      grantId: grantIdentity.grantId,
      expectedStoreRevision: null,
      next: expectedGrant,
    });
    await operation.compareAndSwap({
      key: operationStoreKey(grantIdentity.grantId, 31_337),
      expectedStoreRevision: null,
      next: expectedOperation,
    });
    await Promise.all([grant.close(), operation.close()]);

    const restoredGrant = createSqliteGrantStore(filePath);
    const restoredOperation = createSqliteOperationStore(filePath);
    const restoredGrantRecord = await restoredGrant.get(grantIdentity.grantId);
    expect(restoredGrantRecord).toMatchObject({
      storeRevision: 0,
      value: expectedGrant,
    });
    expect(restoredGrantRecord?.value.identity.application).toEqual(grantIdentity.application);
    expect(
      await restoredOperation.get(operationStoreKey(grantIdentity.grantId, 31_337)),
    ).toMatchObject({ storeRevision: 0, value: expectedOperation });
    await Promise.all([restoredGrant.close(), restoredOperation.close()]);
  });

  it("rejects malformed durable rows instead of treating them as absent", async () => {
    const filePath = await databasePath();
    const store = createSqliteGrantStore(filePath);
    await store.compareAndSwap({
      grantId: grantIdentity.grantId,
      expectedStoreRevision: null,
      next: requestedGrant(),
    });
    await store.close();

    const database = new DatabaseSync(filePath);
    database
      .prepare("UPDATE oaath_test_grant_store_v1 SET payload = ? WHERE grant_id = ?")
      .run("{}", grantIdentity.grantId);
    database.close();

    const restored = createSqliteGrantStore(filePath);
    await expectStoreError(() => restored.get(grantIdentity.grantId), "store_record_invalid");
    await restored.close();
  });

  it("bounds a write-lock failure and reports commit uncertainty", async () => {
    const filePath = await databasePath();
    const store = createSqliteGrantStore(filePath);
    const blocker = new DatabaseSync(filePath);
    blocker.exec("BEGIN IMMEDIATE");
    try {
      await expectStoreError(
        () =>
          store.compareAndSwap({
            grantId: grantIdentity.grantId,
            expectedStoreRevision: null,
            next: requestedGrant(),
          }),
        "store_commit_indeterminate",
      );
    } finally {
      blocker.exec("ROLLBACK");
      blocker.close();
    }
    await expect(store.get(grantIdentity.grantId)).resolves.toBeUndefined();
    await store.close();
  });

  it("rejects a pre-existing unversioned table instead of adopting its shape", async () => {
    const filePath = await databasePath();
    const database = new DatabaseSync(filePath);
    database.exec(`
      CREATE TABLE oaath_test_grant_store_v1 (
        grant_id TEXT,
        record_version TEXT,
        store_revision INTEGER,
        updated_at INTEGER,
        payload TEXT
      ) STRICT
    `);
    database.close();

    expectStoreConstructorError(() => createSqliteGrantStore(filePath), "store_record_invalid");
  });

  it("rejects added triggers before they can mutate another chain lane", async () => {
    const filePath = await databasePath();
    const store = createSqliteOperationStore(filePath);
    await store.close();
    const database = new DatabaseSync(filePath);
    database.exec(`
      CREATE TRIGGER sqliteX_mutate_another_chain
      AFTER UPDATE ON oaath_test_operation_store_v1
      BEGIN
        UPDATE oaath_test_operation_store_v1
        SET payload = NEW.payload
        WHERE grant_id = NEW.grant_id AND chain_id <> NEW.chain_id;
      END
    `);
    database.close();

    expectStoreConstructorError(() => createSqliteOperationStore(filePath), "store_record_invalid");
  });

  it("requires a file-backed database", () => {
    expectStoreConstructorError(() => createSqliteGrantStore(":memory:"), "store_input_invalid");
    expectStoreConstructorError(
      () => createSqliteOperationStore(":memory:"),
      "store_input_invalid",
    );
  });
});
