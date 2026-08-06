import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  advanceOperation,
  applyVerifiedOperationObservation,
  createOperation,
  type Operation,
  type OperationKind,
} from "@oaath/protocol";
import { createSqliteOperationStore } from "@oaath/testing";
import { afterEach, describe, expect, it } from "vitest";
import {
  createOperationObserver,
  createOperationRunner,
  type OaathOperationRunnerError,
  type OperationObserver,
  OperationStore,
  type OperationStoreAdapter,
  type OperationStoreRecord,
} from "../src/advanced.js";
import {
  deriveOperationId,
  type PreparedUserOperation,
  prepareUserOperation,
} from "../src/kernel.js";

const key = { grantId: "runner-grant", chainId: 31_337, kind: "execution" } as const;
const entryPoint = `0x${"11".repeat(20)}` as const;
const account = `0x${"22".repeat(20)}` as const;
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function prepared(kind: OperationKind, nonce = "7"): PreparedUserOperation {
  return prepareUserOperation({
    kind,
    grantId: key.grantId,
    chainId: key.chainId,
    entryPoint: { version: "0.7", address: entryPoint },
    userOperation: {
      sender: account,
      nonce,
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

function runInput(kind: OperationKind) {
  return {
    kind,
    key: { ...key, kind },
    preparedAt: 10,
    attemptedAt: 11,
    submittedAt: 12,
    observedAt: 13,
    timeoutMs: 1_000,
  } as const;
}

function pendingObserver(
  close: () => Promise<void> = async () => {},
  onRead: () => void = () => {},
) {
  return createOperationObserver({
    async read(request: { type: string }) {
      onRead();
      if (request.type === "chain_id") return key.chainId;
      if (request.type === "user_operation_receipt") return null;
      if (request.type === "replacement_candidate") return null;
      throw new Error("unexpected observer read");
    },
    close,
  });
}

function terminalObserver(terminal: "finalized" | "dropped"): OperationObserver {
  return {
    async observeOperation(inputValue) {
      const input = inputValue as { operation: Operation; observedAt: number };
      if (terminal === "dropped") {
        const dropped = applyVerifiedOperationObservation(input.operation, {
          type: "record_dropped",
          identity: input.operation.identity,
          drop: {
            kind: "finalized_nonce_replacement",
            replacement: {
              identity: {
                chainId: input.operation.identity.chainId,
                entryPoint: input.operation.identity.entryPoint,
                account: input.operation.identity.account,
                nonce: input.operation.identity.nonce,
                userOperationHash: `0x${"77".repeat(32)}`,
              },
              inclusion: {
                transactionHash: `0x${"88".repeat(32)}`,
                blockNumber: "20",
                blockHash: `0x${"99".repeat(32)}`,
                outcome: "success",
                observedAt: input.observedAt,
              },
              finality: {
                blockNumber: "21",
                blockHash: `0x${"aa".repeat(32)}`,
                observedAt: input.observedAt,
              },
            },
          },
        });
        if (dropped.state !== "dropped") throw new Error("expected dropped operation");
        return { status: "dropped", operation: dropped };
      }
      const included = applyVerifiedOperationObservation(input.operation, {
        type: "record_included",
        identity: input.operation.identity,
        inclusion: {
          transactionHash: `0x${"44".repeat(32)}`,
          blockNumber: "20",
          blockHash: `0x${"55".repeat(32)}`,
          outcome: "success",
          observedAt: input.observedAt,
        },
      });
      const finalized = applyVerifiedOperationObservation(included, {
        type: "record_finalized",
        identity: included.identity,
        finality: {
          blockNumber: "21",
          blockHash: `0x${"66".repeat(32)}`,
          observedAt: input.observedAt,
        },
      });
      if (finalized.state !== "finalized") throw new Error("expected finalized operation");
      return { status: "finalized", operation: finalized };
    },
    async close() {},
  };
}

interface MemoryControl {
  raw?: unknown;
  archives?: Map<string, unknown>;
  fault?: (next: OperationStoreRecord) => boolean;
  closeFailures: number;
  closeCalls: number;
}

function memoryStore(control: MemoryControl): OperationStore {
  control.archives ??= new Map<string, unknown>();
  const adapter: OperationStoreAdapter = {
    async get() {
      return control.raw;
    },
    async getArchived(input) {
      return control.archives?.get(JSON.stringify([input.key, input.userOperationHash]));
    },
    async compareAndSwap(input) {
      const next = input.next as OperationStoreRecord;
      if (control.fault?.(next)) throw new Error("private store failure");
      const current = control.raw as OperationStoreRecord | undefined;
      if (
        (input.expectedStoreRevision === null && current !== undefined) ||
        (input.expectedStoreRevision !== null &&
          current?.storeRevision !== input.expectedStoreRevision)
      ) {
        return false;
      }
      if (input.archive !== null) {
        const archiveKey = JSON.stringify([input.key, input.archive.userOperationHash]);
        if (control.archives?.has(archiveKey)) return false;
        control.archives?.set(archiveKey, input.archive.record);
      }
      control.raw = next;
      return true;
    },
    async close() {
      control.closeCalls += 1;
      if (control.closeFailures > 0) {
        control.closeFailures -= 1;
        throw new Error("private close failure");
      }
    },
  };
  return new OperationStore(adapter);
}

interface RunnerCounters {
  prepares: number;
  opens: number;
  sends: number;
  preparationCloses: number;
  submissionCloses: number;
  sessionCloses: number;
}

function counters(): RunnerCounters {
  return {
    prepares: 0,
    opens: 0,
    sends: 0,
    preparationCloses: 0,
    submissionCloses: 0,
    sessionCloses: 0,
  };
}

function runner(input: {
  store: OperationStore;
  prepared: PreparedUserOperation;
  counters: RunnerCounters;
  terminalBehavior?: "replace" | "reuse_same_kind";
  observer?: OperationObserver;
  open?: (snapshot: PreparedUserOperation) => Promise<unknown>;
  submit?: () => Promise<unknown>;
}) {
  const submit =
    input.submit ??
    (async () => {
      input.counters.sends += 1;
      return { userOperationHash: input.prepared.userOperationHash };
    });
  return createOperationRunner({
    terminalBehavior: input.terminalBehavior ?? "replace",
    store: input.store,
    observer: input.observer ?? pendingObserver(),
    preparation: {
      async prepare() {
        input.counters.prepares += 1;
        return input.prepared;
      },
      async close() {
        input.counters.preparationCloses += 1;
      },
    },
    submission: {
      async openSubmission(snapshot: PreparedUserOperation) {
        input.counters.opens += 1;
        expect(snapshot).toEqual(input.prepared);
        if (input.open) return input.open(snapshot);
        return {
          submit,
          async close() {
            input.counters.sessionCloses += 1;
          },
        };
      },
      async close() {
        input.counters.submissionCloses += 1;
      },
    },
  });
}

function storedOperation(control: MemoryControl): Operation | undefined {
  return (control.raw as OperationStoreRecord | undefined)?.value;
}

function expectRunnerError(
  action: () => Promise<unknown>,
  code: OaathOperationRunnerError["code"],
): Promise<void> {
  return expect(action()).rejects.toMatchObject({ name: "OaathOperationRunnerError", code });
}

describe("OperationRunner", () => {
  it("rejects send authority or chain policy on the preparation boundary", () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    expect(() =>
      createOperationRunner({
        terminalBehavior: "replace",
        store: memoryStore(control),
        observer: pendingObserver(),
        preparation: {
          async prepare() {
            return prepared("execution");
          },
          async close() {},
          async send() {},
        },
        submission: {
          async openSubmission() {
            return null;
          },
          async close() {},
          supportedChains: [key.chainId],
        },
      }),
    ).toThrowError(expect.objectContaining({ code: "operation_runner_capability_invalid" }));
  });

  it("starts one submitted identity without invoking the observer", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    let observerReads = 0;
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      observer: pendingObserver(
        async () => {},
        () => {
          observerReads += 1;
        },
      ),
    });

    const result = await operationRunner.startOperation(runInput("execution"));

    expect(result).toMatchObject({
      status: "started",
      record: {
        value: {
          state: "submitted",
          observation: null,
          identity: { userOperationHash: prepared("execution").userOperationHash },
        },
      },
    });
    expect(observerReads).toBe(0);
    expect(count).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    await operationRunner.close();
  });

  it("keeps an ambiguous fresh start attempted without observing", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    let observerReads = 0;
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      observer: pendingObserver(
        async () => {},
        () => {
          observerReads += 1;
        },
      ),
      async submit() {
        count.sends += 1;
        throw new Error("private post-send ambiguity");
      },
    });

    const result = await operationRunner.startOperation(runInput("execution"));

    expect(result).toMatchObject({
      status: "submission_uncertain",
      reason: "send_ambiguous",
      record: { value: { state: "submission_attempted", observation: null } },
    });
    expect(observerReads).toBe(0);
    expect(count).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    await operationRunner.close();
  });

  it("rejects a fresh start on an occupied lane without another external effect", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    let observerReads = 0;
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      observer: pendingObserver(
        async () => {},
        () => {
          observerReads += 1;
        },
      ),
    });
    await operationRunner.startOperation(runInput("execution"));

    await expectRunnerError(
      () => operationRunner.startOperation(runInput("execution")),
      "operation_runner_state_conflict",
    );

    expect(observerReads).toBe(0);
    expect(count).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    expect(storedOperation(control)?.state).toBe("submitted");
    await operationRunner.close();
  });

  it("observes and advances only the exact started identity", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    const snapshot = prepared("execution");
    let observerReads = 0;
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: count,
      observer: pendingObserver(
        async () => {},
        () => {
          observerReads += 1;
        },
      ),
    });
    await operationRunner.startOperation(runInput("execution"));

    const result = await operationRunner.observeOperation({
      ...runInput("execution"),
      expectedUserOperationHash: snapshot.userOperationHash,
    });

    expect(result).toMatchObject({
      status: "observed",
      observation: { status: "pending", reason: "receipt_missing" },
      record: {
        value: {
          state: "submitted",
          identity: { userOperationHash: snapshot.userOperationHash },
          observation: { status: "pending", reason: "receipt_missing" },
        },
      },
    });
    expect(observerReads).toBeGreaterThan(0);
    expect(count).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    await operationRunner.close();
  });

  it("observes an archived terminal identity without preparing, opening, or sending", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const firstSnapshot = prepared("execution");
    const first = runner({
      store: memoryStore(control),
      prepared: firstSnapshot,
      counters: counters(),
      observer: terminalObserver("finalized"),
    });
    await expect(first.runOperation(runInput("execution"))).resolves.toMatchObject({
      status: "observed",
      record: { value: { state: "finalized" } },
    });

    const secondSnapshot = prepared("execution", "8");
    const second = runner({
      store: memoryStore(control),
      prepared: secondSnapshot,
      counters: counters(),
    });
    await second.runOperation({
      ...runInput("execution"),
      preparedAt: 20,
      attemptedAt: 21,
      submittedAt: 22,
      observedAt: 23,
    });
    expect(storedOperation(control)?.identity.userOperationHash).toBe(
      secondSnapshot.userOperationHash,
    );

    const staleCounters = counters();
    const stale = runner({
      store: memoryStore(control),
      prepared: firstSnapshot,
      counters: staleCounters,
      observer: {
        async observeOperation(inputValue) {
          const input = inputValue as { operation: Operation };
          if (input.operation.state !== "finalized") {
            throw new Error("expected archived finalized operation");
          }
          return { status: "finalized", operation: input.operation };
        },
        async close() {},
      },
    });
    const observed = await stale.observeOperation({
      ...runInput("execution"),
      preparedAt: 30,
      attemptedAt: 30,
      submittedAt: 30,
      observedAt: 30,
      expectedUserOperationHash: firstSnapshot.userOperationHash,
    });

    expect(observed).toMatchObject({
      status: "observed",
      record: {
        value: {
          state: "finalized",
          identity: { userOperationHash: firstSnapshot.userOperationHash },
        },
      },
    });
    expect(storedOperation(control)?.identity.userOperationHash).toBe(
      secondSnapshot.userOperationHash,
    );
    expect(staleCounters).toMatchObject({ prepares: 0, opens: 0, sends: 0 });
    await Promise.all([first.close(), second.close(), stale.close()]);
  });

  it("rejects absent and wrong-hash observations before every external effect", async () => {
    const snapshot = prepared("execution");
    const missingControl: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const missingCount = counters();
    let missingObserverReads = 0;
    const missing = runner({
      store: memoryStore(missingControl),
      prepared: snapshot,
      counters: missingCount,
      observer: pendingObserver(
        async () => {},
        () => {
          missingObserverReads += 1;
        },
      ),
    });
    await expectRunnerError(
      () =>
        missing.observeOperation({
          ...runInput("execution"),
          expectedUserOperationHash: snapshot.userOperationHash,
        }),
      "operation_runner_state_conflict",
    );
    expect(missingObserverReads).toBe(0);
    expect(missingCount).toMatchObject({ prepares: 0, opens: 0, sends: 0 });

    const occupiedControl: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const occupiedCount = counters();
    let occupiedObserverReads = 0;
    const occupied = runner({
      store: memoryStore(occupiedControl),
      prepared: snapshot,
      counters: occupiedCount,
      observer: pendingObserver(
        async () => {},
        () => {
          occupiedObserverReads += 1;
        },
      ),
    });
    await occupied.startOperation(runInput("execution"));
    await expectRunnerError(
      () =>
        occupied.observeOperation({
          ...runInput("execution"),
          expectedUserOperationHash: `0x${"ff".repeat(32)}`,
        }),
      "operation_runner_identity_mismatch",
    );
    expect(occupiedObserverReads).toBe(0);
    expect(occupiedCount).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    await Promise.all([missing.close(), occupied.close()]);
  });

  it("captures the expected observation hash without invoking an accessor", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    let hashReads = 0;
    let observerReads = 0;
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      observer: pendingObserver(
        async () => {},
        () => {
          observerReads += 1;
        },
      ),
    });
    const hostile = Object.defineProperty(
      { ...runInput("execution") },
      "expectedUserOperationHash",
      {
        enumerable: true,
        get() {
          hashReads += 1;
          return prepared("execution").userOperationHash;
        },
      },
    );

    await expectRunnerError(
      () => operationRunner.observeOperation(hostile),
      "operation_runner_input_invalid",
    );

    expect(hashReads).toBe(0);
    expect(observerReads).toBe(0);
    expect(count).toMatchObject({ prepares: 0, opens: 0, sends: 0 });
    await operationRunner.close();
  });

  it("fails closed when the observed identity is replaced before its CAS", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    const snapshot = prepared("execution");
    const replacement = prepared("execution", "8");
    let replaceDuringObservation = false;
    let observerCalls = 0;
    const observer: OperationObserver = {
      async observeOperation(inputValue) {
        observerCalls += 1;
        const input = inputValue as { operation: Operation; observedAt: number };
        const pending = applyVerifiedOperationObservation(input.operation, {
          type: "record_pending",
          identity: input.operation.identity,
          observedAt: input.observedAt,
          reason: "receipt_missing",
        });
        if (replaceDuringObservation) {
          const retained = control.raw as OperationStoreRecord;
          const replaced = createOperation({
            identity: deriveOperationId(replacement),
            preparedAt: input.observedAt,
          });
          control.raw = Object.freeze({
            ...retained,
            storeRevision: retained.storeRevision + 1,
            updatedAt: replaced.updatedAt,
            value: replaced,
          });
        }
        return { status: "pending", reason: "receipt_missing", operation: pending };
      },
      async close() {},
    };
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: count,
      observer,
    });
    await operationRunner.startOperation(runInput("execution"));
    replaceDuringObservation = true;

    await expectRunnerError(
      () =>
        operationRunner.observeOperation({
          ...runInput("execution"),
          expectedUserOperationHash: snapshot.userOperationHash,
        }),
      "operation_runner_state_conflict",
    );

    expect(observerCalls).toBe(1);
    expect(count).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    expect(storedOperation(control)?.identity.userOperationHash).toBe(
      replacement.userOperationHash,
    );
    await operationRunner.close();
  });

  it.each<OperationKind>(["execution", "revocation"])(
    "durably attempts before the %s signer and exact send",
    async (kind) => {
      const directory = await mkdtemp(join(tmpdir(), "oaath-runner-order-"));
      temporaryDirectories.push(directory);
      const filePath = join(directory, "store.db");
      const store = createSqliteOperationStore(filePath);
      const snapshot = prepared(kind);
      const count = counters();
      const operationRunner = runner({
        store,
        prepared: snapshot,
        counters: count,
        async open() {
          const independent = createSqliteOperationStore(filePath);
          expect((await independent.get({ ...key, kind }))?.value).toMatchObject({
            state: "submission_attempted",
            identity: { kind, userOperationHash: snapshot.userOperationHash },
          });
          await independent.close();
          return {
            async submit() {
              const beforeSend = createSqliteOperationStore(filePath);
              expect((await beforeSend.get({ ...key, kind }))?.value.state).toBe(
                "submission_attempted",
              );
              await beforeSend.close();
              count.sends += 1;
              return { userOperationHash: snapshot.userOperationHash };
            },
            async close() {
              count.sessionCloses += 1;
            },
          };
        },
      });

      const result = await operationRunner.runOperation(runInput(kind));

      expect(result).toMatchObject({
        status: "observed",
        observation: { status: "pending", reason: "receipt_missing" },
        record: { value: { state: "submitted", identity: { kind } } },
      });
      expect(count).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
      await operationRunner.close();
    },
  );

  it.each([
    ["prepared", "prepared", undefined, 0, 0],
    ["submission_attempted", "submission_attempted", "prepared", 0, 0],
    ["submitted", "submitted", "submission_attempted", 1, 1],
  ] as const)(
    "fails closed when the %s durable commit is uncertain",
    async (_boundary, faultState, expectedStoredState, expectedOpens, expectedSends) => {
      const control: MemoryControl = {
        closeFailures: 0,
        closeCalls: 0,
        fault: (next) => next.value.state === faultState,
      };
      const count = counters();
      const operationRunner = runner({
        store: memoryStore(control),
        prepared: prepared("execution"),
        counters: count,
      });

      await expectRunnerError(
        () => operationRunner.runOperation(runInput("execution")),
        "operation_runner_store_uncertain",
      );
      expect(count.opens).toBe(expectedOpens);
      expect(count.sends).toBe(expectedSends);
      expect(storedOperation(control)?.state).toBe(expectedStoredState);
    },
  );

  it("survives the true send/return gap and recreates observe-only with one send", async () => {
    const directory = await mkdtemp(join(tmpdir(), "oaath-runner-crash-"));
    temporaryDirectories.push(directory);
    const filePath = join(directory, "store.db");
    const snapshot = prepared("execution");
    const firstCount = counters();
    const first = runner({
      store: createSqliteOperationStore(filePath),
      prepared: snapshot,
      counters: firstCount,
      async submit() {
        firstCount.sends += 1;
        throw new Error("adapter died after external send");
      },
    });
    const ambiguous = await first.runOperation(runInput("execution"));
    expect(ambiguous).toMatchObject({
      status: "submission_uncertain",
      reason: "send_ambiguous",
      record: { value: { state: "submission_attempted" } },
    });
    expect(firstCount.sends).toBe(1);
    await first.close();

    const recreatedCount = counters();
    const recreated = runner({
      store: createSqliteOperationStore(filePath),
      prepared: snapshot,
      counters: recreatedCount,
    });
    const recovered = await recreated.runOperation({
      ...runInput("execution"),
      observedAt: 14,
    });
    expect(recovered).toMatchObject({
      status: "observed",
      observation: { status: "pending" },
      record: { value: { state: "submission_attempted" } },
    });
    expect(recreatedCount).toMatchObject({ prepares: 0, opens: 0, sends: 0 });
    expect(firstCount.sends + recreatedCount.sends).toBe(1);
    await recreated.close();
  });

  it("allows only exact re-preparation while the durable state is still prepared", async () => {
    const control: MemoryControl = {
      closeFailures: 0,
      closeCalls: 0,
      fault: (next) => next.value.state === "submission_attempted",
    };
    const firstCount = counters();
    const first = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: firstCount,
    });
    await expectRunnerError(
      () => first.runOperation(runInput("execution")),
      "operation_runner_store_uncertain",
    );
    expect(storedOperation(control)?.state).toBe("prepared");
    expect(firstCount.opens).toBe(0);

    delete control.fault;
    const changedCount = counters();
    const changed = runner({
      store: memoryStore(control),
      prepared: prepared("execution", "8"),
      counters: changedCount,
    });
    await expectRunnerError(
      () => changed.runOperation(runInput("execution")),
      "operation_runner_identity_mismatch",
    );
    expect(changedCount).toMatchObject({ prepares: 1, opens: 0, sends: 0 });
    expect(storedOperation(control)?.state).toBe("prepared");
  });

  it("resumes an exactly re-prepared durable prepared identity", async () => {
    const control: MemoryControl = {
      closeFailures: 0,
      closeCalls: 0,
      fault: (next) => next.value.state === "submission_attempted",
    };
    const snapshot = prepared("revocation");
    const first = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: counters(),
    });
    await expectRunnerError(
      () => first.runOperation(runInput("revocation")),
      "operation_runner_store_uncertain",
    );
    delete control.fault;

    const resumedCount = counters();
    const resumed = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: resumedCount,
    });
    const result = await resumed.runOperation(runInput("revocation"));
    expect(result).toMatchObject({
      status: "observed",
      record: { value: { state: "submitted", identity: { kind: "revocation" } } },
    });
    expect(resumedCount).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
  });

  it("lets only one independent SQLite runner win the attempted CAS and send", async () => {
    const directory = await mkdtemp(join(tmpdir(), "oaath-runner-race-"));
    temporaryDirectories.push(directory);
    const filePath = join(directory, "store.db");
    const snapshot = prepared("execution");
    const leftCount = counters();
    const rightCount = counters();
    const left = runner({
      store: createSqliteOperationStore(filePath),
      prepared: snapshot,
      counters: leftCount,
    });
    const right = runner({
      store: createSqliteOperationStore(filePath),
      prepared: snapshot,
      counters: rightCount,
    });

    await Promise.all([
      left.runOperation(runInput("execution")),
      right.runOperation(runInput("execution")),
    ]);

    expect(leftCount.sends + rightCount.sends).toBe(1);
    expect(leftCount.opens + rightCount.opens).toBe(1);
    const restored = createSqliteOperationStore(filePath);
    expect((await restored.get(key))?.value.state).not.toBe("prepared");
    await Promise.all([left.close(), right.close(), restored.close()]);
  });

  it.each([
    ["session unavailable", async () => Promise.reject(new Error("secret")), "session_unavailable"],
    ["session invalid", async () => ({ submit: async () => null }), "session_invalid"],
  ] as const)("keeps attempted observe-only when %s", async (_label, open, reason) => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      open,
    });
    const result = await operationRunner.runOperation(runInput("execution"));
    expect(result).toMatchObject({ status: "submission_uncertain", reason });
    expect(storedOperation(control)?.state).toBe("submission_attempted");
    expect(count.sends).toBe(0);
  });

  it("bounds an ambiguous submission timeout and keeps recreation observe-only", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      async submit() {
        count.sends += 1;
        return new Promise<never>(() => {});
      },
    });
    const result = await operationRunner.runOperation({
      ...runInput("execution"),
      timeoutMs: 5,
    });
    expect(result).toMatchObject({
      status: "submission_uncertain",
      reason: "send_ambiguous",
      record: { value: { state: "submission_attempted" } },
    });
    expect(count.sends).toBe(1);
    await operationRunner.runOperation({
      ...runInput("execution"),
      observedAt: 14,
      timeoutMs: 5,
    });
    expect(count.sends).toBe(1);
  });

  it.each([
    ["wrong hash", { userOperationHash: `0x${"ff".repeat(32)}` }, "identity_mismatch"],
    ["malformed hash", { userOperationHash: "0x1234" }, "result_invalid"],
    [
      "expanded result",
      { userOperationHash: `0x${"33".repeat(32)}`, extra: true },
      "result_invalid",
    ],
  ] as const)("never retries a %s submission result", async (_label, returned, reason) => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    const snapshot = prepared("execution");
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: count,
      async submit() {
        count.sends += 1;
        return returned;
      },
    });
    const result = await operationRunner.runOperation(runInput("execution"));
    expect(result).toMatchObject({ status: "submission_uncertain", reason });
    expect(storedOperation(control)?.state).toBe("submission_attempted");
    expect(count.sends).toBe(1);

    await operationRunner.runOperation({ ...runInput("execution"), observedAt: 14 });
    expect(count).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
  });

  it("rejects an accessor-backed submission result without reading the accessor", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    let reads = 0;
    const hostile = Object.defineProperty({}, "userOperationHash", {
      enumerable: true,
      get() {
        reads += 1;
        return prepared("execution").userOperationHash;
      },
    });
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      async submit() {
        count.sends += 1;
        return hostile;
      },
    });
    const result = await operationRunner.runOperation(runInput("execution"));
    expect(result).toMatchObject({
      status: "submission_uncertain",
      reason: "result_invalid",
    });
    expect(reads).toBe(0);
    expect(count.sends).toBe(1);
  });

  it("never resubmits when observation persistence is uncertain", async () => {
    const control: MemoryControl = {
      closeFailures: 0,
      closeCalls: 0,
      fault: (next) => next.value.state === "submitted" && next.value.observation !== null,
    };
    const snapshot = prepared("execution");
    const firstCount = counters();
    const first = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: firstCount,
    });
    await expectRunnerError(
      () => first.runOperation(runInput("execution")),
      "operation_runner_store_uncertain",
    );
    expect(firstCount.sends).toBe(1);
    expect(storedOperation(control)?.state).toBe("submitted");

    delete control.fault;
    const recreatedCount = counters();
    const recreated = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: recreatedCount,
    });
    await recreated.runOperation({ ...runInput("execution"), observedAt: 14 });
    expect(recreatedCount).toMatchObject({ prepares: 0, opens: 0, sends: 0 });
  });

  it("fails closed on an observer identity substitution without overwriting durable state", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    const observer: OperationObserver = {
      async observeOperation(inputValue) {
        const input = inputValue as { operation: Operation; observedAt: number };
        const pending = applyVerifiedOperationObservation(input.operation, {
          type: "record_pending",
          identity: input.operation.identity,
          observedAt: input.observedAt,
          reason: "receipt_missing",
        });
        return {
          status: "pending",
          reason: "receipt_missing",
          operation: {
            ...pending,
            identity: {
              ...pending.identity,
              userOperationHash: `0x${"ff".repeat(32)}`,
            },
          },
        };
      },
      async close() {},
    };
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      observer,
    });
    const result = await operationRunner.runOperation(runInput("execution"));
    expect(result).toMatchObject({
      status: "observation_unavailable",
      reason: "identity_mismatch",
      record: { value: { state: "submitted" } },
    });
    expect(storedOperation(control)).toMatchObject({
      state: "submitted",
      identity: { userOperationHash: prepared("execution").userOperationHash },
    });
    expect(count.sends).toBe(1);
  });

  it("rejects an observer lifecycle regression with the same exact identity", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    const observer: OperationObserver = {
      async observeOperation(inputValue) {
        const input = inputValue as { operation: Operation; observedAt: number };
        if (input.operation.state === "prepared") throw new Error("unexpected prepared state");
        const reset = createOperation({
          identity: input.operation.identity,
          preparedAt: input.operation.preparedAt,
        });
        const attempted = advanceOperation(reset, {
          type: "mark_submission_attempted",
          identity: reset.identity,
          attemptedAt: input.operation.attemptedAt,
        });
        const regressed = applyVerifiedOperationObservation(attempted, {
          type: "record_pending",
          identity: attempted.identity,
          observedAt: input.observedAt,
          reason: "receipt_missing",
        });
        return { status: "pending", reason: "receipt_missing", operation: regressed };
      },
      async close() {},
    };
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      observer,
    });

    const result = await operationRunner.runOperation(runInput("execution"));

    expect(result).toMatchObject({
      status: "observation_unavailable",
      reason: "result_invalid",
      record: { value: { state: "submitted" } },
    });
    expect(storedOperation(control)).toMatchObject({
      state: "submitted",
      revision: 2,
      observation: null,
    });
    expect(count.sends).toBe(1);
  });

  it("runs a revocation on its own lane while the execution lane is still occupied", async () => {
    // Kind is part of the lane key: owner-signed revocation work never queues
    // behind or replaces session-signed execution work on the same chain.
    const records = new Map<string, unknown>();
    const archives = new Map<string, unknown>();
    const lanedStore = () =>
      new OperationStore({
        async get(laneKey: unknown) {
          return records.get(JSON.stringify(laneKey));
        },
        async getArchived(input: { key: unknown; userOperationHash: string }) {
          return archives.get(JSON.stringify([input.key, input.userOperationHash]));
        },
        async compareAndSwap(input: {
          key: unknown;
          expectedStoreRevision: number | null;
          next: unknown;
          archive: Readonly<{ userOperationHash: string; record: unknown }> | null;
        }) {
          const lane = JSON.stringify(input.key);
          const current = records.get(lane) as OperationStoreRecord | undefined;
          if (
            (input.expectedStoreRevision === null && current !== undefined) ||
            (input.expectedStoreRevision !== null &&
              current?.storeRevision !== input.expectedStoreRevision)
          ) {
            return false;
          }
          if (input.archive !== null) {
            const archiveKey = JSON.stringify([input.key, input.archive.userOperationHash]);
            if (archives.has(archiveKey)) return false;
            archives.set(archiveKey, input.archive.record);
          }
          records.set(lane, input.next);
          return true;
        },
        async close() {},
      });

    const executionCount = counters();
    const executionRunner = runner({
      store: lanedStore(),
      prepared: prepared("execution"),
      counters: executionCount,
    });
    const executionResult = await executionRunner.runOperation(runInput("execution"));
    // Submitted and unobserved: the execution lane stays durably occupied.
    expect(executionResult).toMatchObject({
      status: "observed",
      observation: { status: "pending" },
      record: { value: { state: "submitted", identity: { kind: "execution" } } },
    });
    await executionRunner.close();

    const revocationCount = counters();
    const revocationRunner = runner({
      store: lanedStore(),
      prepared: prepared("revocation", "8"),
      counters: revocationCount,
    });
    const result = await revocationRunner.runOperation({
      ...runInput("revocation"),
      preparedAt: 20,
      attemptedAt: 21,
      submittedAt: 22,
      observedAt: 23,
    });
    expect(result).toMatchObject({
      status: "observed",
      record: { value: { state: "submitted", identity: { kind: "revocation", nonce: "8" } } },
    });
    expect(revocationCount).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    // Both lanes hold their own durable journal.
    expect(records.size).toBe(2);
    await revocationRunner.close();
  });

  it("never restarts the same exact identity after it becomes terminal", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const snapshot = prepared("execution");
    const first = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: counters(),
      observer: terminalObserver("finalized"),
    });
    await first.runOperation(runInput("execution"));
    await first.close();

    const repeatedCount = counters();
    const repeated = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: repeatedCount,
    });
    await expectRunnerError(
      () =>
        repeated.runOperation({
          ...runInput("execution"),
          preparedAt: 20,
          attemptedAt: 21,
          submittedAt: 22,
          observedAt: 23,
        }),
      "operation_runner_state_conflict",
    );
    expect(repeatedCount).toMatchObject({ prepares: 1, opens: 0, sends: 0 });
    expect(storedOperation(control)?.state).toBe("finalized");
  });

  it.each(["finalized", "dropped"] as const)(
    "reuses a %s revocation after SQLite recreation without preparing or sending again",
    async (terminal) => {
      const directory = await mkdtemp(join(tmpdir(), "oaath-runner-terminal-reuse-"));
      temporaryDirectories.push(directory);
      const filePath = join(directory, "store.db");
      const first = runner({
        store: createSqliteOperationStore(filePath),
        prepared: prepared("revocation"),
        counters: counters(),
        observer: terminalObserver(terminal),
        terminalBehavior: "reuse_same_kind",
      });
      await first.runOperation(runInput("revocation"));
      await first.close();

      const repeatedCount = counters();
      const repeated = runner({
        store: createSqliteOperationStore(filePath),
        prepared: prepared("revocation", "8"),
        counters: repeatedCount,
        terminalBehavior: "reuse_same_kind",
      });
      const result = await repeated.runOperation({
        ...runInput("revocation"),
        preparedAt: 20,
        attemptedAt: 21,
        submittedAt: 22,
        observedAt: 23,
      });

      expect(result).toMatchObject({
        status: "observed",
        observation: { status: terminal },
        record: { value: { state: terminal, identity: { kind: "revocation", nonce: "7" } } },
      });
      expect(repeatedCount).toMatchObject({ prepares: 0, opens: 0, sends: 0 });
      await repeated.close();
    },
  );

  it("lets only one independent runner publish and send after a terminal lane", async () => {
    const directory = await mkdtemp(join(tmpdir(), "oaath-runner-terminal-race-"));
    temporaryDirectories.push(directory);
    const filePath = join(directory, "store.db");
    const seed = runner({
      store: createSqliteOperationStore(filePath),
      prepared: prepared("execution"),
      counters: counters(),
      observer: terminalObserver("finalized"),
    });
    await seed.runOperation(runInput("execution"));
    await seed.close();

    const snapshot = prepared("revocation", "8");
    const leftCount = counters();
    const rightCount = counters();
    const left = runner({
      store: createSqliteOperationStore(filePath),
      prepared: snapshot,
      counters: leftCount,
    });
    const right = runner({
      store: createSqliteOperationStore(filePath),
      prepared: snapshot,
      counters: rightCount,
    });
    const nextInput = {
      kind: "revocation",
      key: { ...key, kind: "revocation" },
      preparedAt: 20,
      attemptedAt: 21,
      submittedAt: 22,
      observedAt: 23,
      timeoutMs: 1_000,
    } as const;

    await Promise.all([left.runOperation(nextInput), right.runOperation(nextInput)]);

    expect(leftCount.sends + rightCount.sends).toBe(1);
    expect(leftCount.opens + rightCount.opens).toBe(1);
    const restored = createSqliteOperationStore(filePath);
    expect(await restored.get({ ...key, kind: "revocation" })).toMatchObject({
      value: { identity: { kind: "revocation", nonce: "8" } },
    });
    await Promise.all([left.close(), right.close(), restored.close()]);
  });

  it("retries an exact prepared publish when a missing-lane race reveals a terminal record", async () => {
    const seedControl: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const seed = runner({
      store: memoryStore(seedControl),
      prepared: prepared("revocation"),
      counters: counters(),
      observer: terminalObserver("finalized"),
    });
    await seed.runOperation(runInput("revocation"));
    await seed.close();
    const terminalRecord = seedControl.raw as OperationStoreRecord;

    let retained: OperationStoreRecord | undefined;
    let archived: unknown;
    let injected = false;
    const store = new OperationStore({
      async get() {
        return retained;
      },
      async getArchived() {
        return archived;
      },
      async compareAndSwap(input: {
        expectedStoreRevision: number | null;
        next: unknown;
        archive: Readonly<{ record: unknown }> | null;
      }) {
        if (!injected) {
          injected = true;
          retained = terminalRecord;
          return false;
        }
        if (retained?.storeRevision !== input.expectedStoreRevision) return false;
        if (input.archive !== null) archived = input.archive.record;
        retained = input.next as OperationStoreRecord;
        return true;
      },
      async close() {},
    });
    const count = counters();
    const operationRunner = runner({
      store,
      prepared: prepared("revocation", "8"),
      counters: count,
    });

    const result = await operationRunner.runOperation({
      kind: "revocation",
      key: { ...key, kind: "revocation" },
      preparedAt: 20,
      attemptedAt: 21,
      submittedAt: 22,
      observedAt: 23,
      timeoutMs: 1_000,
    });

    expect(injected).toBe(true);
    expect(result).toMatchObject({
      status: "observed",
      record: { value: { state: "submitted", identity: { kind: "revocation", nonce: "8" } } },
    });
    expect(count).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    await operationRunner.close();
  });

  it("attempts every owned cleanup and retries only failed resources", async () => {
    const control: MemoryControl = { closeFailures: 1, closeCalls: 0 };
    const count = counters();
    let observerCloseFailures = 1;
    let observerCloses = 0;
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: prepared("execution"),
      counters: count,
      async submit() {
        count.sends += 1;
        throw new Error("primary send ambiguity");
      },
      observer: pendingObserver(async () => {
        observerCloses += 1;
        if (observerCloseFailures > 0) {
          observerCloseFailures -= 1;
          throw new Error("private observer close failure");
        }
      }),
    });

    const primary = await operationRunner.runOperation(runInput("execution"));
    expect(primary).toMatchObject({
      status: "submission_uncertain",
      reason: "send_ambiguous",
      record: { value: { state: "submission_attempted" } },
    });

    await expect(operationRunner.close()).rejects.toMatchObject({
      code: "operation_runner_close_failed",
    });
    expect(count).toMatchObject({
      preparationCloses: 1,
      submissionCloses: 1,
      sessionCloses: 1,
    });
    expect(observerCloses).toBe(1);
    expect(control.closeCalls).toBe(1);
    expect(storedOperation(control)?.state).toBe("submission_attempted");
    await expectRunnerError(
      () => operationRunner.runOperation(runInput("execution")),
      "operation_runner_closed",
    );

    await operationRunner.close();
    expect(count).toMatchObject({ preparationCloses: 1, submissionCloses: 1 });
    expect(observerCloses).toBe(2);
    expect(control.closeCalls).toBe(2);
    expect(storedOperation(control)?.state).toBe("submission_attempted");
  });

  it("drains an admitted run before closing any owned resource", async () => {
    const control: MemoryControl = { closeFailures: 0, closeCalls: 0 };
    const count = counters();
    let signalOpened: (() => void) | undefined;
    let releaseOpen: (() => void) | undefined;
    const opened = new Promise<void>((resolve) => {
      signalOpened = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      releaseOpen = resolve;
    });
    const snapshot = prepared("execution");
    const operationRunner = runner({
      store: memoryStore(control),
      prepared: snapshot,
      counters: count,
      async open() {
        signalOpened?.();
        await gate;
        return {
          async submit() {
            count.sends += 1;
            return { userOperationHash: snapshot.userOperationHash };
          },
          async close() {
            count.sessionCloses += 1;
          },
        };
      },
    });
    const running = operationRunner.runOperation(runInput("execution"));
    await opened;
    let closeFinished = false;
    const closing = operationRunner.close().then(() => {
      closeFinished = true;
    });
    await Promise.resolve();
    expect(closeFinished).toBe(false);
    expect(count).toMatchObject({
      preparationCloses: 0,
      submissionCloses: 0,
      sessionCloses: 0,
    });

    releaseOpen?.();
    await running;
    await closing;
    expect(count).toMatchObject({
      sends: 1,
      preparationCloses: 1,
      submissionCloses: 1,
      sessionCloses: 1,
    });
    expect(control.closeCalls).toBe(1);
  });
});
