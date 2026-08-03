import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  advanceGrant,
  createGrant,
  createKernelPermissionRevocationCoordinator,
  type Grant,
  type GrantIdentity,
  type KernelPermissionUninstallDescriptor,
  type LocalKernelPermissionUninstallAdapter,
  type OgpKernelPermissionRevocationError,
  type Operation,
  type OperationObserver,
  type PreparedUserOperation,
  prepareUserOperation,
} from "../src/index.js";
import { applyVerifiedOperationObservation } from "../src/operation.js";
import { createSqliteGrantStore, createSqliteOperationStore } from "../src/testing.js";

const chainId = 31_337;
const entryPoint = `0x${"11".repeat(20)}` as const;
const account = `0x${"22".repeat(20)}` as const;
const signer = `0x${"66".repeat(20)}` as const;
const operator = `0x${"77".repeat(20)}` as const;
const permissionId = "0x6eea81c7" as const;
const validationId = `0x02${permissionId.slice(2)}${"00".repeat(16)}` as const;
const inclusionBlockHash = `0x${"44".repeat(32)}` as const;
const finalityBlockHash = `0x${"55".repeat(32)}` as const;

const descriptor: KernelPermissionUninstallDescriptor = {
  kind: "kernel-v3.3-permission-uninstall",
  grantId: "revoke-grant",
  chainId,
  entryPoint,
  account,
  permissionId,
  validationId,
  signer,
  operator,
};

const identity: GrantIdentity = {
  grantId: descriptor.grantId,
  chainScope: "all",
  application: {
    applicationId: "ogp-tests",
    clientId: "kernel-revocation",
    origin: "https://revocation.example",
    deviceId: "revocation-device",
  },
  logicalAccount: {
    version: "ogp.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.3.3",
    factoryRoute: "kernel_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "ogp.owner-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"aa".repeat(20)}`,
    },
  },
  operatorCredential: {
    version: "ogp.operator-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"bb".repeat(20)}`,
  },
  policyHash: `0x${"cc".repeat(32)}`,
};

const binding = { chainId, account, permissionId } as const;
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function installedGrant(includeInstallation = true): Grant {
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
  grant = advanceGrant(grant, {
    type: "record_unmaterialized",
    identity,
    binding,
    recordedAt: 31,
  });
  grant = advanceGrant(grant, {
    type: "begin_materialization",
    identity,
    binding,
    startedAt: 32,
  });
  if (!includeInstallation) return grant;
  return advanceGrant(grant, {
    type: "record_installed",
    identity,
    binding,
    installation: {
      kind: "permission_present",
      ...binding,
      blockNumber: "10",
      blockHash: `0x${"33".repeat(32)}`,
      observedAt: 33,
    },
  });
}

function prepared(): PreparedUserOperation {
  return prepareUserOperation({
    kind: "revocation",
    grantId: descriptor.grantId,
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

function times(offset = 0) {
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

function counters() {
  return {
    prepares: 0,
    opens: 0,
    sends: 0,
    preparationCloses: 0,
    submissionCloses: 0,
    sessionCloses: 0,
  };
}
type AdapterCounters = ReturnType<typeof counters>;

function uninstallAdapter(input: {
  counters: AdapterCounters;
  beforePrepare?: () => Promise<void>;
  loseAcknowledgment?: boolean;
}): LocalKernelPermissionUninstallAdapter {
  const snapshot = prepared();
  let loseAcknowledgment = input.loseAcknowledgment ?? false;
  return {
    descriptor,
    preparation: {
      async prepare() {
        input.counters.prepares += 1;
        await input.beforePrepare?.();
        return snapshot;
      },
      async close() {
        input.counters.preparationCloses += 1;
      },
    },
    submission: {
      async openSubmission(value) {
        input.counters.opens += 1;
        expect(value).toEqual(snapshot);
        return {
          async submit() {
            input.counters.sends += 1;
            if (loseAcknowledgment) {
              loseAcknowledgment = false;
              throw new Error("private acknowledgement loss");
            }
            return { userOperationHash: snapshot.userOperationHash };
          },
          async close() {
            input.counters.sessionCloses += 1;
          },
        };
      },
      async close() {
        input.counters.submissionCloses += 1;
      },
    },
  };
}

function finalizedObserver(outcome: "success" | "reverted" = "success"): OperationObserver {
  return {
    async observeOperation(inputValue) {
      const input = inputValue as { operation: Operation; observedAt: number };
      if (input.operation.state === "finalized") {
        return { status: "finalized", operation: input.operation };
      }
      let operation = applyVerifiedOperationObservation(input.operation, {
        type: "record_included",
        identity: input.operation.identity,
        inclusion: {
          transactionHash: `0x${"77".repeat(32)}`,
          blockNumber: "20",
          blockHash: inclusionBlockHash,
          outcome,
          observedAt: input.observedAt,
        },
      });
      operation = applyVerifiedOperationObservation(operation, {
        type: "record_finalized",
        identity: operation.identity,
        finality: {
          blockNumber: "30",
          blockHash: finalityBlockHash,
          observedAt: input.observedAt,
        },
      });
      if (operation.state !== "finalized") throw new Error("expected finalized Operation");
      return { status: "finalized", operation };
    },
    async close() {},
  };
}

function pendingObserver(): OperationObserver {
  return {
    async observeOperation(inputValue) {
      const input = inputValue as { operation: Operation; observedAt: number };
      const operation = applyVerifiedOperationObservation(input.operation, {
        type: "record_pending",
        identity: input.operation.identity,
        observedAt: input.observedAt,
        reason: "receipt_missing",
      });
      return { status: "pending", reason: "receipt_missing", operation };
    },
    async close() {},
  };
}

function permissionObserver(input: {
  status: "absent" | "present" | "unreadable" | "throw";
  calls: { observe: number; close: number };
  closeFailures?: { remaining: number };
  beforeThrow?: (value: unknown) => Promise<void>;
}) {
  return {
    async observeRemoval(value: unknown) {
      input.calls.observe += 1;
      const operation = (value as { operation: Operation }).operation;
      if (operation.state !== "finalized") throw new Error("expected finalized Operation");
      if (input.status === "throw") {
        await input.beforeThrow?.(value);
        throw new Error("private observer failure");
      }
      if (input.status === "unreadable") {
        return { status: "unreadable", reason: "provider_unavailable", operation } as const;
      }
      return {
        status: input.status,
        evidence: {
          kind: input.status === "absent" ? "permission_absent" : "permission_present",
          ...binding,
          blockNumber: operation.inclusion.blockNumber,
          blockHash: operation.inclusion.blockHash,
          observedAt: (value as { permissionObservedAt?: number; observedAt: number }).observedAt,
        },
        operation,
      } as const;
    },
    async close() {
      input.calls.close += 1;
      if (input.closeFailures && input.closeFailures.remaining > 0) {
        input.closeFailures.remaining -= 1;
        throw new Error("private permission observer close failure");
      }
    },
  };
}

async function database(grant: Grant = installedGrant()) {
  const directory = await mkdtemp(join(tmpdir(), "ogp-kernel-revoke-"));
  temporaryDirectories.push(directory);
  const path = join(directory, "state.db");
  const seed = createSqliteGrantStore(path);
  const result = await seed.compareAndSwap({
    grantId: descriptor.grantId,
    expectedStoreRevision: null,
    next: grant,
  });
  expect(result.status).toBe("committed");
  await seed.close();
  return path;
}

async function expectCoordinatorError(
  action: () => Promise<unknown>,
  code: OgpKernelPermissionRevocationError["code"],
) {
  await expect(action()).rejects.toMatchObject({
    name: "OgpKernelPermissionRevocationError",
    code,
  });
}

function revoker(
  path: string,
  state: AdapterCounters,
  operationObserver: OperationObserver,
  removalObserver: ReturnType<typeof permissionObserver>,
  adapter = uninstallAdapter({ counters: state }),
) {
  return createKernelPermissionRevocationCoordinator({
    grantStore: createSqliteGrantStore(path),
    operationStore: createSqliteOperationStore(path),
    operationObserver,
    uninstall: adapter,
    permissionObserver: removalObserver,
  });
}

describe("Kernel permission revocation coordinator", () => {
  it("recovers an ambiguous send after recreation and revokes only from absence evidence", async () => {
    const path = await database();
    const state = counters();
    const firstRemoval = { observe: 0, close: 0 };
    let coordinator = revoker(
      path,
      state,
      pendingObserver(),
      permissionObserver({ status: "absent", calls: firstRemoval }),
      uninstallAdapter({
        counters: state,
        loseAcknowledgment: true,
        async beforePrepare() {
          const independent = createSqliteGrantStore(path);
          const durable = await independent.get(descriptor.grantId);
          await independent.close();
          expect(durable?.value).toMatchObject({
            state: "revoking",
            materializations: [{ chainId, state: "revoking" }],
          });
        },
      }),
    );

    const first = await coordinator.revoke(times());
    expect(first).toMatchObject({
      status: "submission_uncertain",
      reason: "send_ambiguous",
      grant: { value: { state: "revoking", materializations: [{ state: "revoking" }] } },
      operation: { value: { state: "submission_attempted" } },
    });
    expect(firstRemoval.observe).toBe(0);
    await coordinator.close();

    const secondRemoval = { observe: 0, close: 0 };
    coordinator = revoker(
      path,
      state,
      finalizedObserver(),
      permissionObserver({ status: "absent", calls: secondRemoval }),
    );
    const recovered = await coordinator.revoke(times(10));
    expect(recovered.status).toBe("revoked");
    expect(recovered.grant.value).toMatchObject({
      state: "revoking",
      materializations: [{ state: "revoked" }],
    });
    expect(secondRemoval.observe).toBe(1);
    expect(state).toMatchObject({ prepares: 1, opens: 1, sends: 1 });
    await coordinator.close();
  });

  it.each([
    ["present", "permission_present"],
    ["unreadable", "permission_unreadable"],
  ] as const)("never marks removal from %s permission state", async (permission, status) => {
    const path = await database();
    const state = counters();
    const calls = { observe: 0, close: 0 };
    const coordinator = revoker(
      path,
      state,
      finalizedObserver(),
      permissionObserver({ status: permission, calls }),
    );

    const result = await coordinator.revoke(times());
    expect(result.status).toBe(status);
    expect(result.grant.value.state).toBe("revoking");
    expect(result.grant.value.materializations[0]).toMatchObject(
      permission === "unreadable"
        ? { state: "unreadable", priorState: "revoking", reason: "provider_unavailable" }
        : { state: "revoking" },
    );
    expect(calls.observe).toBe(1);
    await coordinator.close();
  });

  it("rejects a revoking materialization without retained installation before preparation", async () => {
    let grant = installedGrant(false);
    grant = advanceGrant(grant, { type: "begin_revocation", identity, revocationStartedAt: 40 });
    grant = advanceGrant(grant, {
      type: "begin_chain_revocation",
      identity,
      binding,
      startedAt: 41,
    });
    const path = await database(grant);
    const state = counters();
    const coordinator = revoker(
      path,
      state,
      pendingObserver(),
      permissionObserver({
        status: "absent",
        calls: { observe: 0, close: 0 },
      }),
    );

    await expectCoordinatorError(
      () => coordinator.revoke(times(10)),
      "kernel_permission_revocation_state_conflict",
    );
    expect(state).toMatchObject({ prepares: 0, opens: 0, sends: 0 });
    await coordinator.close();
  });

  it("reports a concurrent authoritative revocation when permission observation throws", async () => {
    const path = await database();
    const state = counters();
    const coordinator = revoker(
      path,
      state,
      finalizedObserver(),
      permissionObserver({
        status: "throw",
        calls: { observe: 0, close: 0 },
        async beforeThrow(value) {
          const operation = (value as { operation: Operation }).operation;
          if (operation.state !== "finalized") throw new Error("not finalized");
          const independent = createSqliteGrantStore(path);
          const current = await independent.get(descriptor.grantId);
          if (!current) throw new Error("missing Grant");
          await independent.compareAndSwap({
            grantId: descriptor.grantId,
            expectedStoreRevision: current.storeRevision,
            next: advanceGrant(current.value, {
              type: "record_chain_revoked",
              identity,
              binding,
              removal: {
                kind: "permission_absent",
                ...binding,
                blockNumber: operation.inclusion.blockNumber,
                blockHash: operation.inclusion.blockHash,
                observedAt: 46,
              },
            }),
          });
          await independent.close();
        },
      }),
    );

    expect(await coordinator.revoke(times())).toMatchObject({
      status: "revoked",
      grant: { value: { state: "revoking", materializations: [{ state: "revoked" }] } },
    });
    await coordinator.close();
  });

  it("rejects registries, cleanup effects, and a descriptor that does not bind the Grant", async () => {
    const path = await database();
    const state = counters();
    const calls = { observe: 0, close: 0 };
    expect(() =>
      createKernelPermissionRevocationCoordinator({
        grantStore: createSqliteGrantStore(path),
        operationStore: createSqliteOperationStore(path),
        operationObserver: pendingObserver(),
        uninstall: uninstallAdapter({ counters: state }),
        permissionObserver: permissionObserver({ status: "absent", calls }),
        supportedChains: [chainId],
      }),
    ).toThrowError(
      expect.objectContaining({
        name: "OgpKernelPermissionRevocationError",
        code: "kernel_permission_revocation_capability_invalid",
      }),
    );

    const coordinator = createKernelPermissionRevocationCoordinator({
      grantStore: createSqliteGrantStore(path),
      operationStore: createSqliteOperationStore(path),
      operationObserver: pendingObserver(),
      uninstall: {
        ...uninstallAdapter({ counters: state }),
        descriptor: { ...descriptor, account: signer },
      },
      permissionObserver: permissionObserver({ status: "absent", calls }),
    });
    await expectCoordinatorError(
      () =>
        coordinator.revoke({
          ...times(),
          forgetLocal: true,
          signOut: true,
        }),
      "kernel_permission_revocation_input_invalid",
    );
    await expectCoordinatorError(
      () => coordinator.revoke(times()),
      "kernel_permission_revocation_identity_mismatch",
    );
    await coordinator.close();
  });

  it("keeps cleanup separate, attempts every owner, and retries failed cleanup", async () => {
    const path = await database();
    const state = counters();
    const calls = { observe: 0, close: 0 };
    const closeFailures = { remaining: 1 };
    const coordinator = revoker(
      path,
      state,
      finalizedObserver("reverted"),
      permissionObserver({
        status: "absent",
        calls,
        closeFailures,
      }),
    );
    const result = await coordinator.revoke(times());
    expect(result).toMatchObject({ status: "operation_failed", reason: "operation_reverted" });
    expect(calls.observe).toBe(0);

    await expectCoordinatorError(
      () => coordinator.close(),
      "kernel_permission_revocation_close_failed",
    );
    expect(calls.close).toBe(1);
    expect({ preparation: state.preparationCloses, submission: state.submissionCloses }).toEqual({
      preparation: 1,
      submission: 1,
    });
    await coordinator.close();
    expect(calls.close).toBe(2);

    const restored = createSqliteGrantStore(path);
    expect(await restored.get(descriptor.grantId)).toMatchObject({
      value: { state: "revoking", materializations: [{ state: "revoking" }] },
    });
    await restored.close();
  });
});
