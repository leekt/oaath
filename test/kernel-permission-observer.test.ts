import { describe, expect, it } from "vitest";
import {
  advanceOperation,
  createKernelPermissionRemovalObserver,
  createOperation,
  type FinalizedOperation,
  type KernelPermissionStateReadRequest,
  type KernelPermissionUninstallDescriptor,
  type OgpKernelPermissionObserverError,
  type Operation,
} from "../src/index.js";
import { applyVerifiedOperationObservation } from "../src/operation.js";

const chainId = 31_337;
const entryPoint = `0x${"11".repeat(20)}` as const;
const account = `0x${"22".repeat(20)}` as const;
const signer = `0x${"66".repeat(20)}` as const;
const operator = `0x${"77".repeat(20)}` as const;
const zeroAddress = `0x${"00".repeat(20)}` as const;
const noHook = `0x${"00".repeat(19)}01` as const;
const inclusionHash = `0x${"44".repeat(32)}` as const;
const transactionHash = `0x${"55".repeat(32)}` as const;
const finalityHash = `0x${"66".repeat(32)}` as const;

const descriptor: KernelPermissionUninstallDescriptor = {
  kind: "kernel-v3.3-permission-uninstall",
  grantId: "permission-observer-grant",
  chainId,
  entryPoint,
  account,
  permissionId: "0x6eea81c7",
  validationId: "0x026eea81c700000000000000000000000000000000",
  signer,
  operator,
};

function includedOperation(outcome: "success" | "reverted" = "success"): Operation {
  let value: Operation = createOperation({
    identity: {
      kind: "revocation",
      grantId: descriptor.grantId,
      chainId,
      entryPoint,
      account,
      nonce: "7",
      userOperationHash: `0x${"33".repeat(32)}`,
    },
    preparedAt: 10,
  });
  value = advanceOperation(value, {
    type: "mark_submission_attempted",
    identity: value.identity,
    attemptedAt: 11,
  });
  value = advanceOperation(value, {
    type: "mark_submitted",
    identity: value.identity,
    returnedUserOperationHash: value.identity.userOperationHash,
    submittedAt: 12,
  });
  return applyVerifiedOperationObservation(value, {
    type: "record_included",
    identity: value.identity,
    inclusion: {
      transactionHash,
      blockNumber: "20",
      blockHash: inclusionHash,
      outcome,
      observedAt: 13,
    },
  });
}

function operation(outcome: "success" | "reverted" = "success"): FinalizedOperation {
  let value = includedOperation(outcome);
  value = applyVerifiedOperationObservation(value, {
    type: "record_finalized",
    identity: value.identity,
    finality: { blockNumber: "30", blockHash: finalityHash, observedAt: 14 },
  });
  if (value.state !== "finalized") throw new Error("expected finalized operation");
  return value;
}

interface Control {
  reads: KernelPermissionStateReadRequest[];
  result: "present" | "absent" | "partial";
  override?: (request: KernelPermissionStateReadRequest) => unknown;
  failReads: number;
  closeCalls: number;
  closeFailures: number;
}

function control(): Control {
  return {
    reads: [],
    result: "absent",
    failReads: 0,
    closeCalls: 0,
    closeFailures: 0,
  };
}

function observer(state: Control) {
  return createKernelPermissionRemovalObserver({
    async read(request: KernelPermissionStateReadRequest) {
      state.reads.push(request);
      if (state.failReads > 0) {
        state.failReads -= 1;
        throw new Error("private RPC failure");
      }
      if (state.override) {
        const overridden = state.override(request);
        if (overridden !== undefined) return overridden;
      }
      const common = {
        chainId,
        account,
        blockNumber: "20",
        blockHash: inclusionHash,
        requireCanonical: true,
      } as const;
      if (request.type === "code") return { ...common, code: "0x01" };
      if (request.type === "kernel_validation_config") {
        return {
          ...common,
          validationId: descriptor.validationId,
          nonce: "1",
          hook: state.result === "present" || state.result === "partial" ? noHook : zeroAddress,
        };
      }
      return {
        ...common,
        permissionId: descriptor.permissionId,
        permissionFlag: "0x0000",
        signer: state.result === "present" ? signer : zeroAddress,
        policyCount: 0,
      };
    },
    async close() {
      state.closeCalls += 1;
      if (state.closeFailures > 0) {
        state.closeFailures -= 1;
        throw new Error("private close failure");
      }
    },
  });
}

async function expectObserverError(
  action: () => Promise<unknown>,
  code: OgpKernelPermissionObserverError["code"],
) {
  await expect(action()).rejects.toMatchObject({
    name: "OgpKernelPermissionObserverError",
    code,
  });
}

describe("Kernel permission removal observer", () => {
  it.each(["absent", "present"] as const)(
    "classifies exact %s authority at the finalized operation inclusion block",
    async (status) => {
      const state = control();
      state.result = status;
      const permissionObserver = observer(state);

      const result = await permissionObserver.observeRemoval({
        descriptor,
        operation: operation(),
        observedAt: 15,
        timeoutMs: 1_000,
      });

      expect(result).toMatchObject({
        status,
        evidence: {
          kind: status === "absent" ? "permission_absent" : "permission_present",
          chainId,
          account,
          permissionId: descriptor.permissionId,
          blockNumber: "20",
          blockHash: inclusionHash,
          observedAt: 15,
        },
        operation: {
          state: "finalized",
          inclusion: { transactionHash, outcome: "success" },
          finality: { blockNumber: "30", blockHash: finalityHash },
        },
      });
      expect(state.reads).toEqual([
        {
          type: "code",
          chainId,
          account,
          blockNumber: "20",
          blockHash: inclusionHash,
          requireCanonical: true,
        },
        {
          type: "kernel_validation_config",
          chainId,
          account,
          validationId: descriptor.validationId,
          blockNumber: "20",
          blockHash: inclusionHash,
          requireCanonical: true,
        },
        {
          type: "kernel_permission_config",
          chainId,
          account,
          permissionId: descriptor.permissionId,
          blockNumber: "20",
          blockHash: inclusionHash,
          requireCanonical: true,
        },
      ]);
      expect(Object.isFrozen(result)).toBe(true);
    },
  );

  it("does not treat receipt inclusion or a reverted final Operation as removal authority", async () => {
    const state = control();
    const permissionObserver = observer(state);

    await expect(
      permissionObserver.observeRemoval({
        descriptor,
        operation: includedOperation(),
        observedAt: 15,
        timeoutMs: 1_000,
      }),
    ).resolves.toMatchObject({ status: "operation_unresolved" });
    await expect(
      permissionObserver.observeRemoval({
        descriptor,
        operation: operation("reverted"),
        observedAt: 15,
        timeoutMs: 1_000,
      }),
    ).resolves.toMatchObject({ status: "operation_failed", reason: "operation_reverted" });
    expect(state.reads).toHaveLength(0);
  });

  it.each([
    ["grantId", "another-grant"],
    ["chainId", chainId + 1],
    ["entryPoint", `0x${"88".repeat(20)}`],
    ["account", `0x${"99".repeat(20)}`],
    ["kind", "execution"],
  ] as const)(
    "rejects substituted Operation identity field %s before reads",
    async (field, value) => {
      const state = control();
      const permissionObserver = observer(state);
      const exact = operation();
      const substituted = {
        ...exact,
        identity: { ...exact.identity, [field]: value },
      };

      await expectObserverError(
        () =>
          permissionObserver.observeRemoval({
            descriptor,
            operation: substituted,
            observedAt: 15,
            timeoutMs: 1_000,
          }),
        "kernel_permission_observer_identity_mismatch",
      );
      expect(state.reads).toHaveLength(0);
    },
  );

  it("keeps provider, hostile, canonicality, missing-code, and partial state unreadable", async () => {
    const cases: Array<{
      expected: "provider_unavailable" | "state_invalid" | "canonicality_unproven";
      configure: (state: Control) => void;
    }> = [
      { expected: "provider_unavailable", configure: (state) => (state.failReads = 1) },
      {
        expected: "state_invalid",
        configure: (state) => {
          state.override = () =>
            new Proxy(
              {},
              {
                ownKeys() {
                  throw new Error("private provider detail");
                },
              },
            );
        },
      },
      {
        expected: "canonicality_unproven",
        configure: (state) => {
          state.override = (request) => ({
            chainId,
            account,
            blockNumber: request.blockNumber,
            blockHash: `0x${"aa".repeat(32)}`,
            requireCanonical: true,
            code: "0x01",
          });
        },
      },
      {
        expected: "state_invalid",
        configure: (state) => {
          state.override = () => ({
            chainId,
            account,
            blockNumber: "20",
            blockHash: inclusionHash,
            requireCanonical: true,
            code: "0x",
          });
        },
      },
      {
        expected: "state_invalid",
        configure: (state) => {
          state.override = (request) =>
            request.type === "kernel_permission_config"
              ? {
                  chainId,
                  account,
                  permissionId: descriptor.permissionId,
                  blockNumber: "20",
                  blockHash: inclusionHash,
                  requireCanonical: true,
                  permissionFlag: "0x0000",
                  signer: zeroAddress,
                  policyCount: -0,
                }
              : undefined;
        },
      },
      { expected: "state_invalid", configure: (state) => (state.result = "partial") },
    ];

    for (const testCase of cases) {
      const state = control();
      testCase.configure(state);
      const result = await observer(state).observeRemoval({
        descriptor,
        operation: operation(),
        observedAt: 15,
        timeoutMs: 1_000,
      });
      expect(result).toMatchObject({ status: "unreadable", reason: testCase.expected });
    }
  });

  it("rejects registry-shaped capabilities and retries failed cleanup", async () => {
    expect(() =>
      createKernelPermissionRemovalObserver({
        read: async () => null,
        close: async () => {},
        supportedChains: [chainId],
      }),
    ).toThrowError(
      expect.objectContaining({ code: "kernel_permission_observer_capability_invalid" }),
    );

    const state = control();
    state.closeFailures = 1;
    const permissionObserver = observer(state);
    await expectObserverError(
      () => permissionObserver.close(),
      "kernel_permission_observer_close_failed",
    );
    await permissionObserver.close();
    expect(state.closeCalls).toBe(2);
  });
});
