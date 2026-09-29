import { hashTypedData } from "viem";
import { describe, expect, it } from "vitest";
import { parseKernelV33PermissionState } from "../src/kernel/permission/v33-revocation.js";
import {
  createKernelRuntime,
  kernelDeployment,
  kernelKey,
  kernelV33PermissionEnableTypedData,
  OAATH_KERNEL_V33_APPROVAL_VERSION,
  sessionOperator,
  verifyKernelPermissionRevocation,
} from "../src/kernel.js";

const empty = {
  currentNonce: "1",
  validationNonce: "0",
  hook: "0x0000000000000000000000000000000000000000",
  signer: "0x0000000000000000000000000000000000000000",
  permissionFlag: "0x0000",
  policies: [],
};

describe("v3.3 revocation state", () => {
  it("does not turn unreadable, contradictory, or wrapping nonce state into absence", () => {
    for (const state of [
      null,
      { ...empty, currentNonce: "0" },
      { ...empty, validationNonce: "2" },
      { ...empty, currentNonce: "4294967295", validationNonce: "4294967295" },
      { ...empty, policies: ["0x01"] },
    ]) {
      expect(() => parseKernelV33PermissionState(state)).toThrow();
    }
    expect(parseKernelV33PermissionState(empty).currentNonce).toBe("1");
  });

  it("reports replayable, active, revoked and unreadable from one finalized block", async () => {
    const account = "0x1111111111111111111111111111111111111111";
    const runtime = createKernelRuntime({
      deployment: kernelDeployment({ chainId: 143, kernelVersion: "0.3.3" }),
      reads: {
        read: async () => {
          throw new Error("unused");
        },
      },
      operator: sessionOperator({
        key: kernelKey({
          account: { address: account, sign: async () => "0x" },
          validator: kernelDeployment({ chainId: 143, kernelVersion: "0.3.3" }).ecdsaValidator,
        }),
        policies: [
          {
            kind: "call",
            permissions: [{ target: account, selector: "0x12345678", valueLimit: "0" }],
          },
        ],
      }),
    });
    if (runtime.validation.kind !== "permission") throw new Error("missing permission");
    const scope = {
      chainScope: "all",
      account,
      nonce: "1",
      permissionId: runtime.validation.permissionId,
      packages: runtime.packages,
    } as const;
    const approval = {
      ...scope,
      version: OAATH_KERNEL_V33_APPROVAL_VERSION,
      digest: hashTypedData(kernelV33PermissionEnableTypedData(scope)),
      enableSignature: "0x01",
    } as const;
    const installed = {
      currentNonce: "2",
      validationNonce: "1",
      hook: "0x0000000000000000000000000000000000000001",
      signer: runtime.packages[runtime.packages.length - 1]!.module,
      permissionFlag: "0x0002",
      policies: runtime.packages.slice(0, -1).map((entry) => `0x0002${entry.module.slice(2)}`),
    };
    const hash = `0x${"11".repeat(32)}` as const;
    let state: unknown = empty;
    let canonical = hash;
    let finality = true;
    const seen: string[] = [];
    const verify = () =>
      verifyKernelPermissionRevocation({
        approval,
        chainId: 143,
        now: () => 100,
        reads: {
          async read(request) {
            seen.push(request.type);
            if (request.type === "chain_id") return 143;
            if (request.type === "finalized_block") {
              if (!finality) throw new Error("finalized tag unsupported");
              return { number: "0x2", hash };
            }
            if (request.type === "canonical_block") return { number: "0x2", hash: canonical };
            if (request.type === "kernel_v33_permission_state") {
              expect(request).toMatchObject({
                account,
                permissionId: scope.permissionId,
                blockNumber: "2",
              });
              return state;
            }
            throw new Error("unexpected read");
          },
        },
      });
    // Absent before first use: the enable signature can still install it.
    expect(await verify()).toEqual({ status: "approval-replayable" });
    state = installed;
    expect(await verify()).toEqual({ status: "active" });
    state = { ...empty, currentNonce: "2", validationNonce: "1" };
    expect(await verify()).toEqual({
      status: "revoked",
      evidence: {
        permission: {
          chainId: 143,
          account,
          permissionId: scope.permissionId,
          kind: "permission_absent",
          blockNumber: "2",
          blockHash: hash,
          observedAt: 100,
        },
        installNonce: "2",
      },
    });
    for (const failure of [
      () => {
        canonical = `0x${"22".repeat(32)}`;
      },
      () => {
        finality = false;
      },
      () => {
        state = { ...installed, signer: `0x${"22".repeat(20)}` };
      },
      () => {
        state = undefined;
      },
    ]) {
      canonical = hash;
      finality = true;
      state = { ...empty, currentNonce: "2", validationNonce: "1" };
      failure();
      expect(await verify()).toEqual({ status: "unreadable" });
    }
    // Never a generic module query, an EntryPoint nonce, or any write.
    expect(new Set(seen)).toEqual(
      new Set(["chain_id", "finalized_block", "canonical_block", "kernel_v33_permission_state"]),
    );
    await expect(
      verifyKernelPermissionRevocation({
        approval: { ...approval, version: "oaath.unknown/v1" } as never,
        chainId: 143,
        reads: { read: async () => 143 },
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
  });
});
