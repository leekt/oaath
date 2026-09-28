import { hashTypedData } from "viem";
import { describe, expect, it } from "vitest";
import { observeKernelPermissionRevocation } from "../src/kernel/permission/observe-revocation.js";
import { parseKernelV33PermissionState } from "../src/kernel/permission/v33-revocation.js";
import {
  createKernelRuntime,
  ecdsaKey,
  kernelV33Deployment,
  kernelV33PermissionEnableTypedData,
  OAATH_KERNEL_V33_APPROVAL_VERSION,
  sessionOperator,
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

  it("requires finalized absence and consumed nonce, not v3.3's false generic module query", async () => {
    const account = "0x1111111111111111111111111111111111111111";
    const runtime = createKernelRuntime({
      deployment: kernelV33Deployment(143),
      reads: {
        read: async () => {
          throw new Error("unused");
        },
      },
      operator: sessionOperator({
        key: ecdsaKey({
          account: { address: account, sign: async () => "0x" },
          validator: kernelV33Deployment(143).ecdsaValidator,
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
    const binding = { chainId: 143, account, permissionId: scope.permissionId } as const;
    const hash = `0x${"11".repeat(32)}` as const;
    let state: unknown = empty;
    let canonical = hash;
    let genericReads = 0;
    const input = {
      binding,
      approval,
      now: () => 100,
      observation: {
        async read(request: { type: string }) {
          if (request.type === "chain_id") return 143;
          if (request.type === "finalized_block") return { number: "0x2", hash };
          if (request.type === "canonical_block") return { number: "0x2", hash: canonical };
          if (request.type === "kernel_v33_permission_state") return state;
          if (request.type === "kernel_permission_installed") {
            genericReads++;
            return false;
          }
          throw new Error("unexpected read");
        },
        async close() {},
      },
    };
    expect(await observeKernelPermissionRevocation(input)).toBeNull();
    state = { ...empty, validationNonce: "1" };
    expect(await observeKernelPermissionRevocation(input)).toMatchObject({
      installNonce: "2",
      permission: { kind: "permission_absent", blockNumber: "2" },
    });
    canonical = `0x${"22".repeat(32)}`;
    expect(await observeKernelPermissionRevocation(input)).toBeNull();
    canonical = hash;
    state = { ...empty, validationNonce: "1", signer: runtime.authorityModule };
    expect(await observeKernelPermissionRevocation(input)).toBeNull();
    state = undefined;
    expect(await observeKernelPermissionRevocation(input)).toBeNull();
    expect(genericReads).toBe(0);
  });
});
