import type { OperationIdentity, OperationInclusion } from "@oaath/protocol";
import { encodeFunctionData, type Hex } from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import { encodeKernelV4Execution, KERNEL_V4_ENTRY_POINT_V07 } from "../src/kernel-v4.js";
import { verifyOperationExecutionEvidence } from "../src/operation-execution.js";

const account = `0x${"11".repeat(20)}` as const;
const target = `0x${"22".repeat(20)}` as const;
const transactionHash = `0x${"33".repeat(32)}` as const;
const blockHash = `0x${"44".repeat(32)}` as const;
const calls = Object.freeze([
  Object.freeze({ target, value: "7", data: "0x12345678" as const }),
  Object.freeze({ target: account, value: "0", data: "0x" as const }),
]);
const inclusion: Readonly<OperationInclusion> = Object.freeze({
  transactionHash,
  blockHash,
  blockNumber: "20",
  outcome: "success",
  observedAt: 100,
});

function fixture(callData: Hex = encodeKernelV4Execution({ calls }), aggregated = false) {
  const operation: UserOperation<"0.7"> = {
    sender: account,
    nonce: 7n,
    callData,
    callGasLimit: 100_000n,
    verificationGasLimit: 200_000n,
    preVerificationGas: 50_000n,
    maxFeePerGas: 2n,
    maxPriorityFeePerGas: 1n,
    signature: "0x",
  };
  const identity: Readonly<OperationIdentity> = {
    kind: "execution",
    grantId: "execution-evidence",
    chainId: 31337,
    entryPoint: KERNEL_V4_ENTRY_POINT_V07,
    account,
    nonce: "7",
    requestHash: null,
    userOperationHash: getUserOperationHash({
      chainId: 31337,
      entryPointAddress: KERNEL_V4_ENTRY_POINT_V07,
      entryPointVersion: "0.7",
      userOperation: operation,
    }),
  };
  const packed = toPackedUserOperation(operation);
  const prior = { ...packed, nonce: 6n };
  const next = { ...packed, nonce: 8n };
  const data = aggregated
    ? encodeFunctionData({
        abi: entryPoint07Abi,
        functionName: "handleAggregatedOps",
        args: [[{ userOps: [prior, packed, next], aggregator: target, signature: "0x" }], target],
      })
    : encodeFunctionData({
        abi: entryPoint07Abi,
        functionName: "handleOps",
        args: [[prior, packed, next], target],
      });
  const transaction = {
    hash: transactionHash,
    to: KERNEL_V4_ENTRY_POINT_V07,
    blockNumber: "0x14",
    blockHash,
    input: data,
  };
  return { identity, inclusion, transaction, packed };
}

describe("exact finalized execution calldata", () => {
  it.each([false, true])(
    "selects the exact operation from a batch (aggregated=%s)",
    (aggregated) => {
      const facts = verifyOperationExecutionEvidence(fixture(undefined, aggregated));
      expect(facts).toEqual({ sender: account, calls });
      expect(Object.isFrozen(facts)).toBe(true);
      expect(Object.isFrozen(facts.calls)).toBe(true);
      expect(facts.calls.every(Object.isFrozen)).toBe(true);
    },
  );

  it.each([1, 2])("decodes %s calls with enforced validity time range", (count) => {
    const selected = calls.slice(0, count);
    const data = encodeKernelV4Execution({
      calls: selected,
      validityTimeRange: { validAfter: "1", validUntil: "200" },
    });
    expect(verifyOperationExecutionEvidence(fixture(data)).calls).toEqual(selected);
  });

  it("decodes the canonical single-call form", () => {
    expect(
      verifyOperationExecutionEvidence(
        fixture(encodeKernelV4Execution({ calls: calls.slice(0, 1) })),
      ).calls,
    ).toEqual(calls.slice(0, 1));
  });

  it.each(["chainId", "entryPoint", "account", "nonce", "userOperationHash"] as const)(
    "rejects a mismatched %s",
    (field) => {
      const value = fixture();
      const replacements = {
        chainId: 1,
        entryPoint: target,
        account: target,
        nonce: "8",
        userOperationHash: transactionHash,
      };
      expect(() =>
        verifyOperationExecutionEvidence({
          ...value,
          identity: { ...value.identity, [field]: replacements[field] },
        }),
      ).toThrow();
    },
  );

  it.each(["hash", "to", "blockNumber", "blockHash"] as const)(
    "rejects mismatched transaction %s",
    (field) => {
      const value = fixture();
      const replacements = {
        hash: blockHash,
        to: target,
        blockNumber: "0x15",
        blockHash: transactionHash,
      };
      expect(() =>
        verifyOperationExecutionEvidence({
          ...value,
          transaction: { ...value.transaction, [field]: replacements[field] },
        }),
      ).toThrow();
    },
  );

  it("rejects duplicates instead of choosing an ambiguous occurrence", () => {
    const value = fixture();
    const input = encodeFunctionData({
      abi: entryPoint07Abi,
      functionName: "handleOps",
      args: [[value.packed, value.packed], target],
    });
    expect(() =>
      verifyOperationExecutionEvidence({ ...value, transaction: { ...value.transaction, input } }),
    ).toThrow();
  });

  it("rejects changed calls even when the receipt claims the original operation", () => {
    const value = fixture();
    const changed = {
      ...value.packed,
      callData: encodeKernelV4Execution({ calls: [{ target, data: "0x12345678", value: "8" }] }),
    };
    const input = encodeFunctionData({
      abi: entryPoint07Abi,
      functionName: "handleOps",
      args: [[changed], target],
    });
    expect(() =>
      verifyOperationExecutionEvidence({ ...value, transaction: { ...value.transaction, input } }),
    ).toThrow();
  });

  it.each(["0x", "0x12345678"] as const)("rejects unsupported Kernel calldata %s", (data) => {
    expect(() => verifyOperationExecutionEvidence(fixture(data))).toThrow();
  });

  it("rejects try-execution modes and trailing noncanonical data", () => {
    const encoded = encodeKernelV4Execution({ calls });
    const tryMode = `${encoded.slice(0, 12)}01${encoded.slice(14)}` as Hex;
    expect(() => verifyOperationExecutionEvidence(fixture(tryMode))).toThrow();
    expect(() => verifyOperationExecutionEvidence(fixture(`${encoded}00`))).toThrow();
  });
});
