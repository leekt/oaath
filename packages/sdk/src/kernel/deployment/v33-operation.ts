import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { getSigningHash } from "cetane/execution/erc4337";
import { keccak256, stringToHex } from "cetane/utils";
import {
  encodeKernelV4Execution,
  encodeKernelV4Nonce,
  encodeKernelV4NonceKey,
  type KernelUserOperationGas,
  type KernelValidation,
} from "../../kernel-v4.js";
import {
  asCetaneUserOperation,
  type PreparedUserOperation,
  parsePreparedUserOperation,
  prepareUserOperation,
} from "../../prepared-user-operation.js";
import { applyKernelGasPolicy, type KernelGasPolicy } from "../gas-policy.js";
import { exactInput, inputInvalid, runtimeFail } from "../internal.js";
import type { KernelV33RuntimePrepareInput } from "../types.js";
import { provenKernelV33Account } from "./v33.js";

/** Kernel v3.3's signature marker selects its chain-zero enable domain and operation hash. */
export const KERNEL_V33_REPLAYABLE_SIGNATURE_PREFIX = keccak256(
  stringToHex("kernel.replayable.signature"),
);

/**
 * Digest verified by Kernel v3.3, without changing the prepared operation's
 * chain-specific EntryPoint hash or durable identity. Enable always uses the
 * native replayable path; installed sessions and owners sign the actual hash.
 */
export function kernelV33OperationSigningHash(value: unknown): `0x${string}` {
  const prepared = parsePreparedUserOperation(value);
  const mode = BigInt(prepared.userOperation.nonce) >> 248n;
  if (mode === 0n) return prepared.userOperationHash;
  if (mode !== 1n || ((BigInt(prepared.userOperation.nonce) >> 240n) & 0xffn) !== 2n)
    return inputInvalid("Kernel v3.3 signing mode is unsupported");
  return getSigningHash(
    asCetaneUserOperation(prepared.userOperation),
    0,
    prepared.entryPoint.address,
    prepared.entryPoint.version,
  );
}

/** v3.3 uses mode 0x01 for enable; its validation/namespace layout matches v4. */
export function encodeKernelV33NonceKey(value: {
  mode: "standard" | "enable";
  validation: Readonly<KernelValidation>;
  nonceKey: string;
}): string {
  const input = exactInput(
    value,
    ["mode", "validation", "nonceKey"],
    "Kernel v3.3 nonce key",
    new WeakSet(),
  );
  if (input.mode !== "standard" && input.mode !== "enable")
    return inputInvalid("Kernel v3.3 validation mode is unsupported");
  const key = BigInt(
    encodeKernelV4NonceKey({
      mode: "standard",
      validation: input.validation as KernelValidation,
      nonceKey: input.nonceKey as string,
    }),
  );
  if (input.mode === "enable" && ((key >> 176n) & 0xffn) !== 2n)
    return inputInvalid("Kernel v3.3 enable requires permission authority");
  return (key | (input.mode === "enable" ? 1n << 184n : 0n)).toString(10);
}

export function prepareKernelV33Operation(
  value: KernelV33RuntimePrepareInput,
  validation: Readonly<KernelValidation>,
  gasPolicy: Readonly<KernelGasPolicy>,
): PreparedUserOperation {
  const context: CaptureContext = new WeakSet();
  const captured = captureRecord(value, "Kernel v3.3 operation", context, inputInvalid);
  const optional = ["mode", "paymaster"].filter((key) => Object.hasOwn(captured, key));
  const record = exactCapturedRecord(
    captured,
    ["account", "kind", "grantId", "nonceKey", "sequence", "calls", "gas", ...optional],
    "Kernel v3.3 operation",
    inputInvalid,
  );
  const mode = (record.mode === undefined ? "standard" : record.mode) as "standard" | "enable";
  return encodeKernelV33Operation(
    record,
    { mode, validation, nonceKey: record.nonceKey, sequence: record.sequence },
    (gas) => applyKernelGasPolicy(gas, mode, gasPolicy),
    context,
  );
}

/**
 * One v3.3 UserOperation from an explicit validation binding and exact gas, with
 * no gas policy applied: the version-agnostic `prepareKernelUserOperation`
 * reaches this for a v3.3 account.
 */
export function prepareKernelV33UserOperation(value: unknown): PreparedUserOperation {
  const context: CaptureContext = new WeakSet();
  const captured = captureRecord(value, "Kernel v3.3 UserOperation", context, inputInvalid);
  if (Object.hasOwn(captured, "validityTimeRange"))
    return runtimeFail(
      "kernel_runtime_unsupported",
      "Kernel v3.3 has no OAAth validity policy for a requested time range",
    );
  const record = exactCapturedRecord(
    captured,
    [
      "kind",
      "grantId",
      "account",
      "nonce",
      "calls",
      "gas",
      ...(Object.hasOwn(captured, "paymaster") ? ["paymaster"] : []),
    ],
    "Kernel v3.3 UserOperation",
    inputInvalid,
  );
  const nonce = exactInput(
    record.nonce,
    ["mode", "validation", "nonceKey", "sequence"],
    "Kernel v3.3 UserOperation nonce",
    context,
  );
  if (nonce.mode !== "standard" && nonce.mode !== "enable")
    return inputInvalid("Kernel v3.3 validation mode is unsupported");
  return encodeKernelV33Operation(
    record,
    {
      mode: nonce.mode,
      validation: nonce.validation as Readonly<KernelValidation>,
      nonceKey: nonce.nonceKey,
      sequence: nonce.sequence,
    },
    (gas) => gas,
    context,
  );
}

function encodeKernelV33Operation(
  record: Readonly<Record<string, unknown>>,
  nonce: Readonly<{
    mode: "standard" | "enable";
    validation: Readonly<KernelValidation>;
    nonceKey: unknown;
    sequence: unknown;
  }>,
  gasFor: (gas: KernelUserOperationGas) => KernelUserOperationGas,
  context: CaptureContext,
): PreparedUserOperation {
  const account = provenKernelV33Account(record.account);
  const gas = exactInput(
    record.gas,
    [
      "callGasLimit",
      "verificationGasLimit",
      "preVerificationGas",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
    ],
    "Kernel operation gas",
    context,
  );
  return prepareUserOperation({
    kind: record.kind as "execution" | "revocation",
    grantId: record.grantId as string,
    chainId: account.chainId,
    entryPoint: { version: "0.7", address: account.entryPoint },
    userOperation: {
      sender: account.account,
      nonce: encodeKernelV4Nonce({
        key: encodeKernelV33NonceKey({
          mode: nonce.mode,
          validation: nonce.validation,
          nonceKey: nonce.nonceKey as string,
        }),
        sequence: nonce.sequence as string,
      }),
      callData: encodeKernelV4Execution({
        calls: record.calls as KernelV33RuntimePrepareInput["calls"],
      }),
      ...gasFor(gas as unknown as KernelUserOperationGas),
      factory:
        account.state === "counterfactual"
          ? { address: account.factory, data: account.factoryData }
          : null,
      paymaster: (record.paymaster ?? null) as KernelV33RuntimePrepareInput["paymaster"] &
        (object | null),
    },
  });
}
