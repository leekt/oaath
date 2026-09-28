import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { keccak256, stringToHex } from "viem";
import { getUserOperationHash } from "viem/account-abstraction";
import {
  encodeKernelV4Execution,
  encodeKernelV4Nonce,
  encodeKernelV4NonceKey,
  type KernelV4UserOperationGas,
  type KernelV4Validation,
} from "../../kernel-v4.js";
import {
  asViemUserOperation,
  type PreparedUserOperation,
  parsePreparedUserOperation,
  prepareUserOperation,
} from "../../prepared-user-operation.js";
import { applyKernelGasPolicy, type KernelGasPolicy } from "../gas-policy.js";
import { exactInput, inputInvalid } from "../internal.js";
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
  return getUserOperationHash({
    chainId: 0,
    entryPointAddress: prepared.entryPoint.address,
    entryPointVersion: prepared.entryPoint.version,
    userOperation: asViemUserOperation(prepared.userOperation),
  });
}

/** v3.3 uses mode 0x01 for enable; its validation/namespace layout matches v4. */
export function encodeKernelV33NonceKey(value: {
  mode: "standard" | "enable";
  validation: Readonly<KernelV4Validation>;
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
      validation: input.validation as KernelV4Validation,
      nonceKey: input.nonceKey as string,
    }),
  );
  if (input.mode === "enable" && ((key >> 176n) & 0xffn) !== 2n)
    return inputInvalid("Kernel v3.3 enable requires permission authority");
  return (key | (input.mode === "enable" ? 1n << 184n : 0n)).toString(10);
}

export function prepareKernelV33Operation(
  value: KernelV33RuntimePrepareInput,
  validation: Readonly<KernelV4Validation>,
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
  const account = provenKernelV33Account(record.account);
  const mode = (record.mode === undefined ? "standard" : record.mode) as "standard" | "enable";
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
          mode,
          validation,
          nonceKey: record.nonceKey as string,
        }),
        sequence: record.sequence as string,
      }),
      callData: encodeKernelV4Execution({
        calls: record.calls as KernelV33RuntimePrepareInput["calls"],
      }),
      ...applyKernelGasPolicy(gas as unknown as KernelV4UserOperationGas, mode, gasPolicy),
      factory: null,
      paymaster: (record.paymaster ?? null) as KernelV33RuntimePrepareInput["paymaster"] &
        (object | null),
    },
  });
}
