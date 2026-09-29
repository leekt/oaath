import { isKernelV4EnableNonce, type KernelUserOperationGas } from "../kernel-v4.js";
import { exactInput, inputInvalid, inputUint } from "./internal.js";
import type { KernelRuntimeValidationMode } from "./types.js";

export interface KernelGasPolicy {
  /** Minimum verification gas for the first operation that installs a session. */
  readonly enableVerificationGasFloor: bigint;
}

const MAX_UINT120 = (1n << 120n) - 1n;

/** Configuration owner; all gas policy values are captured before asynchronous work. */
export function captureKernelGasPolicy(chainId: number, value: unknown): Readonly<KernelGasPolicy> {
  if (value === undefined) {
    return Object.freeze({ enableVerificationGasFloor: chainId === 143 ? 2_000_000n : 0n });
  }
  const record = exactInput(
    value,
    ["enableVerificationGasFloor"],
    "Kernel gas policy",
    new WeakSet(),
  );
  const floor = record.enableVerificationGasFloor;
  if (typeof floor !== "bigint" || floor < 0n || floor > MAX_UINT120) {
    return inputInvalid("Kernel enable verification gas floor must be a uint120 bigint");
  }
  return Object.freeze({ enableVerificationGasFloor: floor });
}

/** v4 replayable enable and v3.3 chain-bound enable both install permission state. */
export function enableVerificationFloorForNonce(
  nonce: string,
  policy: Readonly<KernelGasPolicy>,
): bigint {
  return isKernelV4EnableNonce(nonce) || BigInt(nonce) >> 248n === 1n
    ? policy.enableVerificationGasFloor
    : 0n;
}

export function applyKernelGasPolicy(
  value: KernelUserOperationGas,
  mode: KernelRuntimeValidationMode | "enable",
  policy: Readonly<KernelGasPolicy>,
): Readonly<KernelUserOperationGas> {
  if (
    (mode !== "enable-replayable" && mode !== "enable") ||
    policy.enableVerificationGasFloor === 0n
  )
    return value;
  const gas = exactInput(
    value,
    [
      "callGasLimit",
      "verificationGasLimit",
      "preVerificationGas",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
    ],
    "Kernel operation gas",
    new WeakSet(),
  );
  const quoted = inputUint(gas.verificationGasLimit, MAX_UINT120, "Kernel verification gas limit");
  return Object.freeze({
    callGasLimit: gas.callGasLimit as string,
    verificationGasLimit: (quoted > policy.enableVerificationGasFloor
      ? quoted
      : policy.enableVerificationGasFloor
    ).toString(10),
    preVerificationGas: gas.preVerificationGas as string,
    maxFeePerGas: gas.maxFeePerGas as string,
    maxPriorityFeePerGas: gas.maxPriorityFeePerGas as string,
  });
}
