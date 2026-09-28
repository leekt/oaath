import { exactRecord } from "./internal/exact-record.js";

/** ERC-4337 pre-acceptance refusal codes; transport failures are never refusals. */
export const OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES: readonly number[] = Object.freeze([
  -32500, -32501, -32502, -32503, -32504, -32505, -32506, -32507, -32521,
]);
export interface BundlerRejection {
  readonly code: number;
}

/** Captures only a conclusive code. No prose or raw provider data crosses this boundary. */
export function captureBundlerRejection(value: unknown): Readonly<BundlerRejection> | null {
  try {
    const record = exactRecord(value, ["code"], "bundler rejection", new WeakSet(), () => {
      throw new Error("invalid rejection");
    });
    return typeof record.code === "number" &&
      OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES.includes(record.code)
      ? Object.freeze({ code: record.code })
      : null;
  } catch {
    return null;
  }
}

/** Reads structured SDK RPC failure fields, never a message, inherited field, or accessor. */
export function readRpcBundlerRejection(error: unknown): Readonly<BundlerRejection> | null {
  if (error === null || typeof error !== "object") return null;
  try {
    const code = Object.getOwnPropertyDescriptor(error, "code");
    const rpcCode = Object.getOwnPropertyDescriptor(error, "rpcCode");
    return code &&
      "value" in code &&
      code.value === "oaath_rpc_rejected" &&
      rpcCode &&
      "value" in rpcCode
      ? captureBundlerRejection({ code: rpcCode.value })
      : null;
  } catch {
    return null;
  }
}
