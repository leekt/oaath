import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import {
  encodeKernelV4Execution,
  encodeKernelV4Nonce,
  encodeKernelV4NonceKey,
  type KernelV4UserOperationGas,
} from "../../kernel-v4.js";
import { type PreparedUserOperation, prepareUserOperation } from "../../prepared-user-operation.js";
import { exactInput, inputInvalid } from "../internal.js";
import type { KernelV33RuntimePrepareInput } from "../types.js";
import { provenKernelV33Account } from "./v33.js";

/** Root nonce and ERC-7579 execute encoding are identical in Kernel 0.3.3 and 0.4.0. */
export function prepareKernelV33OwnerOperation(
  value: KernelV33RuntimePrepareInput,
): PreparedUserOperation {
  const context: CaptureContext = new WeakSet();
  const captured = captureRecord(value, "Kernel v3.3 owner operation", context, inputInvalid);
  const optional = ["mode", "paymaster"].filter((key) => Object.hasOwn(captured, key));
  const record = exactCapturedRecord(
    captured,
    ["account", "kind", "grantId", "nonceKey", "sequence", "calls", "gas", ...optional],
    "Kernel v3.3 owner operation",
    inputInvalid,
  );
  if (record.mode !== undefined && record.mode !== "standard")
    return inputInvalid("Kernel root authority does not use enable mode");
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
        key: encodeKernelV4NonceKey({
          mode: "standard",
          validation: { kind: "root" },
          nonceKey: record.nonceKey as string,
        }),
        sequence: record.sequence as string,
      }),
      callData: encodeKernelV4Execution({
        calls: record.calls as KernelV33RuntimePrepareInput["calls"],
      }),
      ...(gas as unknown as KernelV4UserOperationGas),
      factory: null,
      paymaster: (record.paymaster ?? null) as KernelV33RuntimePrepareInput["paymaster"] &
        (object | null),
    },
  });
}
