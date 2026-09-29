import {
  captureRecord,
  exactCapturedRecord,
  type OperationIdentity,
  type OperationInclusion,
} from "@oaath/protocol";
import { decodeFunctionData, type Hex } from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { decodeKernelV4Execution, type KernelCall } from "./kernel-v4.js";

const BYTES = /^0x(?:[0-9a-f]{2})*$/u;

function invalid(): never {
  throw new Error("operation_execution_evidence_invalid");
}

/**
 * Binds transient transaction calldata to verified inclusion and immutable
 * operation identity. Signatures are neither returned nor retained. This is
 * an internal projection, not another operation lifecycle or finality owner.
 */
export function verifyOperationExecutionEvidence(
  input: Readonly<{
    identity: Readonly<OperationIdentity>;
    inclusion: Readonly<OperationInclusion>;
    transaction: unknown;
  }>,
): Readonly<{ sender: Hex; calls: readonly Readonly<KernelCall>[] }> {
  const { identity, inclusion } = input;
  const transaction = exactCapturedRecord(
    captureRecord(input.transaction, "execution transaction", new WeakSet(), invalid),
    ["hash", "to", "blockNumber", "blockHash", "input"],
    "execution transaction",
    invalid,
  );
  if (
    transaction.hash !== inclusion.transactionHash ||
    transaction.to !== identity.entryPoint ||
    transaction.blockNumber !== `0x${BigInt(inclusion.blockNumber).toString(16)}` ||
    transaction.blockHash !== inclusion.blockHash ||
    typeof transaction.input !== "string" ||
    !BYTES.test(transaction.input)
  )
    return invalid();
  const decoded = decodeFunctionData({ abi: entryPoint07Abi, data: transaction.input as Hex });
  const operations =
    decoded.functionName === "handleOps"
      ? decoded.args[0]
      : decoded.functionName === "handleAggregatedOps"
        ? decoded.args[0].flatMap((group) => group.userOps)
        : invalid();
  let calls: readonly Readonly<KernelCall>[] | undefined;
  for (const packed of operations) {
    // Use the library's EntryPoint hash implementation, including factory,
    // paymaster and gas fields, rather than trusting a provider's claimed ID.
    // The converter accepts packed input but its inferred return type retains
    // that input shape; specify the actual unpacked v0.7 result explicitly.
    const operation = toUserOperation<Omit<UserOperation<"0.7">, "authorization">>({
      ...packed,
      signature: "0x",
    });
    const hash = getUserOperationHash({
      chainId: identity.chainId,
      entryPointAddress: identity.entryPoint,
      entryPointVersion: "0.7",
      userOperation: operation,
    });
    if (hash !== identity.userOperationHash) continue;
    if (
      calls ||
      packed.sender.toLowerCase() !== identity.account ||
      packed.nonce.toString(10) !== identity.nonce
    )
      return invalid();
    calls = decodeKernelV4Execution(packed.callData);
  }
  if (!calls) return invalid();
  return Object.freeze({ sender: identity.account, calls });
}
