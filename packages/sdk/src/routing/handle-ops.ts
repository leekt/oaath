/**
 * Direct `EntryPoint.handleOps` fee-payer requirements and calldata encoding.
 *
 * The encoder is the fallback's identity guarantee: it re-parses the prepared
 * operation (which re-derives and re-checks its hash), packs exactly those
 * fields, and returns the same `userOperationHash` the bundler route would have
 * submitted. Only the signature bytes and the outer transaction differ between
 * routes.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext } from "@oaath/protocol";
import { encodeFunctionData } from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { asViemUserOperation, parsePreparedUserOperation } from "../prepared-user-operation.js";
import { routingAddress, routingBytes, routingUint } from "./capabilities.js";
import { deriveOperationPrefund } from "./gas.js";
import {
  exactRoutingRecord,
  inputInvalid,
  type OaathFeePayerDescriptor,
  routingFail,
} from "./types.js";

/**
 * Gas the EOA fee payer must cover beyond the operation's own gas: the 21000
 * transaction base plus EntryPoint 0.7 handleOps loop, deposit accounting, and
 * beneficiary transfer overhead for one operation.
 *
 * ponytail: one reviewed constant for the single-operation batch this release
 * submits. Pass a measured value per chain if an L2's calldata or precompile
 * pricing makes it too tight.
 */
export const OAATH_HANDLE_OPS_OVERHEAD_GAS = "60000";

export interface OaathHandleOpsRequirementInput {
  readonly prepared: unknown;
  readonly feePayer: Readonly<OaathFeePayerDescriptor>;
  /** Canonical decimal gas overhead; use OAATH_HANDLE_OPS_OVERHEAD_GAS unless measured. */
  readonly overheadGas: string;
}

/**
 * What the EOA fee payer must hold to submit one prepared operation through
 * `EntryPoint.handleOps`, bound to the operation identity it was derived from.
 *
 * `requiredPrefund` is the sender account's EntryPoint 0.7 prepayment, which the
 * account (or its deposit) covers. `requiredFeePayerBalance` is what the EOA
 * itself must hold to pay for the transaction it signs; the EntryPoint refunds
 * the beneficiary afterwards, so this is an upper bound, not a spend.
 */
export interface OaathHandleOpsRequirement {
  readonly status: "funded" | "underfunded";
  readonly chainId: number;
  readonly entryPoint: `0x${string}`;
  readonly account: `0x${string}`;
  readonly userOperationHash: `0x${string}`;
  readonly feePayer: `0x${string}`;
  readonly requiredPrefund: string;
  readonly overheadGas: string;
  readonly requiredFeePayerBalance: string;
}

export interface OaathHandleOpsEncodingInput {
  readonly prepared: unknown;
  /** The signature produced for this exact prepared operation. */
  readonly signature: `0x${string}`;
  /** The EOA that receives the EntryPoint refund; normally the fee payer. */
  readonly beneficiary: `0x${string}`;
}

export interface OaathHandleOpsCall {
  readonly chainId: number;
  readonly entryPoint: `0x${string}`;
  readonly account: `0x${string}`;
  /** The identity the bundler route would have submitted, unchanged. */
  readonly userOperationHash: `0x${string}`;
  readonly beneficiary: `0x${string}`;
  readonly data: `0x${string}`;
}

/**
 * Derives the fee-payer requirement for one prepared operation. It compares the
 * requirement against the captured balance fact only; it never changes a route,
 * a gas field, or an operation identity. An `underfunded` result is a caller
 * pre-submission failure, not a route change.
 */
export function deriveHandleOpsRequirement(
  input: OaathHandleOpsRequirementInput,
): Readonly<OaathHandleOpsRequirement> {
  const context: CaptureContext = new WeakSet();
  const record = exactRoutingRecord(
    input,
    ["prepared", "feePayer", "overheadGas"],
    "handleOps requirement input",
    context,
    inputInvalid,
  );
  const feePayer = exactRoutingRecord(
    record.feePayer,
    ["address", "balance"],
    "handleOps fee payer",
    context,
    inputInvalid,
  );
  const feePayerAddress = routingAddress(
    feePayer.address,
    "handleOps fee payer address",
    inputInvalid,
  );
  const balance = BigInt(
    routingUint(feePayer.balance, "handleOps fee payer balance", inputInvalid),
  );
  const overheadGas = BigInt(
    routingUint(record.overheadGas, "handleOps overhead gas", inputInvalid),
  );
  const prefund = deriveOperationPrefund(record.prepared);
  const requiredFeePayerBalance =
    (BigInt(prefund.totalGas) + overheadGas) * BigInt(prefund.maxFeePerGas);

  return Object.freeze({
    status: balance >= requiredFeePayerBalance ? "funded" : "underfunded",
    chainId: prefund.chainId,
    entryPoint: prefund.entryPoint,
    account: prefund.account,
    userOperationHash: prefund.userOperationHash,
    feePayer: feePayerAddress,
    requiredPrefund: prefund.requiredPrefund,
    overheadGas: overheadGas.toString(10),
    requiredFeePayerBalance: requiredFeePayerBalance.toString(10),
  });
}

/**
 * Encodes `handleOps([op], beneficiary)` for one prepared and signed operation.
 * The prepared parser re-derives the hash from the fields being packed, so the
 * returned `userOperationHash` proves the fallback submits the same identity the
 * bundler route was given. Only the outer transaction differs.
 */
export function encodeHandleOps(input: OaathHandleOpsEncodingInput): Readonly<OaathHandleOpsCall> {
  const record = exactRoutingRecord(
    input,
    ["prepared", "signature", "beneficiary"],
    "handleOps encoding input",
    new WeakSet(),
    inputInvalid,
  );
  const signature = routingBytes(record.signature, "handleOps signature", inputInvalid);
  const beneficiary = routingAddress(record.beneficiary, "handleOps beneficiary", inputInvalid);
  let operation: ReturnType<typeof parsePreparedUserOperation>;
  try {
    operation = parsePreparedUserOperation(record.prepared);
  } catch {
    return routingFail(
      "routing_operation_invalid",
      "handleOps encoding requires an exact prepared UserOperation",
    );
  }
  if (operation.userOperation.paymaster !== null) {
    return routingFail(
      "routing_paymaster_unsupported",
      "the handleOps route does not submit paymaster-sponsored operations",
    );
  }

  const packed = toPackedUserOperation({
    ...asViemUserOperation(operation.userOperation),
    signature,
  });
  return Object.freeze({
    chainId: operation.chainId,
    entryPoint: operation.entryPoint.address,
    account: operation.userOperation.sender,
    userOperationHash: operation.userOperationHash,
    beneficiary,
    data: encodeFunctionData({
      abi: entryPoint07Abi,
      functionName: "handleOps",
      args: [[packed], beneficiary],
    }),
  });
}
