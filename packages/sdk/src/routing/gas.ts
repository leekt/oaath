/**
 * Reviewed EntryPoint 0.7 prefund arithmetic. It reads an already validated
 * prepared operation and derives one number; it never mutates a field, never
 * re-estimates gas, and never selects or changes a route.
 *
 * @author taek <leekt216@gmail.com>
 */
import { parsePreparedUserOperation } from "../prepared-user-operation.js";
import { routingFail } from "./types.js";

const MAX_UINT256 = (1n << 256n) - 1n;

/**
 * The EntryPoint 0.7 prefund requirement for one operation, bound to the exact
 * operation identity it was derived from.
 */
export interface OaathOperationPrefund {
  readonly chainId: number;
  readonly entryPoint: `0x${string}`;
  readonly account: `0x${string}`;
  readonly userOperationHash: `0x${string}`;
  /** Canonical decimal sum of verification, call, and pre-verification gas. */
  readonly totalGas: string;
  /** The prepared operation's fee ceiling, echoed as the arithmetic's second factor. */
  readonly maxFeePerGas: string;
  /** Canonical decimal wei the account must have deposited: totalGas * maxFeePerGas. */
  readonly requiredPrefund: string;
}

/**
 * Derives `requiredPrefund = (verificationGasLimit + callGasLimit +
 * preVerificationGas) * maxFeePerGas`, the EntryPoint 0.7 prepayment the sender
 * account must cover when no paymaster sponsors the operation.
 *
 * Paymaster-sponsored operations are rejected: the 0.1.0 handleOps route is
 * unsponsored, and a paymaster would add verification and post-operation gas
 * this owner does not price.
 */
export function deriveOperationPrefund(prepared: unknown): Readonly<OaathOperationPrefund> {
  let operation: ReturnType<typeof parsePreparedUserOperation>;
  try {
    operation = parsePreparedUserOperation(prepared);
  } catch {
    return routingFail(
      "routing_operation_invalid",
      "routing prefund requires an exact prepared UserOperation",
    );
  }
  if (operation.userOperation.paymaster !== null) {
    return routingFail(
      "routing_paymaster_unsupported",
      "routing prefund does not price paymaster-sponsored operations",
    );
  }

  const totalGas =
    BigInt(operation.userOperation.verificationGasLimit) +
    BigInt(operation.userOperation.callGasLimit) +
    BigInt(operation.userOperation.preVerificationGas);
  const requiredPrefund = totalGas * BigInt(operation.userOperation.maxFeePerGas);
  // ponytail: unreachable while the prepared parser bounds every gas field to
  // uint120 (3 * 2^120 * 2^120 < 2^256). Kept as a cross-module invariant guard
  // so widening those fields fails here instead of silently wrapping on chain.
  if (totalGas > MAX_UINT256 || requiredPrefund > MAX_UINT256) {
    return routingFail(
      "routing_prefund_out_of_bounds",
      "routing prefund exceeds the EntryPoint value range",
    );
  }

  return Object.freeze({
    chainId: operation.chainId,
    entryPoint: operation.entryPoint.address,
    account: operation.userOperation.sender,
    userOperationHash: operation.userOperationHash,
    totalGas: totalGas.toString(10),
    maxFeePerGas: operation.userOperation.maxFeePerGas,
    requiredPrefund: requiredPrefund.toString(10),
  });
}
