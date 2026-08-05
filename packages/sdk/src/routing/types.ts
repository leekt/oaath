/**
 * Pre-sign execution routing contracts. Routing selects the authority signer and
 * the submission route from exactly captured facts and encodes the fallback
 * call; it never submits, never signs, never constructs a provider, and never
 * touches a prepared operation's identity.
 *
 * Fallback invariance: `OaathExecutionDecision` carries no operation field and
 * no callable field, and `decideExecution` never receives a prepared operation.
 * A decision therefore has no surface that could change an operation hash,
 * signer key, nonce, calls, values, gas, paymaster, or account binding; the
 * bundler route and the EntryPoint.handleOps route submit byte-identical
 * prepared and signed operations.
 *
 * Deferred: the native owner-EOA route (`routing/native-owner.ts` in the program
 * tree) is out of scope here. No route value, reason code, or capability fact
 * represents it, so no evidence combination can select it, and bundler downtime
 * can never authorize a native transaction.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureRecord,
  type ExactRecord,
  exactCapturedRecord,
} from "@oaath/protocol";

export type RoutingErrorCode =
  | "routing_input_invalid"
  | "routing_capability_invalid"
  | "routing_operation_invalid"
  | "routing_sponsorship_invalid"
  | "routing_paymaster_unsupported"
  | "routing_prefund_out_of_bounds";

export class OaathRoutingError extends Error {
  readonly code: RoutingErrorCode;

  constructor(code: RoutingErrorCode, message: string) {
    super(message);
    this.name = "OaathRoutingError";
    this.code = code;
  }
}

/** The authority that signs the UserOperation. Routing selects it before signing. */
export type OaathExecutionSigner = "session" | "owner";

/**
 * The submission route for one prepared operation.
 *
 * - `bundler`: send the signed operation to the configured ERC-4337 bundler.
 * - `entrypoint-handleops`: send the same signed operation through
 *   `EntryPoint.handleOps` with an EOA fee payer.
 * - `none`: no authorized route exists; the caller must fail closed. Routing
 *   never invents a route from unreadable or unfunded evidence.
 */
export type OaathExecutionRoute = "bundler" | "entrypoint-handleops" | "none";

export type OaathExecutionSignerReason =
  | "root_operation_requires_owner"
  | "session_covers_calls"
  | "session_calls_uncovered"
  | "session_coverage_unreadable";

export type OaathExecutionRouteReason =
  | "bundler_available"
  | "bundler_absent"
  | "bundler_unsupported"
  | "bundler_unreadable"
  | "fee_payer_configured"
  | "fee_payer_absent";

export type OaathExecutionReason = OaathExecutionSignerReason | OaathExecutionRouteReason;

/**
 * One EOA that pays for a direct `EntryPoint.handleOps` transaction and receives
 * the EntryPoint refund as beneficiary. It may be a different key from the
 * account owner, which is how a P-256 or WebAuthn owner funds a fallback.
 */
export interface OaathFeePayerDescriptor {
  readonly address: `0x${string}`;
  /** Canonical decimal wei balance captured from the caller's chain read. */
  readonly balance: string;
}

/**
 * The frozen pre-sign decision. Every field is a fact or a closed code: there is
 * no operation, no capability handle, and no callable member, so a decision can
 * neither mutate nor re-derive an operation identity.
 *
 * `feePayer` is non-null exactly when `route` is `entrypoint-handleops`.
 */
export interface OaathExecutionDecision {
  readonly signer: OaathExecutionSigner;
  readonly route: OaathExecutionRoute;
  readonly feePayer: Readonly<OaathFeePayerDescriptor> | null;
  /** One signer reason, one bundler reason, and one fee-payer reason when a fallback was considered. */
  readonly reasons: readonly OaathExecutionReason[];
}

export function routingFail(code: RoutingErrorCode, message: string): never {
  throw new OaathRoutingError(code, message);
}

export function inputInvalid(message: string): never {
  return routingFail("routing_input_invalid", message);
}

export function capabilityInvalid(message: string): never {
  return routingFail("routing_capability_invalid", message);
}

/** Captures one caller-supplied record with an exact key set at a routing boundary. */
export function exactRoutingRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
  context: CaptureContext,
  fail: (message: string) => never,
): ExactRecord {
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}
