/**
 * Pre-sign execution routing contracts. Routing selects the authority signer and
 * the submission route from exactly captured facts and encodes the fallback
 * call; it never submits, never signs, never constructs a provider, and never
 * touches a prepared operation's identity.
 *
 * Fallback invariance: `OaathExecutionDecision` carries no operation field and
 * no callable field, and `decideExecution` never receives a prepared operation.
 * A decision therefore has no surface that could change an operation hash,
 * signer key, nonce, calls, values, gas, paymaster, or account binding; every
 * ERC-4337 route kind submits the byte-identical prepared and signed operation.
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
  captureValidationGasDiagnostic,
  type ExactRecord,
  exactCapturedRecord,
  type OperationSubmissionRoute,
  type ValidationGasDiagnostic,
  validationGasDiagnosticMessage,
} from "@oaath/protocol";
import { type OaathUserOperationError, readUserOperationFailure } from "../user-operation-error.js";

export type RoutingErrorCode =
  | "routing_input_invalid"
  | "routing_capability_invalid"
  | "routing_operation_invalid"
  | "routing_sponsorship_invalid"
  | "routing_paymaster_unsupported"
  | "routing_prefund_out_of_bounds";

export class OaathRoutingError extends Error {
  readonly code: RoutingErrorCode;
  readonly failure: Readonly<OaathUserOperationError> | null;
  readonly diagnostic: Readonly<ValidationGasDiagnostic> | null;

  constructor(
    code: RoutingErrorCode,
    message: string,
    diagnostic: Readonly<ValidationGasDiagnostic> | null = null,
    options?: ErrorOptions,
  ) {
    const captured = captureValidationGasDiagnostic(diagnostic);
    super(captured === null ? message : validationGasDiagnosticMessage(captured), options);
    this.failure = readUserOperationFailure(options?.cause);
    this.name = "OaathRoutingError";
    this.code = code;
    this.diagnostic = captured;
  }
}

/** The authority that signs the UserOperation. Routing selects it before signing. */
export type OaathExecutionSigner = "session" | "owner";

/**
 * The signer a decision selects. `none` denies execution: calls that are not
 * conclusively covered by the approved session scope select no authority at
 * all — owner authority is wider than the reviewed policy, so it is never a
 * fallback for a session-scoped request.
 */
export type OaathExecutionSignerDecision = OaathExecutionSigner | "none";

/**
 * The submission route kinds a chain may offer, in the caller's preference
 * order. Only the ERC-4337 kinds ship; a native account-abstraction kind is a
 * later, separate profile.
 *
 * - `erc4337-bundler`: send the signed operation to an ERC-4337 bundler.
 * - `erc4337-handleops`: send the same signed operation through
 *   `EntryPoint.handleOps` with an EOA fee payer.
 */
export type OaathSubmissionRouteKind = OperationSubmissionRoute;

/**
 * The submission route a decision selected: the selected route's kind, recorded
 * unchanged in review and execution evidence. `none` means no authorized route exists; the caller must fail
 * closed. Routing never invents a route from unreadable or unfunded evidence.
 */
export type OaathExecutionRoute = OaathSubmissionRouteKind | "none";

export type OaathExecutionSignerReason =
  | "owner_explicit"
  | "owner_auto_single_operation"
  | "session_auto_owner_unavailable"
  | "session_auto_multiple_operations"
  | "root_operation_requires_owner"
  | "session_covers_calls"
  | "session_calls_uncovered"
  | "session_coverage_unreadable";

/** What routing concluded about one configured route kind. */
export type OaathRouteReasonCode =
  | "route_available"
  | "route_absent"
  | "route_unsupported"
  | "route_unreadable";

/**
 * One per-route reason, `<code>:<route kind>`, in the order routes were
 * considered. `route_none_configured` means the chain offers no route at all.
 */
export type OaathExecutionRouteReason =
  | `${OaathRouteReasonCode}:${OaathSubmissionRouteKind}`
  | "route_none_configured";

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
 * `feePayer` is non-null exactly when `route` is `erc4337-handleops`.
 * `signer` is `none` exactly when the decision denies execution; a denied
 * decision carries `route: "none"`, no fee payer, and only the signer reason,
 * so it exposes no usable submission surface.
 */
export interface OaathExecutionDecision {
  readonly signer: OaathExecutionSignerDecision;
  readonly route: OaathExecutionRoute;
  readonly feePayer: Readonly<OaathFeePayerDescriptor> | null;
  /** One signer reason, then one reason per route considered, in preference order. */
  readonly reasons: readonly OaathExecutionReason[];
}

export function routingFail(
  code: RoutingErrorCode,
  message: string,
  diagnostic: Readonly<ValidationGasDiagnostic> | null = null,
  options?: ErrorOptions,
): never {
  throw new OaathRoutingError(code, message, diagnostic, options);
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
