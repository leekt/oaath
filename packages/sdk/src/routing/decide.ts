/**
 * The one pre-sign routing decision. It is pure and total over the closed fact
 * space: signer and route are functions of the captured facts alone.
 *
 * It never receives a prepared operation, a key, a signer, a store, or a
 * transport, so a decision cannot change an operation hash, nonce, calls,
 * values, gas, paymaster, or account binding. Choosing `entrypoint-handleops`
 * therefore submits the byte-identical prepared and signed operation the bundler
 * route would have submitted.
 *
 * Decision table (48 total fact combinations):
 *
 * ```text
 * signer
 *   revocation, any coverage          -> owner   (root_operation_requires_owner)
 *   execution,  covered               -> session (session_covers_calls)
 *   execution,  uncovered             -> owner   (session_calls_uncovered)
 *   execution,  unreadable            -> owner   (session_coverage_unreadable)
 *
 * route
 *   bundler available,  any fee payer -> bundler              (bundler_available)
 *   bundler unreadable, any fee payer -> bundler              (bundler_unreadable)
 *   bundler absent,      fee payer    -> entrypoint-handleops (bundler_absent, fee_payer_configured)
 *   bundler absent,      none         -> none                 (bundler_absent, fee_payer_absent)
 *   bundler unsupported, fee payer    -> entrypoint-handleops (bundler_unsupported, fee_payer_configured)
 *   bundler unsupported, none         -> none                 (bundler_unsupported, fee_payer_absent)
 * ```
 *
 * An `unreadable` bundler stays on the bundler route and never consults the fee
 * payer: a timeout, disconnect, or ambiguous response is not unavailability, so
 * it authorizes no fallback and no second submission.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext, OperationKind } from "@oaath/protocol";
import {
  bundlerCapability,
  sessionCoverage as captureSessionCoverage,
  feePayerDescriptor,
  type OaathBundlerCapability,
  type OaathSessionCoverage,
} from "./capabilities.js";
import {
  exactRoutingRecord,
  inputInvalid,
  type OaathExecutionDecision,
  type OaathExecutionReason,
  type OaathExecutionRoute,
  type OaathExecutionSigner,
  type OaathExecutionSignerReason,
  type OaathFeePayerDescriptor,
} from "./types.js";

export interface DecideExecutionInput {
  /** `revocation` is owner-authorized root work; `execution` may use a session. */
  readonly operationKind: OperationKind;
  readonly sessionCoverage: OaathSessionCoverage;
  readonly bundler: OaathBundlerCapability;
  readonly feePayer: Readonly<OaathFeePayerDescriptor> | null;
}

function operationKind(value: unknown): OperationKind {
  if (value !== "execution" && value !== "revocation") {
    return inputInvalid("routing operation kind is unsupported");
  }
  return value;
}

function decideSigner(
  kind: OperationKind,
  coverage: OaathSessionCoverage,
): Readonly<{ signer: OaathExecutionSigner; reason: OaathExecutionSignerReason }> {
  if (kind === "revocation") {
    return { signer: "owner", reason: "root_operation_requires_owner" };
  }
  if (coverage === "covered") return { signer: "session", reason: "session_covers_calls" };
  if (coverage === "uncovered") return { signer: "owner", reason: "session_calls_uncovered" };
  return { signer: "owner", reason: "session_coverage_unreadable" };
}

function decideRoute(
  bundler: OaathBundlerCapability,
  feePayer: Readonly<OaathFeePayerDescriptor> | null,
): Readonly<{
  route: OaathExecutionRoute;
  feePayer: Readonly<OaathFeePayerDescriptor> | null;
  reasons: readonly OaathExecutionReason[];
}> {
  if (bundler === "available") {
    return { route: "bundler", feePayer: null, reasons: ["bundler_available"] };
  }
  if (bundler === "unreadable") {
    return { route: "bundler", feePayer: null, reasons: ["bundler_unreadable"] };
  }
  const conclusive: OaathExecutionReason =
    bundler === "absent" ? "bundler_absent" : "bundler_unsupported";
  if (feePayer === null) {
    return { route: "none", feePayer: null, reasons: [conclusive, "fee_payer_absent"] };
  }
  return {
    route: "entrypoint-handleops",
    feePayer,
    reasons: [conclusive, "fee_payer_configured"],
  };
}

/**
 * Decides the signer and submission route before any signature exists. Facts are
 * captured exactly, so hostile or unsupported evidence fails closed with a
 * structured routing code instead of selecting a route.
 */
export function decideExecution(input: DecideExecutionInput): Readonly<OaathExecutionDecision> {
  const context: CaptureContext = new WeakSet();
  const record = exactRoutingRecord(
    input,
    ["operationKind", "sessionCoverage", "bundler", "feePayer"],
    "routing decision input",
    context,
    inputInvalid,
  );
  const signer = decideSigner(
    operationKind(record.operationKind),
    captureSessionCoverage(record.sessionCoverage, inputInvalid),
  );
  const route = decideRoute(
    bundlerCapability(record.bundler, inputInvalid),
    feePayerDescriptor(record.feePayer, context, inputInvalid),
  );
  return Object.freeze({
    signer: signer.signer,
    route: route.route,
    feePayer: route.feePayer,
    reasons: Object.freeze([signer.reason, ...route.reasons]),
  });
}
