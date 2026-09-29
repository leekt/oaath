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
 * Decision table:
 *
 * ```text
 * signer
 *   revocation, any coverage          -> owner   (root_operation_requires_owner)
 *   execution,  covered               -> session (session_covers_calls)
 *   execution,  uncovered             -> none    (session_calls_uncovered)
 *   execution,  unreadable            -> none    (session_coverage_unreadable)
 *   explicit signer: owner            -> owner   (owner_explicit)
 *
 * A denied signer denies the whole decision: owner authority is wider than the
 * session policy the owner approved, so uncovered or inconclusively covered
 * session requests select no authority, no route, and no fee payer. Root
 * execution requires an explicit owner request; it is never inferred from denial.
 *
 * route: the first conclusively usable route, in the configured order
 *   erc4337-bundler   available   -> bundler              (route_available:erc4337-bundler)
 *   erc4337-bundler   unreadable  -> bundler, stop        (route_unreadable:erc4337-bundler)
 *   erc4337-bundler   absent      -> try the next route   (route_absent:erc4337-bundler)
 *   erc4337-bundler   unsupported -> try the next route   (route_unsupported:erc4337-bundler)
 *   erc4337-handleops             -> entrypoint-handleops (route_available:erc4337-handleops)
 *   no route left                 -> none
 *   no route configured           -> none                 (route_none_configured)
 * ```
 *
 * An `unreadable` bundler stays on the bundler route and never consults a later
 * route: a timeout, disconnect, or ambiguous response is not unavailability, so
 * it authorizes no fallback and no second submission.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext, OperationKind } from "@oaath/protocol";
import {
  sessionCoverage as captureSessionCoverage,
  type OaathRouteFact,
  type OaathSessionCoverage,
  routeFacts,
} from "./capabilities.js";
import {
  exactRoutingRecord,
  inputInvalid,
  type OaathExecutionDecision,
  type OaathExecutionRoute,
  type OaathExecutionRouteReason,
  type OaathExecutionSignerDecision,
  type OaathExecutionSignerReason,
  type OaathFeePayerDescriptor,
} from "./types.js";

export interface DecideExecutionInput {
  /** Explicit root authority; absence retains session coverage rules for execution. */
  readonly signer?: "owner" | "session";
  /** `revocation` is owner-authorized root work; `execution` may use a session. */
  readonly operationKind: OperationKind;
  readonly sessionCoverage: OaathSessionCoverage;
  /** The chain's classified routes, in preference order. */
  readonly routes: readonly OaathRouteFact[];
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
): Readonly<{ signer: OaathExecutionSignerDecision; reason: OaathExecutionSignerReason }> {
  if (kind === "revocation") {
    return { signer: "owner", reason: "root_operation_requires_owner" };
  }
  if (coverage === "covered") return { signer: "session", reason: "session_covers_calls" };
  if (coverage === "uncovered") return { signer: "none", reason: "session_calls_uncovered" };
  return { signer: "none", reason: "session_coverage_unreadable" };
}

function decideRoute(routes: readonly OaathRouteFact[]): Readonly<{
  route: OaathExecutionRoute;
  feePayer: Readonly<OaathFeePayerDescriptor> | null;
  reasons: readonly OaathExecutionRouteReason[];
}> {
  if (routes.length === 0) {
    return { route: "none", feePayer: null, reasons: ["route_none_configured"] };
  }
  const reasons: OaathExecutionRouteReason[] = [];
  for (const fact of routes) {
    if (fact.kind === "erc4337-handleops") {
      reasons.push("route_available:erc4337-handleops");
      return { route: "entrypoint-handleops", feePayer: fact.feePayer, reasons };
    }
    reasons.push(`route_${fact.bundler}:erc4337-bundler`);
    // An unreadable bundler is not unavailability: it forbids every later route.
    if (fact.bundler === "available" || fact.bundler === "unreadable") {
      return { route: "bundler", feePayer: null, reasons };
    }
  }
  return { route: "none", feePayer: null, reasons };
}

/** Whether these exact classified routes select the sponsorship-capable bundler route. */
export function supportsBundlerSponsorship(routes: readonly OaathRouteFact[]): boolean {
  return decideRoute(routes).route === "bundler";
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
    [
      "operationKind",
      "sessionCoverage",
      "routes",
      ...(input !== null && typeof input === "object" && Object.hasOwn(input, "signer")
        ? ["signer"]
        : []),
    ],
    "routing decision input",
    context,
    inputInvalid,
  );
  if (Object.hasOwn(record, "signer") && record.signer !== "owner" && record.signer !== "session")
    return inputInvalid("requested signer is unsupported");
  const defaultSigner = decideSigner(
    operationKind(record.operationKind),
    captureSessionCoverage(record.sessionCoverage, inputInvalid),
  );
  const signer =
    record.signer === "owner"
      ? { signer: "owner" as const, reason: "owner_explicit" as const }
      : defaultSigner;
  const route = decideRoute(routeFacts(record.routes, context, inputInvalid));
  if (signer.signer === "none") {
    // Route facts were still captured and validated above, but a denied signer
    // must not carry a usable route: nothing may be signed or submitted.
    return Object.freeze({
      signer: "none" as const,
      route: "none" as const,
      feePayer: null,
      reasons: Object.freeze([signer.reason]),
    });
  }
  return Object.freeze({
    signer: signer.signer,
    route: route.route,
    feePayer: route.feePayer,
    reasons: Object.freeze([signer.reason, ...route.reasons]),
  });
}
