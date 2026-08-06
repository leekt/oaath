/**
 * EXPERIMENTAL PREVIEW — approve/reject saga keyed by the stable operation id.
 *
 * ```text
 * state and owner        the relay's authorization decision record. This saga
 *                        owns no decision state of its own and keeps nothing in
 *                        memory; it routes to `submitAuthorizationDecision`.
 * persisted evidence     one terminal decision row per request
 * resource occupied?     yes: the decision occupies its request, and the
 *                        one-time code and artifact are released exactly once
 * retry positively safe? yes for the saga call, because a repeated call never
 *                        decides again: it answers the stored outcome
 * transitions            undecided -> approved | rejected once, then replay-only
 * crash/reload           the outcome is durable before the caller sees it, so a
 *                        phone that never saw its response retries and is
 *                        answered from the store, on any process
 * cleanup owner          the relay transaction; nothing extra is allocated here
 * ```
 *
 * A second decide answers the *stored* outcome, not the resubmitted command: if
 * a rejected request is retried as approved, the answer is `rejected`. Compare
 * `outcome` against what you sent when that matters.
 *
 * The one-time code and encrypted artifact are released to the deciding call
 * only. A replay reports the outcome and no release material, because releasing
 * it twice is exactly what one-shot semantics forbid.
 *
 * @author taek <leekt216@gmail.com>
 */

import type {
  AuthorizationDecisionCommand,
  SubmittedAuthorizationDecision,
} from "../authorization/decision.js";
import { submitAuthorizationDecision } from "../authorization/decision.js";
import { fetchAuthorizationRequest } from "../authorization/request.js";
import type { RelayClock } from "../clock.js";
import { OaathRelayError, relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayKms } from "../security/kms.js";
import type { RelayStore } from "../store/interface.js";
import type { AuthorizationDecisionOutcome } from "../store/records.js";
import { projectOwnerPhoneScope } from "./projection.js";

export interface SubmitOwnerPhoneDecisionInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  readonly kms: RelayKms;
  /** Authenticated `owner` caller; only the bound subject may decide. */
  readonly caller: RelayCaller;
  /** `operationId` from `projectOwnerPhoneRequest`. */
  readonly operationId: string;
  readonly command: AuthorizationDecisionCommand;
  readonly codeTtlMs: number;
}

export interface OwnerPhoneDecision {
  readonly operationId: string;
  /** The stored outcome, which on a replay may differ from the command sent. */
  readonly outcome: AuthorizationDecisionOutcome;
  readonly decidedAt: number;
  /** `decided` performed the transition; `replayed` answered the stored one. */
  readonly settlement: "decided" | "replayed";
  /** One-time release material, on the deciding call only. */
  readonly release: SubmittedAuthorizationDecision | null;
}

export async function submitOwnerPhoneDecision(
  input: SubmitOwnerPhoneDecisionInput,
): Promise<OwnerPhoneDecision> {
  if (input.caller.role !== "owner") {
    return relayFailure("relay_forbidden", "caller may not act in the required role");
  }
  // A scope the projection could not read is reject-only: the phone never
  // offers approval over it, and the relay enforces the same rule here so a
  // bypassing client cannot approve authority nobody reviewed structurally.
  if (input.command.outcome === "approved") {
    const state = await fetchAuthorizationRequest({
      store: input.store,
      clock: input.clock,
      caller: input.caller,
      requestId: input.operationId,
    });
    const scope = await projectOwnerPhoneScope(state.requestedScope, state.requestId);
    if (scope.decision === "reject-only") {
      return relayFailure("relay_request_invalid", "an unrecognized scope is reject-only");
    }
  }
  try {
    const release = await submitAuthorizationDecision({
      store: input.store,
      clock: input.clock,
      kms: input.kms,
      caller: input.caller,
      requestId: input.operationId,
      command: input.command,
      codeTtlMs: input.codeTtlMs,
    });
    return Object.freeze({
      operationId: input.operationId,
      outcome: release.outcome,
      decidedAt: release.decidedAt,
      settlement: "decided",
      release,
    });
  } catch (error) {
    // Only "already decided" is idempotent. Ambiguous, expired, unauthorized,
    // and unreadable stay failures: an unproven commit never becomes an answer.
    if (!(error instanceof OaathRelayError) || error.code !== "relay_already_decided") throw error;
  }
  const state = await fetchAuthorizationRequest({
    store: input.store,
    clock: input.clock,
    caller: input.caller,
    requestId: input.operationId,
  });
  if (state.decision === null) {
    return relayFailure("relay_internal", "decided request has no decision record");
  }
  return Object.freeze({
    operationId: input.operationId,
    outcome: state.decision.outcome,
    decidedAt: state.decision.decidedAt,
    settlement: "replayed",
    release: null,
  });
}
