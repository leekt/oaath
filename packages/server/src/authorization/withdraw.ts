/** Creator withdrawal shares the immutable decision row and request lock with
 * owner approval. Retrying reads the committed winner; an approval is never revoked.
 */
import { type RelayClock, relayNow } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import { type RelayStore, withRelayTransaction } from "../store/interface.js";
import {
  type AuthorizationDecisionOutcome,
  OAATH_AUTHORIZATION_DECISION_RECORD_VERSION,
} from "../store/records.js";

export interface WithdrawAuthorizationInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  readonly caller: RelayCaller;
  readonly requestId: string;
}
export interface WithdrawnAuthorization {
  readonly requestId: string;
  readonly outcome: AuthorizationDecisionOutcome | "expired";
  readonly decidedAt: number | null;
}
export async function withdrawAuthorizationRequest(
  input: WithdrawAuthorizationInput,
): Promise<Readonly<WithdrawnAuthorization>> {
  if (input.caller.role !== "client")
    return relayFailure("relay_forbidden", "only the creating client may withdraw");
  const now = relayNow(input.clock);
  return withRelayTransaction(input.store, async (transaction) => {
    const request = await transaction.lockAuthorizationRequest(input.requestId);
    if (
      !request ||
      request.clientId !== input.caller.clientId ||
      request.subject !== input.caller.subject
    ) {
      return relayFailure("relay_not_found", "authorization request does not exist");
    }
    const decision = await transaction.lockAuthorizationDecision(input.requestId);
    if (decision)
      return Object.freeze({
        requestId: request.requestId,
        outcome: decision.outcome,
        decidedAt: decision.decidedAt,
      });
    if (now >= request.expiresAt)
      return Object.freeze({ requestId: request.requestId, outcome: "expired", decidedAt: null });
    if (
      !(await transaction.insertAuthorizationDecision({
        version: OAATH_AUTHORIZATION_DECISION_RECORD_VERSION,
        requestId: request.requestId,
        outcome: "withdrawn",
        decidedAt: now,
        codeRef: null,
        codeExpiresAt: null,
      }))
    ) {
      return relayFailure(
        "relay_state_ambiguous",
        "withdrawal did not apply under its request lock",
      );
    }
    return Object.freeze({ requestId: request.requestId, outcome: "withdrawn", decidedAt: now });
  });
}
