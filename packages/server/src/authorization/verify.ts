/**
 * Grant reference verification: one read-only projection of the relay's
 * durable authorization evidence into the `@oaath/protocol` grant-reference
 * contract.
 *
 * ```text
 * state and owner        no new state; the request, decision, and capability
 *                        invalidation records already own every fact projected
 * persisted evidence     the immutable request (subject, clientId, audience,
 *                        requestedScope), the terminal decision, and the
 *                        one-shot invalidation
 * resource occupied?     nothing; verification is a pure read
 * retry positively safe? yes: no write exists, so a replay answers the same
 *                        stored facts and never mutates the Grant
 * transitions            none; this owner performs no transition
 * crash/reload           nothing to recover; the projected records recover
 *                        through their own owners
 * cleanup owner          none
 * ```
 *
 * Decision semantics, fail closed and in deterministic order:
 *
 * 1. absent grant, another client's grant, or unreadable/contradictory stored
 *    scope → `unknown` (absence is reported for another client's grant so the
 *    endpoint is not an existence oracle);
 * 2. subject, client, or audience assertion mismatch → `denied` before any
 *    lifecycle fact is revealed;
 * 3. pending, rejected, revoked, expired → `denied`;
 * 4. revision other than the single approved authority revision → `denied`;
 * 5. reviewed call set digest differing from the permitted call set →
 *    `denied`;
 * 6. otherwise → `authorized` with the immutable reference evidence.
 *
 * The relay verifies *approved authority*: the Grant identity's policy (and so
 * `policyDigest` = `hashGrantPolicy(requestedPolicy)`) is fixed at request
 * time, the owner's approval is the relay's durable authority fact, and
 * per-chain materialization remains the client aggregate's separate domain.
 * `expiresAt`/`validUntil` speak protocol seconds; the relay clock speaks
 * milliseconds and is floored into the protocol domain before comparison.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  type GrantVerificationResult,
  hashGrantPolicy,
  hashGrantPolicyCalls,
  OAATH_GRANT_REFERENCE_APPROVED_REVISION,
  OAATH_GRANT_REFERENCE_VERSION,
  type OaathGrantRef,
  parseVerifyGrantRevisionInput,
  type VerifyGrantRevisionInput,
} from "@oaath/protocol";
import { type RelayClock, relayNow } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayStore } from "../store/interface.js";
import { withRelayTransaction } from "../store/interface.js";
import { classifyStoredAuthorizationScope } from "./scope.js";

export interface VerifyGrantReferenceInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  /** Authenticated `client` caller; only its own Grants are visible. */
  readonly caller: RelayCaller;
  readonly assertion: unknown;
}

function unknown(code: "grant_unknown" | "grant_unreadable"): GrantVerificationResult {
  return Object.freeze({ state: "unknown" as const, code });
}

function denied(
  code:
    | "grant_pending"
    | "grant_rejected"
    | "grant_revoked"
    | "grant_expired"
    | "grant_revision_mismatch"
    | "grant_subject_mismatch"
    | "grant_client_mismatch"
    | "grant_audience_mismatch"
    | "grant_calls_mismatch",
): GrantVerificationResult {
  return Object.freeze({ state: "denied" as const, code });
}

export async function verifyGrantReference(
  input: VerifyGrantReferenceInput,
): Promise<GrantVerificationResult> {
  let assertion: Readonly<VerifyGrantRevisionInput>;
  try {
    assertion = parseVerifyGrantRevisionInput(input.assertion);
  } catch {
    return relayFailure("relay_request_invalid", "grant verification assertion is malformed");
  }
  const now = relayNow(input.clock);

  return withRelayTransaction(input.store, async (transaction) => {
    const request = await transaction.lockAuthorizationRequest(assertion.grantId);
    // Another client's Grant reads as unknown: not an existence oracle.
    if (!request || request.clientId !== input.caller.clientId) {
      return unknown("grant_unknown");
    }

    // The stored scope must be the exact permission request this Grant was
    // created from; anything else is unreadable evidence and never authorizes.
    const scope = classifyStoredAuthorizationScope(request.requestedScope, request.requestId);
    if (scope.kind !== "permission-request") {
      return unknown("grant_unreadable");
    }
    // Contradictory evidence fails closed: the authenticated creator and the
    // scope's own application binding must name the same client.
    if (scope.request.application.clientId !== request.clientId) {
      return unknown("grant_unreadable");
    }

    // Binding assertions deny before any lifecycle fact is revealed.
    if (assertion.subject !== request.subject) return denied("grant_subject_mismatch");
    if (assertion.clientId !== request.clientId) return denied("grant_client_mismatch");
    if (
      request.organizationAudience === null ||
      assertion.organizationAudience !== request.organizationAudience
    ) {
      return denied("grant_audience_mismatch");
    }

    const decision = await transaction.lockAuthorizationDecision(assertion.grantId);
    if (!decision) return denied("grant_pending");
    if (decision.outcome === "rejected") return denied("grant_rejected");
    if (await transaction.lockCapabilityInvalidation(assertion.grantId)) {
      return denied("grant_revoked");
    }
    // The policy's inclusive expiry bounds the authority usable for covered
    // calls; it is always earlier than the Grant expiry, so it is the strict
    // fail-closed bound. Protocol time is whole seconds.
    const validUntil = scope.request.policy.validUntil;
    if (validUntil === null || Math.floor(now / 1_000) > validUntil) {
      return denied("grant_expired");
    }

    if (assertion.revision !== OAATH_GRANT_REFERENCE_APPROVED_REVISION) {
      return denied("grant_revision_mismatch");
    }
    if (assertion.requiredCallsDigest !== hashGrantPolicyCalls(scope.request.policy.calls)) {
      return denied("grant_calls_mismatch");
    }

    const ref: Readonly<OaathGrantRef> = Object.freeze({
      version: OAATH_GRANT_REFERENCE_VERSION,
      grantId: request.requestId,
      revision: OAATH_GRANT_REFERENCE_APPROVED_REVISION,
      subject: request.subject,
      clientId: request.clientId,
      organizationAudience: request.organizationAudience,
      state: "active" as const,
      policyDigest: hashGrantPolicy(scope.request.policy),
    });
    return Object.freeze({ state: "authorized" as const, ref });
  });
}
