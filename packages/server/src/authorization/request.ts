/**
 * Create and read an authorization request.
 *
 * The request record is immutable once created. Its decision is a separate
 * terminal record, so "was this decided?" has exactly one owner.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type RelayClock, relayNow } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayStore, RelayTransaction } from "../store/interface.js";
import { withRelayTransaction } from "../store/interface.js";
import {
  type AuthorizationDecisionOutcome,
  type AuthorizationRequestRecord,
  OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION,
} from "../store/records.js";
import { isCodeChallengeS256, randomIdentifier } from "./challenge.js";

export interface CreateAuthorizationRequestInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  /** Authenticated `client` caller; it owns `clientId` and `subject`. */
  readonly caller: RelayCaller;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly requestedScope: string;
  readonly requestTtlMs: number;
}

export interface CreatedAuthorizationRequest {
  readonly requestId: string;
  readonly expiresAt: number;
}

export interface AuthorizationState {
  readonly requestId: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly requestedScope: string;
  readonly expiresAt: number;
  readonly expired: boolean;
  readonly decision: Readonly<{
    outcome: AuthorizationDecisionOutcome;
    decidedAt: number;
  }> | null;
}

export async function createAuthorizationRequest(
  input: CreateAuthorizationRequestInput,
): Promise<CreatedAuthorizationRequest> {
  if (!isCodeChallengeS256(input.codeChallenge)) {
    return relayFailure("relay_request_invalid", "codeChallenge must be an S256 challenge");
  }
  // The deployment owns client registration, so only a redirect URI it bound to
  // this client may receive an authorization code.
  if (!input.caller.redirectUris.includes(input.redirectUri)) {
    return relayFailure("relay_forbidden", "redirectUri is not registered for this client");
  }
  const createdAt = relayNow(input.clock);
  const record: AuthorizationRequestRecord = Object.freeze({
    version: OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION,
    requestId: randomIdentifier(),
    clientId: input.caller.clientId,
    subject: input.caller.subject,
    organizationAudience: input.caller.organizationAudience,
    redirectUri: input.redirectUri,
    codeChallenge: input.codeChallenge,
    requestedScope: input.requestedScope,
    createdAt,
    expiresAt: createdAt + input.requestTtlMs,
  });
  await withRelayTransaction(input.store, async (transaction) => {
    if (!(await transaction.insertAuthorizationRequest(record))) {
      // 256 bits of CSPRNG output collided, or the store contradicts itself.
      return relayFailure("relay_internal", "authorization request identifier is not unique");
    }
  });
  return Object.freeze({ requestId: record.requestId, expiresAt: record.expiresAt });
}

/**
 * Row-locked read of the request and its decision. Read paths take the same
 * exclusive lock as transitions.
 *
 * ponytail: one lock class for reads and writes; add a shared read mode only if
 * approval-screen traffic measurably contends.
 */
export async function readAuthorizationState(
  transaction: RelayTransaction,
  requestId: string,
  now: number,
  match: (request: AuthorizationRequestRecord) => boolean,
): Promise<AuthorizationState> {
  const request = await transaction.lockAuthorizationRequest(requestId);
  // A caller that is not entitled to this request learns only that it is absent.
  if (!request || !match(request)) {
    return relayFailure("relay_not_found", "authorization request does not exist");
  }
  const decision = await transaction.lockAuthorizationDecision(requestId);
  return Object.freeze({
    requestId: request.requestId,
    clientId: request.clientId,
    redirectUri: request.redirectUri,
    requestedScope: request.requestedScope,
    expiresAt: request.expiresAt,
    expired: now >= request.expiresAt,
    decision: decision
      ? Object.freeze({ outcome: decision.outcome, decidedAt: decision.decidedAt })
      : null,
  });
}

export interface FetchAuthorizationRequestInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  /** Authenticated `owner` caller; only the bound subject may read the request. */
  readonly caller: RelayCaller;
  readonly requestId: string;
}

/** Read for the approving owner. */
export function fetchAuthorizationRequest(
  input: FetchAuthorizationRequestInput,
): Promise<AuthorizationState> {
  const now = relayNow(input.clock);
  return withRelayTransaction(input.store, (transaction) =>
    readAuthorizationState(
      transaction,
      input.requestId,
      now,
      (request) => request.subject === input.caller.subject,
    ),
  );
}
