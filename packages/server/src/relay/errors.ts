/**
 * Closed relay failure codes and their stable HTTP projection.
 *
 * Machine decisions and wire responses use these codes only. `Error.message`
 * exists for local diagnostics and never reaches a response body.
 *
 * @author taek <leekt216@gmail.com>
 */

export type RelayErrorCode =
  /** Wire input is missing, malformed, oversized, or contains unknown fields. */
  | "relay_request_invalid"
  /** The deployment authentication port did not authenticate the caller. */
  | "relay_unauthenticated"
  /** Authenticated caller may not act in the required role. */
  | "relay_forbidden"
  /** Route, or a record the caller is entitled to see, does not exist. */
  | "relay_not_found"
  /** Route exists with a different method. */
  | "relay_method_not_allowed"
  /** The authorization request or code is past its injected-clock expiry. */
  | "relay_expired"
  /** The authorization request already reached a terminal decision. */
  | "relay_already_decided"
  /** The one-time authorization code was already consumed. */
  | "relay_code_already_consumed"
  /** The one-time encrypted artifact was already claimed. */
  | "relay_artifact_already_claimed"
  /**
   * Authorization code redemption failed. One code for every reason it can
   * fail — unknown code, another client's code, wrong redirect URI, wrong PKCE
   * verifier — so the endpoint never confirms that a guessed code was correct.
   * A code that existed is burned.
   */
  | "relay_code_invalid"
  /** The optional deployment limiter rejected the call. */
  | "relay_rate_limited"
  /** A durable record could not be read as the current schema version. */
  | "relay_record_unreadable"
  /** The KMS port was unavailable or returned an unusable result. */
  | "relay_kms_unavailable"
  /** The store failed before any state change could have been committed. */
  | "relay_store_unavailable"
  /**
   * The store could not prove whether a transition committed. The caller must
   * treat the transition as neither applied nor retryable: an ambiguous commit
   * never authorizes resubmission.
   */
  | "relay_state_ambiguous"
  /** An invariant the relay owns was violated. */
  | "relay_internal";

/**
 * Status projection. `relay_state_ambiguous` is deliberately 500 and not 503,
 * because 503 invites the retry that an ambiguous commit forbids.
 */
export const RELAY_ERROR_STATUS: Readonly<Record<RelayErrorCode, number>> = Object.freeze({
  relay_request_invalid: 400,
  relay_unauthenticated: 401,
  relay_forbidden: 403,
  relay_not_found: 404,
  relay_method_not_allowed: 405,
  relay_expired: 410,
  relay_already_decided: 409,
  relay_code_already_consumed: 409,
  relay_artifact_already_claimed: 409,
  relay_code_invalid: 400,
  relay_rate_limited: 429,
  relay_record_unreadable: 500,
  relay_kms_unavailable: 503,
  relay_store_unavailable: 503,
  relay_state_ambiguous: 500,
  relay_internal: 500,
});

export class OaathRelayError extends Error {
  readonly code: RelayErrorCode;

  constructor(code: RelayErrorCode, message: string) {
    super(message);
    this.name = "OaathRelayError";
    this.code = code;
  }
}

export function relayFailure(code: RelayErrorCode, message: string): never {
  throw new OaathRelayError(code, message);
}

/** Any non-relay throw is an unreadable internal failure, never caller-visible detail. */
export function relayErrorCode(error: unknown): RelayErrorCode {
  return error instanceof OaathRelayError ? error.code : "relay_internal";
}

const RESPONSE_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
});

export function relayErrorResponse(code: RelayErrorCode): Response {
  return jsonResponse(RELAY_ERROR_STATUS[code], { error: { code } });
}

export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: RESPONSE_HEADERS });
}
