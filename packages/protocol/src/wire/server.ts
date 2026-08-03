/**
 * Server side of the same envelope: status mapping by code only.
 *
 * A status is decided from the machine-readable protocol code, never from
 * `Error.message`, and the response body is the closed browser envelope so a
 * server can never invent a second wire shape.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { OaathProtocolErrorCode } from "../errors.js";
import { type BrowserEnvelope, OAATH_BROWSER_ENVELOPE_VERSION } from "./browser.js";

/** `400` caller must fix input, `409` authoritative state already decided, `500` internal limit. */
export type ProtocolErrorStatus = 400 | 409 | 500;

/** State already decided elsewhere: retrying the same request cannot succeed. */
const CONFLICT: ReadonlySet<OaathProtocolErrorCode> = new Set<OaathProtocolErrorCode>([
  "authorization_code_transition_forbidden",
  "grant_identity_mismatch",
  "grant_transition_forbidden",
  "operation_identity_mismatch",
  "operation_transition_forbidden",
  "permission_request_binding_mismatch",
  "permission_decision_binding_mismatch",
  "permission_decision_conflict",
  "permission_decision_stale",
  "permission_policy_widening",
]);

/** An owned invariant limit rather than anything the caller supplied. */
const INTERNAL: ReadonlySet<OaathProtocolErrorCode> = new Set<OaathProtocolErrorCode>([
  "grant_revision_exhausted",
  "operation_revision_exhausted",
]);

export function protocolErrorStatus(code: OaathProtocolErrorCode): ProtocolErrorStatus {
  if (INTERNAL.has(code)) return 500;
  return CONFLICT.has(code) ? 409 : 400;
}

/** The only server error body: one code, no diagnostic text. */
export function serverErrorEnvelope(code: OaathProtocolErrorCode): BrowserEnvelope {
  return Object.freeze({
    version: OAATH_BROWSER_ENVELOPE_VERSION,
    kind: "error",
    payload: Object.freeze({ code }),
  });
}
