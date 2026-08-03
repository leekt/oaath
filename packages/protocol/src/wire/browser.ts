/**
 * The one browser <-> issuer envelope.
 *
 * Every message on the channel is exactly `{ version, kind, payload }` with a
 * closed `kind` set. An error envelope carries a machine-readable code and
 * nothing else: no message text, no provider prose, no stack.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type AuthorizationDecision,
  captureAuthorizationDecision,
} from "../authorization/decision.js";
import {
  type AuthorizationRequest,
  captureAuthorizationRequest,
} from "../authorization/request.js";
import {
  capturedByProtocol,
  isOaathProtocolErrorCode,
  type OaathProtocolErrorCode,
  protocolFailure,
} from "../errors.js";
import {
  type CaptureContext,
  type CaptureFailure,
  captureRecord,
  exactCapturedRecord,
} from "../internal/exact-record.js";

export const OAATH_BROWSER_ENVELOPE_VERSION = "oaath.browser-envelope/v1" as const;

export type BrowserEnvelopeKind = "authorization_request" | "authorization_decision" | "error";

export interface BrowserErrorPayload {
  readonly code: OaathProtocolErrorCode;
}

export type BrowserEnvelope =
  | Readonly<{
      version: typeof OAATH_BROWSER_ENVELOPE_VERSION;
      kind: "authorization_request";
      payload: Readonly<AuthorizationRequest>;
    }>
  | Readonly<{
      version: typeof OAATH_BROWSER_ENVELOPE_VERSION;
      kind: "authorization_decision";
      payload: Readonly<AuthorizationDecision>;
    }>
  | Readonly<{
      version: typeof OAATH_BROWSER_ENVELOPE_VERSION;
      kind: "error";
      payload: Readonly<BrowserErrorPayload>;
    }>;

export function captureBrowserEnvelope(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): BrowserEnvelope {
  const record = exactCapturedRecord(
    captureRecord(value, "browser envelope", context, fail),
    ["version", "kind", "payload"],
    "browser envelope",
    fail,
  );
  if (record.version !== OAATH_BROWSER_ENVELOPE_VERSION) {
    return fail("browser envelope version is unsupported");
  }
  if (record.kind === "authorization_request") {
    return Object.freeze({
      version: OAATH_BROWSER_ENVELOPE_VERSION,
      kind: "authorization_request",
      payload: captureAuthorizationRequest(record.payload, context, fail),
    });
  }
  if (record.kind === "authorization_decision") {
    return Object.freeze({
      version: OAATH_BROWSER_ENVELOPE_VERSION,
      kind: "authorization_decision",
      payload: captureAuthorizationDecision(record.payload, context, fail),
    });
  }
  if (record.kind !== "error") return fail("browser envelope kind is unsupported");
  const payload = exactCapturedRecord(
    captureRecord(record.payload, "browser error payload", context, fail),
    ["code"],
    "browser error payload",
    fail,
  );
  if (!isOaathProtocolErrorCode(payload.code)) {
    return fail("browser error payload code is not a protocol error code");
  }
  return Object.freeze({
    version: OAATH_BROWSER_ENVELOPE_VERSION,
    kind: "error",
    payload: Object.freeze({ code: payload.code }),
  });
}

export function parseBrowserEnvelope(value: unknown): BrowserEnvelope {
  return capturedByProtocol(
    "wire_envelope_invalid",
    "browser envelope could not be captured safely",
    () => captureBrowserEnvelope(value, new WeakSet(), protocolFailure("wire_envelope_invalid")),
  );
}
