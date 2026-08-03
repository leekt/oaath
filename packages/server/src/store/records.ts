/**
 * Exact current-version durable relay records.
 *
 * Durable storage is a trust boundary: every read is captured into an exact,
 * owned, immutable record before typed code consumes it. There is exactly one
 * current version per record and no reader for any older version.
 *
 * These shapes are relay-owned for now. `@oaath/protocol` owns the wire
 * `AuthorizationRequest`, `AuthorizationDecision`, and `AuthorizationCode`
 * contracts; adopting them here is a follow-up because the units differ (this
 * store keeps epoch milliseconds, the protocol speaks whole seconds) and the
 * code digest differs (base64url WebCrypto here, `0x` hex there). Once adopted,
 * this file should keep only the store envelope around those records.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type CaptureContext, exactRecord } from "@oaath/protocol";
import { type RelayErrorCode, relayFailure } from "../relay/errors.js";

export const OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION =
  "oaath.authorization-request-record/v1" as const;
export const OAATH_AUTHORIZATION_DECISION_RECORD_VERSION =
  "oaath.authorization-decision-record/v1" as const;
export const OAATH_AUTHORIZATION_CODE_RECORD_VERSION =
  "oaath.authorization-code-record/v1" as const;
export const OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION =
  "oaath.encrypted-artifact-record/v1" as const;

/** Bounded field limits owned here and shared with wire capture. */
export const RELAY_LIMITS = Object.freeze({
  identifier: 256,
  redirectUri: 2048,
  codeChallenge: 128,
  codeVerifier: 128,
  requestedScope: 8192,
  artifactPlaintext: 32_768,
  ciphertextRef: 65_536,
});

const MAX_TIMESTAMP = Number.MAX_SAFE_INTEGER;

export interface AuthorizationRequestRecord {
  readonly version: typeof OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION;
  readonly requestId: string;
  /** Client bound by the deployment authentication port, never by wire input. */
  readonly clientId: string;
  /** Pairwise user/device subject bound by the authentication port. */
  readonly subject: string;
  readonly redirectUri: string;
  /** PKCE S256 challenge; the verifier never reaches the store. */
  readonly codeChallenge: string;
  /** Opaque owner-reviewed scope payload. Migrates to @oaath/protocol. */
  readonly requestedScope: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export type AuthorizationDecisionOutcome = "approved" | "rejected";

/**
 * Terminal decision. Its existence is the single authoritative fact that an
 * authorization request was decided; the request record never mutates.
 */
export interface AuthorizationDecisionRecord {
  readonly version: typeof OAATH_AUTHORIZATION_DECISION_RECORD_VERSION;
  readonly requestId: string;
  readonly outcome: AuthorizationDecisionOutcome;
  readonly decidedAt: number;
}

export interface AuthorizationCodeRecord {
  readonly version: typeof OAATH_AUTHORIZATION_CODE_RECORD_VERSION;
  /** SHA-256 (base64url) of the released code. The code itself is never stored. */
  readonly codeHash: string;
  readonly requestId: string;
  /** Binding snapshot taken at issue time so consume needs exactly one row lock. */
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly artifactId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  /** Set exactly once. A non-null value is terminal. */
  readonly consumedAt: number | null;
}

export interface EncryptedArtifactRecord {
  readonly version: typeof OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION;
  readonly artifactId: string;
  readonly requestId: string;
  readonly clientId: string;
  /** Opaque KMS reference. Plaintext never reaches the store. */
  readonly ciphertextRef: string;
  readonly createdAt: number;
  /** Set exactly once. A non-null value is terminal. */
  readonly claimedAt: number | null;
}

export function boundedText(
  value: unknown,
  maximum: number,
  label: string,
  code: RelayErrorCode,
): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
    return relayFailure(code, `${label} must be a bounded non-empty string`);
  }
  // Control characters would corrupt logs and downstream headers.
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit < 0x20 || unit === 0x7f) {
      return relayFailure(code, `${label} must not contain control characters`);
    }
  }
  return value;
}

export function canonicalIdentifier(value: unknown, label: string, code: RelayErrorCode): string {
  const text = boundedText(value, RELAY_LIMITS.identifier, label, code);
  if (!/^[A-Za-z0-9._~-]+$/u.test(text)) {
    return relayFailure(code, `${label} must be URL-safe`);
  }
  return text;
}

export function timestamp(value: unknown, label: string, code: RelayErrorCode): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0 ||
    value > MAX_TIMESTAMP
  ) {
    return relayFailure(code, `${label} must be a non-negative safe integer`);
  }
  return value;
}

function nullableTimestamp(value: unknown, label: string, code: RelayErrorCode): number | null {
  return value === null ? null : timestamp(value, label, code);
}

const UNREADABLE: RelayErrorCode = "relay_record_unreadable";

function captured(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  const context: CaptureContext = new WeakSet();
  return exactRecord(value, keys, label, context, (message) => relayFailure(UNREADABLE, message));
}

function version<Value extends string>(value: unknown, expected: Value, label: string): Value {
  if (value !== expected) {
    return relayFailure(UNREADABLE, `${label} version is unsupported`);
  }
  return expected;
}

export function parseAuthorizationRequestRecord(value: unknown): AuthorizationRequestRecord {
  const record = captured(
    value,
    [
      "version",
      "requestId",
      "clientId",
      "subject",
      "redirectUri",
      "codeChallenge",
      "requestedScope",
      "createdAt",
      "expiresAt",
    ],
    "authorization request record",
  );
  return Object.freeze({
    version: version(
      record.version,
      OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION,
      "authorization request record",
    ),
    requestId: canonicalIdentifier(record.requestId, "requestId", UNREADABLE),
    clientId: canonicalIdentifier(record.clientId, "clientId", UNREADABLE),
    subject: canonicalIdentifier(record.subject, "subject", UNREADABLE),
    redirectUri: boundedText(
      record.redirectUri,
      RELAY_LIMITS.redirectUri,
      "redirectUri",
      UNREADABLE,
    ),
    codeChallenge: canonicalIdentifier(record.codeChallenge, "codeChallenge", UNREADABLE),
    requestedScope: boundedText(
      record.requestedScope,
      RELAY_LIMITS.requestedScope,
      "requestedScope",
      UNREADABLE,
    ),
    createdAt: timestamp(record.createdAt, "createdAt", UNREADABLE),
    expiresAt: timestamp(record.expiresAt, "expiresAt", UNREADABLE),
  });
}

export function parseAuthorizationDecisionRecord(value: unknown): AuthorizationDecisionRecord {
  const record = captured(
    value,
    ["version", "requestId", "outcome", "decidedAt"],
    "authorization decision record",
  );
  if (record.outcome !== "approved" && record.outcome !== "rejected") {
    return relayFailure(UNREADABLE, "decision outcome is unsupported");
  }
  return Object.freeze({
    version: version(
      record.version,
      OAATH_AUTHORIZATION_DECISION_RECORD_VERSION,
      "authorization decision record",
    ),
    requestId: canonicalIdentifier(record.requestId, "requestId", UNREADABLE),
    outcome: record.outcome,
    decidedAt: timestamp(record.decidedAt, "decidedAt", UNREADABLE),
  });
}

export function parseAuthorizationCodeRecord(value: unknown): AuthorizationCodeRecord {
  const record = captured(
    value,
    [
      "version",
      "codeHash",
      "requestId",
      "clientId",
      "redirectUri",
      "codeChallenge",
      "artifactId",
      "createdAt",
      "expiresAt",
      "consumedAt",
    ],
    "authorization code record",
  );
  return Object.freeze({
    version: version(
      record.version,
      OAATH_AUTHORIZATION_CODE_RECORD_VERSION,
      "authorization code record",
    ),
    codeHash: canonicalIdentifier(record.codeHash, "codeHash", UNREADABLE),
    requestId: canonicalIdentifier(record.requestId, "requestId", UNREADABLE),
    clientId: canonicalIdentifier(record.clientId, "clientId", UNREADABLE),
    redirectUri: boundedText(
      record.redirectUri,
      RELAY_LIMITS.redirectUri,
      "redirectUri",
      UNREADABLE,
    ),
    codeChallenge: canonicalIdentifier(record.codeChallenge, "codeChallenge", UNREADABLE),
    artifactId: canonicalIdentifier(record.artifactId, "artifactId", UNREADABLE),
    createdAt: timestamp(record.createdAt, "createdAt", UNREADABLE),
    expiresAt: timestamp(record.expiresAt, "expiresAt", UNREADABLE),
    consumedAt: nullableTimestamp(record.consumedAt, "consumedAt", UNREADABLE),
  });
}

export function parseEncryptedArtifactRecord(value: unknown): EncryptedArtifactRecord {
  const record = captured(
    value,
    ["version", "artifactId", "requestId", "clientId", "ciphertextRef", "createdAt", "claimedAt"],
    "encrypted artifact record",
  );
  return Object.freeze({
    version: version(
      record.version,
      OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION,
      "encrypted artifact record",
    ),
    artifactId: canonicalIdentifier(record.artifactId, "artifactId", UNREADABLE),
    requestId: canonicalIdentifier(record.requestId, "requestId", UNREADABLE),
    clientId: canonicalIdentifier(record.clientId, "clientId", UNREADABLE),
    ciphertextRef: boundedText(
      record.ciphertextRef,
      RELAY_LIMITS.ciphertextRef,
      "ciphertextRef",
      UNREADABLE,
    ),
    createdAt: timestamp(record.createdAt, "createdAt", UNREADABLE),
    claimedAt: nullableTimestamp(record.claimedAt, "claimedAt", UNREADABLE),
  });
}
