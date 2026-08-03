/**
 * One-time authorization code with a mandatory PKCE S256 challenge.
 *
 * The record never carries the plaintext code or the verifier: it stores the
 * code's SHA-256 digest and the RFC 7636 S256 challenge. Redemption presents
 * both secrets once and this module decides `issued -> consumed`; nothing here
 * stores or transports anything.
 *
 * @author taek <leekt216@gmail.com>
 */
import { sha256, stringToBytes } from "viem";
import { capturedByProtocol, protocolFailure } from "../errors.js";
import {
  type ClientId,
  type GrantId,
  parseClientId,
  parseGrantId,
  parseSubjectId,
  type SubjectId,
} from "../ids.js";
import {
  type CaptureContext,
  type CaptureFailure,
  captureRecord,
  exactCapturedRecord,
  exactRecord,
} from "../internal/exact-record.js";
import {
  type Duration,
  durationBetween,
  parseDuration,
  parseTimestamp,
  type Timestamp,
} from "../time.js";

export const OAATH_AUTHORIZATION_CODE_VERSION = "oaath.authorization-code/v1" as const;

/** An authorization code may never outlive ten minutes (RFC 6749 ceiling). */
export const MAX_AUTHORIZATION_CODE_LIFETIME: Duration = parseDuration(
  600,
  "authorization code lifetime",
);

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const CODE = /^[A-Za-z0-9_-]{22,128}$/u;
const CODE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/u;
const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;

export type AuthorizationCodeState = "issued" | "consumed" | "expired";

interface AuthorizationCodeCommon {
  readonly version: typeof OAATH_AUTHORIZATION_CODE_VERSION;
  readonly state: AuthorizationCodeState;
  /** SHA-256 digest of the plaintext code; the plaintext never appears here. */
  readonly codeHash: `0x${string}`;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
  readonly clientId: ClientId;
  readonly subjectId: SubjectId;
  /** The authorization request this code redeems, which becomes the grantId. */
  readonly requestId: GrantId;
  readonly issuedAt: Timestamp;
  /** Exclusive expiry: the code is unusable at `expiresAt`. */
  readonly expiresAt: Timestamp;
  readonly consumedAt: Timestamp | null;
}

export interface IssuedAuthorizationCode extends AuthorizationCodeCommon {
  readonly state: "issued";
  readonly consumedAt: null;
}

export interface ConsumedAuthorizationCode extends AuthorizationCodeCommon {
  readonly state: "consumed";
  readonly consumedAt: Timestamp;
}

export interface ExpiredAuthorizationCode extends AuthorizationCodeCommon {
  readonly state: "expired";
  readonly consumedAt: null;
}

export type AuthorizationCode =
  | IssuedAuthorizationCode
  | ConsumedAuthorizationCode
  | ExpiredAuthorizationCode;

/** Captured transition input; `advanceAuthorizationCode` accepts the unvalidated shape. */
export type AuthorizationCodeTransition =
  | Readonly<{ type: "consume"; code: string; codeVerifier: string; consumedAt: Timestamp }>
  | Readonly<{ type: "expire"; expiredAt: Timestamp }>;

function base64UrlDigest(bytes: Uint8Array): string {
  let pending = 0;
  let bits = 0;
  let encoded = "";
  for (const byte of bytes) {
    pending = (pending << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      encoded += B64URL_ALPHABET.charAt((pending >> bits) & 63);
    }
  }
  return bits === 0 ? encoded : encoded + B64URL_ALPHABET.charAt((pending << (6 - bits)) & 63);
}

/** The only owner of the code-to-digest mapping stored in a code record. */
export function hashAuthorizationCode(
  code: unknown,
  fail: CaptureFailure = protocolFailure("authorization_code_invalid"),
): `0x${string}` {
  if (typeof code !== "string" || !CODE.test(code)) {
    return fail("authorization code must be a bounded base64url token");
  }
  return sha256(stringToBytes(code));
}

/** The only owner of the RFC 7636 S256 challenge derivation. */
export function deriveCodeChallenge(
  codeVerifier: unknown,
  fail: CaptureFailure = protocolFailure("authorization_code_verifier_mismatch"),
): string {
  if (typeof codeVerifier !== "string" || !CODE_VERIFIER.test(codeVerifier)) {
    return fail("PKCE code verifier must be 43 to 128 unreserved characters");
  }
  return base64UrlDigest(sha256(stringToBytes(codeVerifier), "bytes"));
}

export function captureAuthorizationCode(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<AuthorizationCode> {
  const record = exactRecord(
    value,
    [
      "version",
      "state",
      "codeHash",
      "codeChallenge",
      "codeChallengeMethod",
      "clientId",
      "subjectId",
      "requestId",
      "issuedAt",
      "expiresAt",
      "consumedAt",
    ],
    "authorization code",
    context,
    fail,
  );
  if (record.version !== OAATH_AUTHORIZATION_CODE_VERSION) {
    return fail("authorization code version is unsupported");
  }
  if (record.codeChallengeMethod !== "S256") {
    return fail("authorization code challenge method must be S256");
  }
  if (typeof record.codeChallenge !== "string" || !CODE_CHALLENGE.test(record.codeChallenge)) {
    return fail("authorization code challenge must be a base64url S256 digest");
  }
  if (typeof record.codeHash !== "string" || !HASH.test(record.codeHash)) {
    return fail("authorization codeHash must be a lowercase 32-byte hash");
  }
  const issuedAt = parseTimestamp(record.issuedAt, "authorization code issuedAt", fail);
  const expiresAt = parseTimestamp(record.expiresAt, "authorization code expiresAt", fail);
  if (expiresAt <= issuedAt) return fail("authorization code expiresAt must follow issuedAt");
  if (
    durationBetween(issuedAt, expiresAt, "authorization code lifetime", fail) >
    MAX_AUTHORIZATION_CODE_LIFETIME
  ) {
    return fail(`authorization code lifetime must not exceed ${MAX_AUTHORIZATION_CODE_LIFETIME}s`);
  }
  const common = {
    version: OAATH_AUTHORIZATION_CODE_VERSION,
    codeHash: record.codeHash as `0x${string}`,
    codeChallenge: record.codeChallenge,
    codeChallengeMethod: "S256",
    clientId: parseClientId(record.clientId, fail),
    subjectId: parseSubjectId(record.subjectId, fail),
    requestId: parseGrantId(record.requestId, fail),
    issuedAt,
    expiresAt,
  } as const;

  if (record.state === "consumed") {
    const consumedAt = parseTimestamp(record.consumedAt, "authorization code consumedAt", fail);
    if (consumedAt < issuedAt || consumedAt >= expiresAt) {
      return fail("authorization code consumedAt must fall inside the code lifetime");
    }
    return Object.freeze({ ...common, state: "consumed", consumedAt });
  }
  if (record.consumedAt !== null) {
    return fail("an unconsumed authorization code must have a null consumedAt");
  }
  if (record.state === "issued")
    return Object.freeze({ ...common, state: "issued", consumedAt: null });
  if (record.state === "expired") {
    return Object.freeze({ ...common, state: "expired", consumedAt: null });
  }
  return fail("authorization code state is unsupported");
}

export function parseAuthorizationCode(value: unknown): Readonly<AuthorizationCode> {
  return capturedByProtocol(
    "authorization_code_invalid",
    "authorization code could not be captured safely",
    () =>
      captureAuthorizationCode(value, new WeakSet(), protocolFailure("authorization_code_invalid")),
  );
}

function captureTransition(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): AuthorizationCodeTransition {
  const captured = captureRecord(value, "authorization code transition", context, fail);
  const record = exactCapturedRecord(
    captured,
    captured.type === "expire"
      ? ["type", "expiredAt"]
      : ["type", "code", "codeVerifier", "consumedAt"],
    "authorization code transition",
    fail,
  );
  if (record.type === "expire") {
    return Object.freeze({
      type: "expire",
      expiredAt: parseTimestamp(record.expiredAt, "authorization code expiredAt", fail),
    });
  }
  if (record.type !== "consume") return fail("authorization code transition type is unsupported");
  if (typeof record.code !== "string" || typeof record.codeVerifier !== "string") {
    return fail("authorization code redemption must present a code and verifier");
  }
  return Object.freeze({
    type: "consume",
    code: record.code,
    codeVerifier: record.codeVerifier,
    consumedAt: parseTimestamp(record.consumedAt, "authorization code consumedAt", fail),
  });
}

/**
 * `issued -> consumed | expired`. Consuming or expiring a terminal record is
 * forbidden, so a replayed redemption never succeeds twice.
 */
export function advanceAuthorizationCode(
  recordValue: unknown,
  transitionValue: unknown,
): Readonly<AuthorizationCode> {
  return capturedByProtocol(
    "authorization_code_invalid",
    "authorization code transition could not be captured safely",
    () => {
      const fail = protocolFailure("authorization_code_invalid");
      const context: CaptureContext = new WeakSet();
      const record = captureAuthorizationCode(recordValue, context, fail);
      const transition = captureTransition(transitionValue, context, fail);
      if (record.state !== "issued") {
        return protocolFailure("authorization_code_transition_forbidden")(
          `a ${record.state} authorization code is terminal`,
        );
      }
      if (transition.type === "expire") {
        if (transition.expiredAt < record.expiresAt) {
          return protocolFailure("authorization_code_transition_forbidden")(
            "an authorization code may not expire before its expiresAt",
          );
        }
        return Object.freeze({ ...record, state: "expired", consumedAt: null });
      }
      if (transition.consumedAt < record.issuedAt || transition.consumedAt >= record.expiresAt) {
        return protocolFailure("authorization_code_transition_forbidden")(
          "an authorization code may only be consumed inside its lifetime",
        );
      }
      if (hashAuthorizationCode(transition.code, fail) !== record.codeHash) {
        return fail("authorization code does not match this record");
      }
      if (
        deriveCodeChallenge(
          transition.codeVerifier,
          protocolFailure("authorization_code_verifier_mismatch"),
        ) !== record.codeChallenge
      ) {
        return protocolFailure("authorization_code_verifier_mismatch")(
          "PKCE code verifier does not match the recorded challenge",
        );
      }
      return Object.freeze({ ...record, state: "consumed", consumedAt: transition.consumedAt });
    },
  );
}
