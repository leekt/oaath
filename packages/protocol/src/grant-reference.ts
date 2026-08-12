/**
 * Adopter-facing Grant reference and revision-verification wire contract.
 *
 * An integrating application (the "adopter") that reviewed a call set needs a
 * narrow, server-verifiable reference binding one immutable artifact — for
 * example a reviewed deployment run — to the exact authority revision that
 * approved it. This module owns the wire shapes both sides speak:
 *
 * - `VerifyGrantRevisionInput` — every field is an assertion the verifier
 *   compares against its durable authorization evidence; no field is ever
 *   trusted as identity. Mismatches deny with a typed code.
 * - `GrantVerificationResult` — `authorized` carries the immutable
 *   `OaathGrantRef` evidence; `denied` and `unknown` carry only a typed code.
 *   Unreadable or absent evidence is `unknown` and never authorizes.
 *
 * OAAth Grant authority is immutable per Grant: the policy is fixed in the
 * Grant identity and an authority change is a revocation plus a new Grant. The
 * single approval is therefore authority revision
 * `OAATH_GRANT_REFERENCE_APPROVED_REVISION` (1); a future re-approval protocol
 * would increment it. This authority revision is deliberately not the client
 * aggregate `Grant.revision`, which also advances on per-chain bookkeeping.
 *
 * `policyDigest` is the Grant identity's `policyHash`
 * (`hashGrantPolicy(requestedPolicy)`); `requiredCallsDigest` is
 * `hashGrantPolicyCalls` over the reviewed call set, and verification requires
 * exact equality with the permitted call set — a subset still denies, which
 * fails closed.
 *
 * @author taek <leekt216@gmail.com>
 */

import { capturedByProtocol, protocolFailure } from "./errors.js";
import type { CaptureContext, CaptureFailure } from "./internal/exact-record.js";
import { captureRecord, exactCapturedRecord, exactRecord } from "./internal/exact-record.js";

export const OAATH_GRANT_REFERENCE_VERSION = "oaath.grant-reference/v1" as const;

/** The one authority revision an approved Grant has today. */
export const OAATH_GRANT_REFERENCE_APPROVED_REVISION = 1;

const HASH = /^0x[0-9a-f]{64}$/u;
/** Matches the relay's canonical identifier domain for authenticated bindings. */
const IDENTIFIER = /^[A-Za-z0-9._~-]{1,256}$/u;
const MAX_REVISION = 2 ** 48 - 1;

const fail: CaptureFailure = protocolFailure("grant_reference_invalid");

export type OaathGrantRefState = "pending" | "active" | "revoked" | "expired";

/**
 * Immutable server-verified evidence suitable for persistence by the adopter.
 * Only an `authorized` verification produces one, so today its `state` is
 * always `"active"`; the enum stays total so a future projection surface can
 * reuse the shape.
 */
export interface OaathGrantRef {
  readonly version: typeof OAATH_GRANT_REFERENCE_VERSION;
  readonly grantId: string;
  readonly revision: number;
  readonly subject: string;
  readonly clientId: string;
  readonly organizationAudience: string;
  readonly state: OaathGrantRefState;
  readonly policyDigest: `0x${string}`;
}

export interface VerifyGrantRevisionInput {
  readonly grantId: string;
  readonly revision: number;
  readonly subject: string;
  readonly clientId: string;
  readonly organizationAudience: string;
  readonly requiredCallsDigest: `0x${string}`;
}

export type GrantVerificationDeniedCode =
  /** The authorization request exists but the owner has not decided yet. */
  | "grant_pending"
  /** The owner rejected the authorization request; the Grant never activated. */
  | "grant_rejected"
  /** The Grant's capability is durably invalidated. */
  | "grant_revoked"
  /** The approved authority is past its policy expiry. */
  | "grant_expired"
  /** The asserted revision is not the exact approved authority revision. */
  | "grant_revision_mismatch"
  | "grant_subject_mismatch"
  | "grant_client_mismatch"
  | "grant_audience_mismatch"
  /** The reviewed call set is not exactly the permitted call set. */
  | "grant_calls_mismatch";

export type GrantVerificationUnknownCode =
  /** No Grant the caller is entitled to see; absence, not an existence oracle. */
  | "grant_unknown"
  /** Stored evidence is unreadable or contradictory. Never authorizes. */
  | "grant_unreadable";

export type GrantVerificationResult =
  | Readonly<{ state: "authorized"; ref: Readonly<OaathGrantRef> }>
  | Readonly<{ state: "denied"; code: GrantVerificationDeniedCode }>
  | Readonly<{ state: "unknown"; code: GrantVerificationUnknownCode }>;

const DENIED_CODES: ReadonlySet<string> = new Set<GrantVerificationDeniedCode>([
  "grant_pending",
  "grant_rejected",
  "grant_revoked",
  "grant_expired",
  "grant_revision_mismatch",
  "grant_subject_mismatch",
  "grant_client_mismatch",
  "grant_audience_mismatch",
  "grant_calls_mismatch",
]);

const UNKNOWN_CODES: ReadonlySet<string> = new Set<GrantVerificationUnknownCode>([
  "grant_unknown",
  "grant_unreadable",
]);

const REF_STATES: ReadonlySet<string> = new Set<OaathGrantRefState>([
  "pending",
  "active",
  "revoked",
  "expired",
]);

function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    return fail(`${label} must be a bounded URL-safe identifier`);
  }
  return value;
}

function grantId(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    value !== value.trim()
  ) {
    return fail("grantId must be a bounded canonical string");
  }
  return value;
}

function digest(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return fail(`${label} must be a lowercase 32-byte hash`);
  }
  return value as `0x${string}`;
}

function revision(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    (value as number) < 1 ||
    (value as number) > MAX_REVISION
  ) {
    return fail("revision must be a positive uint48 safe integer");
  }
  return value as number;
}

function capturedByReference<Value>(action: () => Value): Value {
  return capturedByProtocol(
    "grant_reference_invalid",
    "grant reference input could not be captured safely",
    action,
  );
}

export function parseVerifyGrantRevisionInput(value: unknown): Readonly<VerifyGrantRevisionInput> {
  return capturedByReference(() => {
    const context: CaptureContext = new WeakSet();
    const record = exactRecord(
      value,
      ["grantId", "revision", "subject", "clientId", "organizationAudience", "requiredCallsDigest"],
      "verify grant revision input",
      context,
      fail,
    );
    return Object.freeze({
      grantId: grantId(record.grantId),
      revision: revision(record.revision),
      subject: identifier(record.subject, "subject"),
      clientId: identifier(record.clientId, "clientId"),
      organizationAudience: identifier(record.organizationAudience, "organizationAudience"),
      requiredCallsDigest: digest(record.requiredCallsDigest, "requiredCallsDigest"),
    });
  });
}

export function parseOaathGrantRef(value: unknown): Readonly<OaathGrantRef> {
  return capturedByReference(() => {
    const context: CaptureContext = new WeakSet();
    const record = exactRecord(
      value,
      [
        "version",
        "grantId",
        "revision",
        "subject",
        "clientId",
        "organizationAudience",
        "state",
        "policyDigest",
      ],
      "grant reference",
      context,
      fail,
    );
    if (record.version !== OAATH_GRANT_REFERENCE_VERSION) {
      return fail("grant reference version is unsupported");
    }
    if (typeof record.state !== "string" || !REF_STATES.has(record.state)) {
      return fail("grant reference state is unsupported");
    }
    return Object.freeze({
      version: OAATH_GRANT_REFERENCE_VERSION,
      grantId: grantId(record.grantId),
      revision: revision(record.revision),
      subject: identifier(record.subject, "subject"),
      clientId: identifier(record.clientId, "clientId"),
      organizationAudience: identifier(record.organizationAudience, "organizationAudience"),
      state: record.state as OaathGrantRefState,
      policyDigest: digest(record.policyDigest, "policyDigest"),
    });
  });
}

/**
 * Parses one verification result exactly. Adopters must parse every response
 * through this before acting on it; anything unreadable throws and therefore
 * never authorizes.
 */
export function parseGrantVerificationResult(value: unknown): GrantVerificationResult {
  return capturedByReference(() => {
    const context: CaptureContext = new WeakSet();
    const captured = captureRecord(value, "grant verification result", context, fail);
    if (captured.state === "authorized") {
      const record = exactCapturedRecord(
        captured,
        ["state", "ref"],
        "grant verification result",
        fail,
      );
      return Object.freeze({ state: "authorized" as const, ref: parseOaathGrantRef(record.ref) });
    }
    if (captured.state === "denied") {
      const record = exactCapturedRecord(
        captured,
        ["state", "code"],
        "grant verification result",
        fail,
      );
      if (typeof record.code !== "string" || !DENIED_CODES.has(record.code)) {
        return fail("grant verification denial code is unsupported");
      }
      return Object.freeze({
        state: "denied" as const,
        code: record.code as GrantVerificationDeniedCode,
      });
    }
    if (captured.state === "unknown") {
      const record = exactCapturedRecord(
        captured,
        ["state", "code"],
        "grant verification result",
        fail,
      );
      if (typeof record.code !== "string" || !UNKNOWN_CODES.has(record.code)) {
        return fail("grant verification unknown code is unsupported");
      }
      return Object.freeze({
        state: "unknown" as const,
        code: record.code as GrantVerificationUnknownCode,
      });
    }
    return fail("grant verification result state is unsupported");
  });
}
