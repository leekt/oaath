/**
 * Terminal approve/reject envelope.
 *
 * The decision itself, its request binding, and its hash stay owned by
 * `permission-protocol.ts`. The envelope only names the pairwise subject the
 * decision was made for, so a decision cannot be replayed onto another subject.
 *
 * @author taek <leekt216@gmail.com>
 */
import { capturedByProtocol, protocolFailure } from "../errors.js";
import { parseSubjectId, type SubjectId } from "../ids.js";
import { type CaptureContext, type CaptureFailure, exactRecord } from "../internal/exact-record.js";
import { type PermissionDecision, parsePermissionDecision } from "../permission-protocol.js";

export const OAATH_AUTHORIZATION_DECISION_VERSION = "oaath.authorization-decision/v1" as const;

export interface AuthorizationDecision {
  readonly version: typeof OAATH_AUTHORIZATION_DECISION_VERSION;
  readonly subjectId: SubjectId;
  /** The unmodified terminal decision owned by `permission-protocol.ts`. */
  readonly decision: Readonly<PermissionDecision>;
}

export function captureAuthorizationDecision(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<AuthorizationDecision> {
  const record = exactRecord(
    value,
    ["version", "subjectId", "decision"],
    "authorization decision",
    context,
    fail,
  );
  if (record.version !== OAATH_AUTHORIZATION_DECISION_VERSION) {
    return fail("authorization decision version is unsupported");
  }
  return Object.freeze({
    version: OAATH_AUTHORIZATION_DECISION_VERSION,
    subjectId: parseSubjectId(record.subjectId, fail),
    decision: parsePermissionDecision(record.decision),
  });
}

export function parseAuthorizationDecision(value: unknown): Readonly<AuthorizationDecision> {
  return capturedByProtocol(
    "authorization_decision_invalid",
    "authorization decision could not be captured safely",
    () =>
      captureAuthorizationDecision(
        value,
        new WeakSet(),
        protocolFailure("authorization_decision_invalid"),
      ),
  );
}
