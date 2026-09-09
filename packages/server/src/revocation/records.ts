/** Current immutable revocation request and terminal phone decision. No submission evidence. */
import {
  exactRecord,
  type KernelV4RevocationSigningRequest,
  parseKernelV4RevocationSigningRequest,
} from "@oaath/protocol";
import { relayFailure } from "../relay/errors.js";
import { boundedText, canonicalIdentifier, RELAY_LIMITS, timestamp } from "../store/records.js";

export const OAATH_REVOCATION_REQUEST_RECORD_VERSION =
  "oaath.revocation-request-record/v1" as const;
export const OAATH_REVOCATION_DECISION_RECORD_VERSION =
  "oaath.revocation-decision-record/v1" as const;
/** Separates owner operations from authorization request IDs on the shared phone route. */
export const REVOCATION_OPERATION_PREFIX = "revocation-";

export interface RevocationRequestRecord {
  readonly version: typeof OAATH_REVOCATION_REQUEST_RECORD_VERSION;
  readonly operationId: string;
  readonly ownerDeviceId: string;
  readonly ownerSubject: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly signingRequest: Readonly<KernelV4RevocationSigningRequest>;
}
export interface RevocationDecisionRecord {
  readonly version: typeof OAATH_REVOCATION_DECISION_RECORD_VERSION;
  readonly operationId: string;
  readonly outcome: "approved" | "rejected";
  readonly decidedAt: number;
  /** Sealed canonical phone artifact; null exactly for rejection. Never an OAuth release. */
  readonly artifactRef: string | null;
}
const UNREADABLE = "relay_record_unreadable" as const;
const fail = (message: string): never => relayFailure(UNREADABLE, message);
function capture(value: unknown, keys: readonly string[]): Record<string, unknown> {
  return exactRecord(value, keys, "revocation record", new WeakSet(), fail);
}
function operationId(value: unknown): string {
  const id = canonicalIdentifier(value, "operationId", UNREADABLE);
  if (!id.startsWith(REVOCATION_OPERATION_PREFIX) || id.length > 64)
    return fail("revocation operation ID is invalid");
  return id;
}
export function parseRevocationRequestRecord(value: unknown): Readonly<RevocationRequestRecord> {
  const record = capture(value, [
    "version",
    "operationId",
    "ownerDeviceId",
    "ownerSubject",
    "createdAt",
    "expiresAt",
    "signingRequest",
  ]);
  if (record.version !== OAATH_REVOCATION_REQUEST_RECORD_VERSION)
    return fail("revocation request version is unsupported");
  const createdAt = timestamp(record.createdAt, "createdAt", UNREADABLE);
  const expiresAt = timestamp(record.expiresAt, "expiresAt", UNREADABLE);
  if (expiresAt < createdAt) return fail("revocation request expiry precedes creation");
  let signingRequest: Readonly<KernelV4RevocationSigningRequest>;
  try {
    signingRequest = parseKernelV4RevocationSigningRequest(record.signingRequest);
  } catch {
    return fail("stored revocation signing request is unreadable");
  }
  return Object.freeze({
    version: record.version,
    operationId: operationId(record.operationId),
    ownerDeviceId: canonicalIdentifier(record.ownerDeviceId, "ownerDeviceId", UNREADABLE),
    ownerSubject: canonicalIdentifier(record.ownerSubject, "ownerSubject", UNREADABLE),
    createdAt,
    expiresAt,
    signingRequest,
  });
}
export function parseRevocationDecisionRecord(value: unknown): Readonly<RevocationDecisionRecord> {
  const record = capture(value, ["version", "operationId", "outcome", "decidedAt", "artifactRef"]);
  if (
    record.version !== OAATH_REVOCATION_DECISION_RECORD_VERSION ||
    (record.outcome !== "approved" && record.outcome !== "rejected")
  )
    return fail("revocation decision is unsupported");
  if ((record.outcome === "rejected") !== (record.artifactRef === null))
    return fail("revocation decision contradicts artifact custody");
  return Object.freeze({
    version: record.version,
    operationId: operationId(record.operationId),
    outcome: record.outcome,
    decidedAt: timestamp(record.decidedAt, "decidedAt", UNREADABLE),
    artifactRef:
      record.artifactRef === null
        ? null
        : boundedText(record.artifactRef, RELAY_LIMITS.ciphertextRef, "artifactRef", UNREADABLE),
  });
}
