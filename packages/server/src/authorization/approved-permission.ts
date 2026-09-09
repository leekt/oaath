/** Retained service-approved policy, independent of OAuth claim or execution expiry. */
import {
  applyPermissionDecision,
  createGrantFromPermissionRequest,
  type PermissionRequest,
  parsePermissionDecision,
} from "@oaath/protocol";
import { openArtifact } from "../artifact/encrypt.js";
import type { RelayKms } from "../security/kms.js";
import type { RelayTransaction } from "../store/interface.js";
import type { AuthorizationDecisionRecord, AuthorizationRequestRecord } from "../store/records.js";

/**
 * The same protocol approval meaning at admission and after durable recovery.
 * Kernel capability verification belongs to the SDK; this owner checks the
 * decision's request binding, policy attenuation and reported decision time.
 * Evaluate at that time so a retained approval remains readable for revocation
 * after its execution or OAuth claim window has closed.
 */
export function parseApprovedPermission(
  plaintext: string,
  permissionRequest: Readonly<PermissionRequest>,
  relayDecidedAt: number,
) {
  const value = JSON.parse(plaintext) as unknown;
  const decisionValue =
    value !== null && typeof value === "object" && "installApproval" in value
      ? (({ installApproval: _install, ...permission }) => permission)(value)
      : value;
  const permission = parsePermissionDecision(decisionValue);
  if (permission.kind !== "approve" || permission.decidedAt > Math.floor(relayDecidedAt / 1_000))
    throw new Error("permission artifact is not an approved decision at the relay decision time");
  const applied = applyPermissionDecision({
    request: permissionRequest,
    grant: createGrantFromPermissionRequest(permissionRequest),
    observation: { status: "available", decision: permission },
    evaluatedAt: permission.decidedAt,
  });
  if (applied.status !== "applied" || applied.grant.state !== "approved")
    throw new Error("permission artifact does not approve this request");
  return { permission, plaintext };
}

/** Kernel capability verification remains the SDK preparation owner's responsibility. */
export async function readApprovedPermission(
  transaction: RelayTransaction,
  kms: RelayKms,
  request: AuthorizationRequestRecord,
  decision: AuthorizationDecisionRecord,
  permissionRequest: Readonly<PermissionRequest>,
) {
  try {
    const artifact = await transaction.lockEncryptedArtifactByRequestId(request.requestId);
    if (
      !artifact ||
      artifact.requestId !== request.requestId ||
      artifact.clientId !== request.clientId ||
      artifact.createdAt !== decision.decidedAt
    )
      return null;
    const plaintext = await openArtifact(kms, artifact.ciphertextRef);
    return parseApprovedPermission(plaintext, permissionRequest, decision.decidedAt);
  } catch {
    return null;
  }
}
