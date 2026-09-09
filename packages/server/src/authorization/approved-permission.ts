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
    const value = JSON.parse(plaintext) as unknown;
    // The current SDK appends its separately owned install capability to
    // the protocol decision. It is not evidence of onchain installation.
    const decisionValue =
      value !== null && typeof value === "object" && "installApproval" in value
        ? (({ installApproval: _install, ...permission }) => permission)(value)
        : value;
    const permission = parsePermissionDecision(decisionValue);
    if (
      permission.kind !== "approve" ||
      permission.decidedAt > Math.floor(decision.decidedAt / 1_000)
    )
      return null;
    const applied = applyPermissionDecision({
      request: permissionRequest,
      grant: createGrantFromPermissionRequest(permissionRequest),
      observation: { status: "available", decision: permission },
      evaluatedAt: permission.decidedAt,
    });
    return applied.status === "applied" && applied.grant.state === "approved"
      ? { permission, plaintext }
      : null;
  } catch {
    return null;
  }
}
