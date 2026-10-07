/**
 * The relay's stored-scope classification and approved-permission check, kept
 * here as the TypeScript reference the Rust relay's fixtures are generated
 * from (`scripts/export-protocol-fixtures.mjs`). Not a package export.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  applyPermissionDecision,
  createGrantFromPermissionRequest,
  type KernelReplayableInstallOwnerSigningRequest,
  type OwnerSigningRequest,
  type PermissionRequest,
  parseKernelReplayableInstallOwnerSigningRequest,
  parseOwnerSigningRequest,
  parsePermissionDecision,
  parsePermissionRequest,
} from "../index.js";

export type StoredAuthorizationScope =
  | Readonly<{
      kind: "permission-request";
      decision: "approve-or-reject";
      request: Readonly<PermissionRequest>;
    }>
  | Readonly<{
      kind: "kernel-owner-signing-request";
      decision: "approve-or-reject";
      request: Readonly<KernelReplayableInstallOwnerSigningRequest>;
    }>
  | Readonly<{
      kind: "owner-signing-request";
      decision: "reject-only";
      request: Readonly<OwnerSigningRequest>;
    }>
  | Readonly<{ kind: "unverified"; decision: "reject-only" }>;

export function classifyStoredAuthorizationScope(
  requestedScope: string,
  requestId: string,
): StoredAuthorizationScope {
  try {
    const parsed: unknown = JSON.parse(requestedScope);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return Object.freeze({ kind: "unverified", decision: "reject-only" });
    }
    try {
      return Object.freeze({
        kind: "permission-request",
        decision: "approve-or-reject",
        request: parsePermissionRequest({ ...parsed, requestId }),
      });
    } catch {
      const request = parseOwnerSigningRequest(parsed);
      try {
        const kernelRequest = parseKernelReplayableInstallOwnerSigningRequest(request);
        if (kernelRequest.signer.ownerCredential.kind === "p256") {
          return Object.freeze({
            kind: "kernel-owner-signing-request",
            decision: "approve-or-reject",
            request: kernelRequest,
          });
        }
      } catch {
        // The generic closed request remains readable but reject-only.
      }
      return Object.freeze({
        kind: "owner-signing-request",
        decision: "reject-only",
        request,
      });
    }
  } catch {
    return Object.freeze({ kind: "unverified", decision: "reject-only" });
  }
}

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
