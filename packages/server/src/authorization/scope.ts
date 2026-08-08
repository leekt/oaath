/**
 * Authoritative classification of one immutable stored authorization scope.
 *
 * The current server may approve an exact protocol PermissionRequest or the
 * one exact Kernel replayable-install request backed by a P-256 owner. Other
 * closed owner-signing requests are captured for projection and hashing but
 * remain reject-only. Unknown, malformed, and legacy scopes stay readable and
 * rejectable, but never authorize artifact creation.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  type KernelV4ReplayableInstallOwnerSigningRequest,
  type OwnerSigningRequest,
  type PermissionRequest,
  parseKernelV4ReplayableInstallOwnerSigningRequest,
  parseOwnerSigningRequest,
  parsePermissionRequest,
} from "@oaath/protocol";

export type StoredAuthorizationScope =
  | Readonly<{
      kind: "permission-request";
      decision: "approve-or-reject";
      request: Readonly<PermissionRequest>;
    }>
  | Readonly<{
      kind: "kernel-owner-signing-request";
      decision: "approve-or-reject";
      request: Readonly<KernelV4ReplayableInstallOwnerSigningRequest>;
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
        const kernelRequest = parseKernelV4ReplayableInstallOwnerSigningRequest(request);
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
