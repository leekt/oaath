/**
 * Authoritative classification of one immutable stored authorization scope.
 *
 * The current server may approve only an exact protocol PermissionRequest.
 * A closed owner-signing request is captured for projection and hashing, but
 * remains reject-only until a later device-consent owner can authorize it.
 * Unknown, malformed, and legacy scopes remain readable and rejectable, but
 * they never authorize artifact creation.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  type OwnerSigningRequest,
  type PermissionRequest,
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
      return Object.freeze({
        kind: "owner-signing-request",
        decision: "reject-only",
        request: parseOwnerSigningRequest(parsed),
      });
    }
  } catch {
    return Object.freeze({ kind: "unverified", decision: "reject-only" });
  }
}
