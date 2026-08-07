/**
 * Authoritative classification of one immutable stored authorization scope.
 *
 * The current server may approve only an exact protocol PermissionRequest.
 * Unknown, malformed, and legacy network-digest scopes remain readable and
 * rejectable, but they never authorize artifact creation. A future signing
 * request must add its own verified closed branch here before any decision
 * route can approve it.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type PermissionRequest, parsePermissionRequest } from "@oaath/protocol";

export type StoredAuthorizationScope =
  | Readonly<{
      kind: "permission-request";
      decision: "approve-or-reject";
      request: Readonly<PermissionRequest>;
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
    return Object.freeze({
      kind: "permission-request",
      decision: "approve-or-reject",
      request: parsePermissionRequest({ ...parsed, requestId }),
    });
  } catch {
    return Object.freeze({ kind: "unverified", decision: "reject-only" });
  }
}
