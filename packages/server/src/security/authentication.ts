/**
 * Deployment-owned client/device authentication port.
 *
 * The relay never parses credentials. It hands the request to the deployment,
 * which returns the authenticated bindings or nothing. `clientId` and `subject`
 * come only from here: wire input may never declare either.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type CaptureContext, captureDenseArray, exactRecord } from "@oaath/protocol";
import { OaathRelayError, relayFailure } from "../relay/errors.js";
import { boundedText, canonicalIdentifier, RELAY_LIMITS } from "../store/records.js";

/** `client` is the requesting application; `owner` is the approving account owner. */
export type RelayCallerRole = "client" | "owner";

const MAX_REDIRECT_URIS = 8;

export interface RelayCaller {
  readonly role: RelayCallerRole;
  readonly clientId: string;
  /** Pairwise user/device subject. */
  readonly subject: string;
  /**
   * Redirect URIs the deployment registered for this client. An authorization
   * code may only be requested for one of them. `owner` callers pass an empty
   * list; they never receive a code at a redirect URI.
   */
  readonly redirectUris: readonly string[];
}

export interface RelayAuthentication {
  /**
   * Resolves to a `RelayCaller`-shaped value, or `null`/`undefined` when the
   * caller is not authenticated. May throw `OaathRelayError` to choose a code.
   */
  authenticate(request: Request): Promise<unknown>;
}

function captureCaller(value: unknown): RelayCaller {
  const context: CaptureContext = new WeakSet();
  // A port that breaks its own contract is an internal failure, not a 401.
  const fail = (message: string): never => relayFailure("relay_internal", message);
  const record = exactRecord(
    value,
    ["role", "clientId", "subject", "redirectUris"],
    "authenticated caller",
    context,
    fail,
  );
  if (record.role !== "client" && record.role !== "owner") {
    return relayFailure("relay_internal", "authenticated caller role is unsupported");
  }
  const redirectUris = captureDenseArray(record.redirectUris, "caller redirectUris", context, fail);
  if (redirectUris.length > MAX_REDIRECT_URIS) {
    return relayFailure("relay_internal", "caller redirectUris is unbounded");
  }
  return Object.freeze({
    role: record.role,
    clientId: canonicalIdentifier(record.clientId, "caller clientId", "relay_internal"),
    subject: canonicalIdentifier(record.subject, "caller subject", "relay_internal"),
    redirectUris: Object.freeze(
      redirectUris.map((uri) =>
        boundedText(uri, RELAY_LIMITS.redirectUri, "caller redirectUri", "relay_internal"),
      ),
    ),
  });
}

export async function authenticateCaller(
  authentication: RelayAuthentication,
  request: Request,
  required: RelayCallerRole,
): Promise<RelayCaller> {
  let authenticated: unknown;
  try {
    authenticated = await authentication.authenticate(request);
  } catch (error) {
    // Unreadable authentication is not authentication.
    if (error instanceof OaathRelayError) throw error;
    return relayFailure("relay_unauthenticated", "authentication port failed");
  }
  if (authenticated === null || authenticated === undefined) {
    return relayFailure("relay_unauthenticated", "caller is not authenticated");
  }
  const caller = captureCaller(authenticated);
  if (caller.role !== required) {
    return relayFailure("relay_forbidden", "caller may not act in the required role");
  }
  return caller;
}
