/**
 * EXPERIMENTAL PREVIEW — authenticated owner-phone consent projection.
 *
 * This is a preview surface reached through `@oaath/server/native` and the
 * relay's preview HTTP routes (`GET /native/projections/{operationId}`). It has
 * no stability guarantee and no production qualification: real iOS, Apple
 * provisioning, Secure Enclave, and hosted operations are later work.
 *
 * What it owns: turning one stored authorization request into the projection
 * the owner's phone renders before deciding. It owns nothing about deciding;
 * the relay's decision use case stays the only decision owner.
 *
 * Two very different surfaces share this file, and only one of them is opaque:
 *
 * - The **push** projection (`operationId`, `displayPayload`, `expiresAt`)
 *   transits Apple inside an APNs payload, so it stays opaque by design: no
 *   permission, scope, client, chain, or account detail may ride it. The APNs
 *   sender enforces that subset exactly.
 * - The **consent** projection returned here travels only the authenticated
 *   relay → owner channel, so it deliberately carries the full authorization
 *   request: the requesting client identity and the requested scope. The owner
 *   must see exactly the authority they grant before approving.
 *
 * `displayPayload` is not a secret and not authority: it is a deterministic
 * digest of the request and its bound subject, so the owner can check that the
 * code on the phone is the code the browser shows. Holding it authorizes
 * nothing — deciding still requires the authenticated bound owner.
 *
 * @author taek <leekt216@gmail.com>
 */

import { parsePermissionRequest } from "@oaath/protocol";
import { sha256Base64Url } from "../authorization/challenge.js";
import { fetchAuthorizationRequest } from "../authorization/request.js";
import type { RelayClock } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayStore } from "../store/interface.js";

/** Bounded base64url match code length. 48 bits is plenty to compare by eye. */
export const NATIVE_DISPLAY_PAYLOAD_LENGTH = 8;

/** Versioned consent envelope; the Swift decoder pins this exact value. */
export const OAATH_NATIVE_PROJECTION_VERSION = "oaath.native-projection/v1" as const;

const DISPLAY_DOMAIN = "oaath.native-display/v1:";

/**
 * The requested scope as the phone renders it. When the stored scope parses as
 * an `@oaath/protocol` permission request, its consent-relevant facts are
 * projected structurally; anything else is returned as an explicitly labeled
 * raw string for the owner to review. Neither shape is a failure.
 *
 * ponytail: per-call `argumentEquals` constraints are not projected, so the
 * structured view may show *broader* authority than is actually granted —
 * safe for consent. Project them when a consent UI renders argument rules.
 */
export type OwnerPhoneScopeProjection =
  | Readonly<{
      kind: "permission-request";
      chainScope: "all";
      calls: readonly Readonly<{ target: string; selector: string; valueLimit: string }>[];
      /** The permission request's own expiry, as the requesting client stated it. */
      expiresAt: number;
      perChainOperationLimit: number;
    }>
  | Readonly<{ kind: "raw"; text: string }>;

export interface OwnerPhoneRequestProjection {
  readonly version: typeof OAATH_NATIVE_PROJECTION_VERSION;
  /**
   * Stable across every projection of the same request, and the key the
   * approve/reject saga is keyed by. It is the relay's own opaque request
   * identifier: one authoritative id, no second mapping table to lose.
   */
  readonly operationId: string;
  /** Bounded opaque match code, the only variable an APNs payload may carry. */
  readonly displayPayload: string;
  /** The stored request's expiry, in epoch milliseconds. */
  readonly expiresAt: number;
  /** The requesting client, exactly as the stored request binds it. */
  readonly client: Readonly<{ clientId: string; redirectUri: string }>;
  readonly scope: OwnerPhoneScopeProjection;
}

/**
 * The opaque subset of the projection that may transit Apple inside an APNs
 * payload. The sender exact-captures precisely these three fields, so consent
 * detail can never ride a notification.
 */
export type OwnerPhonePushProjection = Pick<
  OwnerPhoneRequestProjection,
  "operationId" | "displayPayload" | "expiresAt"
>;

export interface ProjectOwnerPhoneRequestInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  /** Authenticated `owner` caller; only the bound subject may be projected. */
  readonly caller: RelayCaller;
  readonly requestId: string;
}

/**
 * The stored scope is the requesting client's own JSON permission scope (the
 * SDK serializes a permission request without its `requestId`; the relay's
 * request id is the binding). An unparseable scope is not a failure: the owner
 * still gets the raw text to review, never a silent omission.
 */
function projectScope(requestedScope: string, operationId: string): OwnerPhoneScopeProjection {
  try {
    const parsed: unknown = JSON.parse(requestedScope);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return Object.freeze({ kind: "raw", text: requestedScope });
    }
    const request = parsePermissionRequest({ ...parsed, requestId: operationId });
    return Object.freeze({
      kind: "permission-request",
      chainScope: request.chainScope,
      calls: Object.freeze(
        request.policy.calls.map((call) =>
          Object.freeze({
            target: call.target,
            selector: call.selector,
            valueLimit: call.valueLimit,
          }),
        ),
      ),
      expiresAt: request.expiresAt,
      perChainOperationLimit: request.policy.perChainOperationLimit,
    });
  } catch {
    return Object.freeze({ kind: "raw", text: requestedScope });
  }
}

/**
 * Projects a pending request for its bound owner. An expired or already decided
 * request is not projectable: there is nothing left to approve, so nothing is
 * ever pushed or rendered for it.
 */
export async function projectOwnerPhoneRequest(
  input: ProjectOwnerPhoneRequestInput,
): Promise<OwnerPhoneRequestProjection> {
  if (input.caller.role !== "owner") {
    return relayFailure("relay_forbidden", "caller may not act in the required role");
  }
  const state = await fetchAuthorizationRequest({
    store: input.store,
    clock: input.clock,
    caller: input.caller,
    requestId: input.requestId,
  });
  if (state.expired) {
    return relayFailure("relay_expired", "authorization request expired");
  }
  if (state.decision !== null) {
    return relayFailure("relay_already_decided", "authorization request is already decided");
  }
  const digest = await sha256Base64Url(
    `${DISPLAY_DOMAIN}${input.caller.subject}:${state.requestId}`,
  );
  return Object.freeze({
    version: OAATH_NATIVE_PROJECTION_VERSION,
    operationId: state.requestId,
    displayPayload: digest.slice(0, NATIVE_DISPLAY_PAYLOAD_LENGTH),
    expiresAt: state.expiresAt,
    client: Object.freeze({ clientId: state.clientId, redirectUri: state.redirectUri }),
    scope: projectScope(state.requestedScope, state.requestId),
  });
}
