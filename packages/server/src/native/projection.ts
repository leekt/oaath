/**
 * EXPERIMENTAL PREVIEW — opaque authenticated owner-phone request projection.
 *
 * This is a preview surface reached only through `@oaath/server/native`. It has
 * no HTTP route, no stability guarantee, and no production qualification: real
 * iOS, Apple provisioning, Secure Enclave, and hosted operations are later work.
 *
 * What it owns: turning one stored authorization request into the *bounded
 * opaque* projection a phone may receive. It owns nothing about deciding; the
 * relay's decision use case stays the only decision owner.
 *
 * Why the projection is opaque: an APNs payload transits Apple. So the
 * projection carries no permission, scope, client, chain, or account detail —
 * only a stable operation id, a short derived match code the phone renders, and
 * the request's own expiry. The phone fetches whatever it displays beyond the
 * match code over its own authenticated channel.
 *
 * `displayPayload` is not a secret and not authority: it is a deterministic
 * digest of the request and its bound subject, so the owner can check that the
 * code on the phone is the code the browser shows. Holding it authorizes
 * nothing — deciding still requires the authenticated bound owner.
 *
 * @author taek <leekt216@gmail.com>
 */

import { sha256Base64Url } from "../authorization/challenge.js";
import { fetchAuthorizationRequest } from "../authorization/request.js";
import type { RelayClock } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayStore } from "../store/interface.js";

/** Bounded base64url match code length. 48 bits is plenty to compare by eye. */
export const NATIVE_DISPLAY_PAYLOAD_LENGTH = 8;

const DISPLAY_DOMAIN = "oaath.native-display/v1:";

export interface OwnerPhoneRequestProjection {
  /**
   * Stable across every projection of the same request, and the key the
   * approve/reject saga is keyed by. It is the relay's own opaque request
   * identifier: one authoritative id, no second mapping table to lose.
   */
  readonly operationId: string;
  /** Bounded opaque string the phone renders. Never permission detail. */
  readonly displayPayload: string;
  /** The stored request's expiry, in epoch milliseconds. */
  readonly expiresAt: number;
}

export interface ProjectOwnerPhoneRequestInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  /** Authenticated `owner` caller; only the bound subject may be projected. */
  readonly caller: RelayCaller;
  readonly requestId: string;
}

/**
 * Projects a pending request for its bound owner. An expired or already decided
 * request is not projectable: there is nothing left to approve, so nothing is
 * ever pushed for it.
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
    operationId: state.requestId,
    displayPayload: digest.slice(0, NATIVE_DISPLAY_PAYLOAD_LENGTH),
    expiresAt: state.expiresAt,
  });
}
