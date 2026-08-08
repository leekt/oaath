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

import { hashOwnerSigningRequest, type OwnerSigningRequest } from "@oaath/protocol";
import { sha256Base64Url } from "../authorization/challenge.js";
import { fetchAuthorizationRequest } from "../authorization/request.js";
import { classifyStoredAuthorizationScope } from "../authorization/scope.js";
import type { RelayClock } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayStore } from "../store/interface.js";

/** Bounded base64url match code length. 48 bits is plenty to compare by eye. */
export const NATIVE_DISPLAY_PAYLOAD_LENGTH = 8;

/** Versioned consent envelope; the Swift decoder pins this exact value. */
export const OAATH_NATIVE_PROJECTION_VERSION = "oaath.native-projection/v4" as const;

const DISPLAY_DOMAIN = "oaath.native-display/v1:";

/**
 * Whether the phone may offer approval for one projected scope. Permission
 * requests are currently approvable; owner-signing, unknown, and malformed
 * scopes remain inspectable but reject-only.
 */
export type OwnerPhoneDecisionCapability = "approve-or-reject" | "reject-only";

/** One credential identity as the owner reviews it: public material only. */
export type OwnerPhoneCredentialProjection =
  | Readonly<{ kind: "ecdsa"; address: string }>
  | Readonly<{ kind: "p256"; publicKey: string }>
  | Readonly<{ kind: "webauthn"; publicKey: string; authenticatorIdHash: string }>;

/**
 * The requested scope as the phone renders it. When the stored scope parses as
 * an `@oaath/protocol` permission request, every fact that determines who
 * receives authority, over which account, and under what limits is projected
 * structurally. A valid owner-signing request is also projected in full with
 * its protocol-owned hash, but remains reject-only. Anything else is returned
 * as explicitly labeled raw text.
 */
export type OwnerPhoneScopeProjection =
  | Readonly<{
      kind: "permission-request";
      decision: "approve-or-reject";
      /** The application identity the signed request binds, verbatim. */
      application: Readonly<{
        applicationId: string;
        clientId: string;
        origin: string;
        /** Opaque device identity, fingerprinted: raw ids mean nothing to an owner. */
        deviceFingerprint: string;
      }>;
      /** The logical account this authority acts for. */
      account: Readonly<{
        accountIndex: string;
        kernelVersion: string;
        factoryRoute: string;
        entryPointVersion: string;
        ownerCredential: OwnerPhoneCredentialProjection;
      }>;
      /** The session credential that receives the scoped authority. */
      operatorCredential: OwnerPhoneCredentialProjection;
      /**
       * Where the session key lives: null for frontend custody (the page's
       * own non-extractable key), or the remote trust model the owner is
       * asked to approve — the request hash binds it, so approving this
       * display approves exactly this custody.
       */
      sessionSigner: Readonly<{
        mode: "application_backend" | "oaath_hosted";
        providerId: string;
      }> | null;
      chainScope: "all";
      calls: readonly Readonly<{
        target: string;
        selector: string;
        valueLimit: string;
        argumentEquals: readonly Readonly<{ index: number; value: string }>[];
      }>[];
      requestedAt: number;
      /** The permission request's own expiry, as the requesting client stated it. */
      expiresAt: number;
      /** The policy's on-chain validity window; inclusive, in Unix seconds. */
      policyValidAfter: number;
      policyValidUntil: number | null;
      perChainOperationLimit: number;
    }>
  | Readonly<{
      kind: "owner-signing-request";
      decision: "reject-only";
      /** Canonical hash binding every captured request fact. */
      requestHash: `0x${string}`;
      /** Full immutable protocol request for independent device review. */
      request: Readonly<OwnerSigningRequest>;
    }>
  | Readonly<{ kind: "raw"; decision: "reject-only"; text: string }>;

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
function projectCredential(
  credential: Readonly<{
    kind: "ecdsa" | "p256" | "webauthn";
    address?: string;
    publicKey?: string;
    authenticatorIdHash?: string;
  }>,
): OwnerPhoneCredentialProjection {
  if (credential.kind === "ecdsa") {
    return Object.freeze({ kind: "ecdsa", address: credential.address ?? "" });
  }
  if (credential.kind === "p256") {
    return Object.freeze({ kind: "p256", publicKey: credential.publicKey ?? "" });
  }
  return Object.freeze({
    kind: "webauthn",
    publicKey: credential.publicKey ?? "",
    authenticatorIdHash: credential.authenticatorIdHash ?? "",
  });
}

export async function projectOwnerPhoneScope(
  requestedScope: string,
  operationId: string,
): Promise<OwnerPhoneScopeProjection> {
  try {
    const classified = classifyStoredAuthorizationScope(requestedScope, operationId);
    if (classified.kind === "permission-request") {
      const request = classified.request;
      return Object.freeze({
        kind: "permission-request",
        decision: "approve-or-reject",
        application: Object.freeze({
          applicationId: request.application.applicationId,
          clientId: request.application.clientId,
          origin: request.application.origin,
          deviceFingerprint: (
            await sha256Base64Url(`${DISPLAY_DOMAIN}device:${request.application.deviceId}`)
          ).slice(0, NATIVE_DISPLAY_PAYLOAD_LENGTH),
        }),
        account: Object.freeze({
          accountIndex: request.logicalAccount.accountIndex,
          kernelVersion: request.logicalAccount.kernelVersion,
          factoryRoute: request.logicalAccount.factoryRoute,
          entryPointVersion: request.logicalAccount.entryPoint.version,
          ownerCredential: projectCredential(request.logicalAccount.ownerCredential),
        }),
        operatorCredential: projectCredential(request.operatorCredential),
        sessionSigner:
          request.sessionSigner === null
            ? null
            : Object.freeze({
                mode: request.sessionSigner.mode,
                providerId: request.sessionSigner.providerId,
              }),
        chainScope: request.chainScope,
        calls: Object.freeze(
          request.policy.calls.map((call) =>
            Object.freeze({
              target: call.target,
              selector: call.selector,
              valueLimit: call.valueLimit,
              argumentEquals: Object.freeze(
                call.argumentEquals.map((rule) =>
                  Object.freeze({ index: rule.index, value: rule.value }),
                ),
              ),
            }),
          ),
        ),
        requestedAt: request.requestedAt,
        expiresAt: request.expiresAt,
        policyValidAfter: request.policy.validAfter,
        policyValidUntil: request.policy.validUntil,
        perChainOperationLimit: request.policy.perChainOperationLimit,
      });
    }
    if (classified.kind === "owner-signing-request") {
      return Object.freeze({
        kind: "owner-signing-request",
        decision: "reject-only",
        requestHash: hashOwnerSigningRequest(classified.request),
        request: classified.request,
      });
    }
    return Object.freeze({ kind: "raw", decision: "reject-only", text: requestedScope });
  } catch {
    return Object.freeze({ kind: "raw", decision: "reject-only", text: requestedScope });
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
    scope: await projectOwnerPhoneScope(state.requestedScope, state.requestId),
  });
}
