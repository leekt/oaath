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
export const OAATH_NATIVE_PROJECTION_VERSION = "oaath.native-projection/v2" as const;

/**
 * The versioned scope envelope a client stores to ask the owner's phone for one
 * signature over one 32-byte digest. It rides the existing kind-agnostic
 * authorization routes: `requestedScope` carries this JSON, the phone approves
 * with the signature as the decision artifact, and the one-time code/artifact
 * machinery releases it to the client exactly once. The relay never verifies or
 * interprets the signature; the requesting client's own key profile does.
 */
export const OAATH_SIGNATURE_REQUEST_SCOPE_VERSION = "oaath.signature-request/v1" as const;

const DISPLAY_DOMAIN = "oaath.native-display/v1:";
const DIGEST = /^0x[0-9a-f]{64}$/u;

/**
 * Whether the phone may offer approval for one projected scope. A recognized,
 * fully projected scope is approvable; an unknown or malformed one stays
 * inspectable but is reject-only — a production consent surface never offers
 * an Approve button over authority it could not read.
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
 * structurally; anything else is returned as an explicitly labeled raw string
 * for the owner to review. Neither shape is a failure, but only a recognized
 * shape is approvable.
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
      kind: "signature-request";
      decision: "approve-or-reject";
      /** The exact 32-byte digest the owner's key is asked to sign. */
      digest: `0x${string}`;
      /**
       * The full display JSON as one recursively key-sorted compact canonical
       * string. Ambiguous/noncanonical bytes fail closed to `raw`. The phone
       * renders these exact bytes, including the independently supplied digest,
       * before the owner decides.
       */
      display: string;
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
    const parsed: unknown = JSON.parse(requestedScope);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return Object.freeze({ kind: "raw", decision: "reject-only", text: requestedScope });
    }
    const signatureRequest = projectSignatureRequestScope(parsed);
    if (signatureRequest) return signatureRequest;
    const request = parsePermissionRequest({ ...parsed, requestId: operationId });
    // This projection version displays no custody model, so a request naming
    // remote session-key custody stays inspectable but reject-only: the owner
    // never approves a trust model the consent surface cannot show.
    // ponytail: projection v3 adds a custody section and lifts this.
    if (request.sessionSigner !== null) {
      return Object.freeze({ kind: "raw", decision: "reject-only", text: requestedScope });
    }
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
  } catch {
    return Object.freeze({ kind: "raw", decision: "reject-only", text: requestedScope });
  }
}

/**
 * Projects a stored signature-request scope structurally, or returns null so a
 * malformed one falls through to the labeled raw text: the owner still reviews
 * exactly what was stored, and the phone simply has no digest to sign.
 */
function sortedJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortedJsonValue);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, sortedJsonValue(record[key])]),
    );
  }
  return value;
}

function projectSignatureRequestScope(parsed: object): OwnerPhoneScopeProjection | null {
  const record = parsed as Record<string, unknown>;
  if (
    record.version !== OAATH_SIGNATURE_REQUEST_SCOPE_VERSION ||
    record.kind !== "signature-request"
  )
    return null;
  if (Object.keys(record).sort().join(",") !== "digest,display,kind,version") return null;
  const digest = record.digest;
  const display = record.display;
  if (typeof digest !== "string" || !DIGEST.test(digest)) return null;
  if (typeof display !== "string" || display.length < 1) return null;
  // Parse and re-encode the actual consent bytes using the same recursively
  // sorted compact codec the Swift decoder pins. This rejects whitespace,
  // duplicate-key collapse, noncanonical escapes, and any display that does
  // not visibly bind the independently supplied digest.
  try {
    const displayed: unknown = JSON.parse(display);
    if (
      displayed === null ||
      typeof displayed !== "object" ||
      Array.isArray(displayed) ||
      (displayed as Record<string, unknown>).digest !== digest ||
      JSON.stringify(sortedJsonValue(displayed)) !== display
    )
      return null;
  } catch {
    return null;
  }
  return Object.freeze({
    kind: "signature-request",
    decision: "approve-or-reject",
    digest: digest as `0x${string}`,
    display,
  });
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
