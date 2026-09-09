/** Consent projection for an immutable owner revocation request; no admission or decision state. */
import {
  hashKernelV4RevocationSigningRequest,
  hashOwnerSigningRequest,
  type KernelV4RevocationSigningRequest,
  parseKernelV4RevocationSigningRequest,
} from "@oaath/protocol";
import { sha256Base64Url } from "../authorization/challenge.js";
import { relayFailure } from "../relay/errors.js";
import {
  NATIVE_DISPLAY_PAYLOAD_LENGTH,
  OAATH_NATIVE_PROJECTION_VERSION,
  type OwnerPhonePermissionScopeProjection,
  type OwnerPhoneRequestProjection,
  projectPermissionConsent,
} from "./projection.js";

export interface OwnerPhoneRevocationScopeProjection {
  readonly kind: "kernel-revocation";
  readonly decision: "approve-or-reject";
  /** Authenticated service commitment; the phone independently derives the operation digest. */
  readonly requestHash: `0x${string}`;
  readonly permission: OwnerPhonePermissionScopeProjection;
  readonly install: Readonly<{
    kind: "owner-signing-request";
    decision: "approve-or-reject";
    requestHash: `0x${string}`;
    request: KernelV4RevocationSigningRequest["install"];
  }>;
  readonly effect: KernelV4RevocationSigningRequest["effect"];
  readonly chainId: number;
  readonly entryPoint: `0x${string}`;
  readonly operation: KernelV4RevocationSigningRequest["operation"];
  readonly expectedDigest: `0x${string}`;
}

/** A terminal owner decision acknowledges custody; it releases no OAuth code or signing artifact. */
export interface OwnerPhoneRevocationDecision {
  readonly version: "oaath.native-revocation-decision/v1";
  readonly operationId: string;
  readonly outcome: "approved" | "rejected";
  readonly decidedAt: number;
  readonly settlement: "decided" | "replayed";
}

/**
 * Projects a stored request for its authenticated owner. The calling queue owns
 * admission, current ownership, expiry and terminal-decision checks; this helper
 * owns only consent bytes. It performs no signing, submission or observation.
 */
export async function projectOwnerPhoneRevocation(input: {
  readonly operationId: string;
  readonly ownerSubject: string;
  readonly expiresAt: number;
  readonly request: unknown;
}): Promise<OwnerPhoneRequestProjection> {
  if (
    !/^[A-Za-z0-9._~-]{1,64}$/u.test(input.operationId) ||
    !input.ownerSubject ||
    !Number.isSafeInteger(input.expiresAt) ||
    input.expiresAt < 0
  )
    return relayFailure("relay_request_invalid", "revocation projection metadata is invalid");
  const request = parseKernelV4RevocationSigningRequest(input.request);
  const display = await sha256Base64Url(
    `oaath.native-display/v1:${input.ownerSubject}:${input.operationId}`,
  );
  return Object.freeze({
    version: OAATH_NATIVE_PROJECTION_VERSION,
    operationId: input.operationId,
    displayPayload: display.slice(0, NATIVE_DISPLAY_PAYLOAD_LENGTH),
    expiresAt: input.expiresAt,
    client: Object.freeze({
      clientId: request.permissionRequest.application.clientId,
      redirectUri: null,
    }),
    scope: Object.freeze({
      kind: "kernel-revocation",
      decision: "approve-or-reject",
      requestHash: hashKernelV4RevocationSigningRequest(request),
      permission: await projectPermissionConsent(request.permissionRequest),
      install: Object.freeze({
        kind: "owner-signing-request",
        decision: "approve-or-reject",
        requestHash: hashOwnerSigningRequest(request.install),
        request: request.install,
      }),
      effect: request.effect,
      chainId: request.chainId,
      entryPoint: request.entryPoint,
      operation: request.operation,
      expectedDigest: request.expectedDigest,
    }),
  });
}
