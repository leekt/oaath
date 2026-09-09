/** Canonical permission preparation supplied by the deployment's Kernel SDK integration. */
import {
  captureRecord,
  hashOwnerSigningRequest,
  type KernelV4ReplayableInstallOwnerSigningRequest,
  type OwnerSigningArtifact,
  type PermissionRequest,
  parseKernelV4ReplayableInstallOwnerSigningRequest,
  sameOwnerCredentialProfile,
} from "@oaath/protocol";
import { relayFailure } from "../relay/errors.js";
import { boundedText, RELAY_LIMITS } from "../store/records.js";

export interface PreparedOwnerPhonePermissionApproval {
  readonly signingRequest: Readonly<KernelV4ReplayableInstallOwnerSigningRequest>;
  /** Verifies and serializes the SDK's decision plus install approval; submits nothing. */
  complete(artifact: Readonly<OwnerSigningArtifact>, decidedAt: number): Promise<string>;
}

export interface OwnerPhonePermissionApprovals {
  /** Recreate from the stored request and the deployment-owned install nonce. */
  prepare(
    request: Readonly<PermissionRequest>,
  ): Promise<Readonly<PreparedOwnerPhonePermissionApproval>>;
}

export async function prepareOwnerPhonePermissionApproval(
  provider: OwnerPhonePermissionApprovals | undefined,
  request: Readonly<PermissionRequest>,
): Promise<Readonly<PreparedOwnerPhonePermissionApproval>> {
  if (!provider)
    return relayFailure("relay_request_invalid", "phone permission signing is not configured");
  const invalid = () =>
    relayFailure("relay_request_invalid", "phone permission preparation is invalid");
  const result = captureRecord(
    await provider.prepare(request),
    "phone permission preparation",
    new WeakSet(),
    invalid,
  );
  const signingRequest = parseKernelV4ReplayableInstallOwnerSigningRequest(result.signingRequest);
  if (
    signingRequest.signer.ownerCredential.kind !== "p256" ||
    !sameOwnerCredentialProfile(
      signingRequest.signer.ownerCredential,
      request.logicalAccount.ownerCredential,
    ) ||
    typeof result.complete !== "function"
  )
    return invalid();
  const complete = result.complete as PreparedOwnerPhonePermissionApproval["complete"];
  const requestHash = hashOwnerSigningRequest(signingRequest);
  return Object.freeze({
    signingRequest,
    async complete(artifact: Readonly<OwnerSigningArtifact>, decidedAt: number) {
      if (artifact.requestHash !== requestHash) return invalid();
      return boundedText(
        await complete(artifact, decidedAt),
        RELAY_LIMITS.artifactPlaintext,
        "permission artifact",
        "relay_request_invalid",
      );
    },
  });
}
