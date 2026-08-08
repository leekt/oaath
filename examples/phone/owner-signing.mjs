/**
 * Exact consumer boundary for a claimed Kernel owner-signing artifact.
 *
 * The protocol owns both immutable wire shapes. This helper adds only the
 * demo consumer's binding: canonical artifact text, exact Kernel/P-256 request,
 * and the request hash must agree before compact signature bytes reach the
 * SDK's independently verifying P-256 key profile.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  hashOwnerSigningRequest,
  parseKernelV4ReplayableInstallOwnerSigningRequest,
  parseOwnerSigningArtifact,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";

export function captureKernelOwnerSignature(requestValue, artifactPlaintext) {
  try {
    const request = parseKernelV4ReplayableInstallOwnerSigningRequest(requestValue);
    if (request.signer.ownerCredential.kind !== "p256") throw new TypeError();
    if (typeof artifactPlaintext !== "string") throw new TypeError();
    const artifact = parseOwnerSigningArtifact(JSON.parse(artifactPlaintext));
    if (serializeOwnerSigningArtifact(artifact) !== artifactPlaintext) throw new TypeError();
    if (artifact.requestHash !== hashOwnerSigningRequest(request)) throw new TypeError();
    return artifact.signature;
  } catch {
    throw new Error("owner_signing_artifact_invalid");
  }
}
