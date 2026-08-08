/**
 * Pure authorization of one returned Kernel owner-signing artifact.
 *
 * The protocol owns both exact wire shapes. This server owner adds only the
 * release policy: the request must use the first-runtime P-256 credential, the
 * artifact must be its one canonical JSON representation, its request hash must
 * bind the exact request, and its compact low-S signature must verify the exact
 * Kernel digest. It allocates and persists nothing.
 *
 * @author taek <leekt216@gmail.com>
 */

import { p256 } from "@noble/curves/nist.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import {
  hashOwnerSigningRequest,
  parseKernelV4ReplayableInstallOwnerSigningRequest,
  parseOwnerSigningArtifact,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";
import { relayFailure } from "../relay/errors.js";
import { boundedText, RELAY_LIMITS } from "../store/records.js";

const INVALID = "relay_request_invalid" as const;

/**
 * Returns the canonical artifact plaintext only after every request, key,
 * request-hash, and signature binding agrees.
 */
export function verifyKernelV4ReplayableInstallOwnerSigningArtifact(
  requestValue: unknown,
  artifactPlaintext: unknown,
): string {
  try {
    const request = parseKernelV4ReplayableInstallOwnerSigningRequest(requestValue);
    if (request.signer.ownerCredential.kind !== "p256") throw new TypeError();

    const received = boundedText(
      artifactPlaintext,
      RELAY_LIMITS.artifactPlaintext,
      "owner signing artifact",
      INVALID,
    );
    const artifact = parseOwnerSigningArtifact(JSON.parse(received) as unknown);
    const canonical = serializeOwnerSigningArtifact(artifact);
    if (received !== canonical) throw new TypeError();
    if (artifact.requestHash !== hashOwnerSigningRequest(request)) throw new TypeError();

    const verified = p256.verify(
      hexToBytes(artifact.signature.slice(2)),
      hexToBytes(request.expectedDigest.slice(2)),
      hexToBytes(request.signer.ownerCredential.publicKey.slice(2)),
      { format: "compact", lowS: true, prehash: false },
    );
    if (!verified) throw new TypeError();
    return canonical;
  } catch {
    return relayFailure(INVALID, "Kernel owner signing artifact is invalid");
  }
}
