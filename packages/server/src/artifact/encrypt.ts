/**
 * KMS sealing boundary. Plaintext never reaches the store.
 *
 * @author taek <leekt216@gmail.com>
 */

import { relayFailure } from "../relay/errors.js";
import type { RelayKms } from "../security/kms.js";
import { boundedText, RELAY_LIMITS } from "../store/records.js";

const KMS_UNAVAILABLE = "relay_kms_unavailable" as const;

/**
 * Encrypts an approval artifact and returns the opaque reference to store.
 * A port that echoes plaintext is rejected: the store must never hold it.
 */
export async function sealArtifact(kms: RelayKms, plaintext: string): Promise<string> {
  let sealed: unknown;
  try {
    sealed = await kms.encrypt(plaintext);
  } catch {
    return relayFailure(KMS_UNAVAILABLE, "KMS encrypt failed");
  }
  const ciphertextRef = boundedText(
    sealed,
    RELAY_LIMITS.ciphertextRef,
    "KMS ciphertext reference",
    KMS_UNAVAILABLE,
  );
  if (ciphertextRef.includes(plaintext)) {
    return relayFailure(KMS_UNAVAILABLE, "KMS reference contains plaintext");
  }
  return ciphertextRef;
}

/** Opens a reference this KMS previously sealed. Called only after the claim commits. */
export async function openArtifact(kms: RelayKms, ciphertextRef: string): Promise<string> {
  let opened: unknown;
  try {
    opened = await kms.decrypt(ciphertextRef);
  } catch {
    return relayFailure(KMS_UNAVAILABLE, "KMS decrypt failed");
  }
  return boundedText(opened, RELAY_LIMITS.artifactPlaintext, "KMS plaintext", KMS_UNAVAILABLE);
}
