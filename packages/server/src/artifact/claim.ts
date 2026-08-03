/**
 * One-time encrypted artifact release.
 *
 * ```text
 * state and owner        the artifact record's `claimedAt` owns "released"
 * transitions            sealed -> claimed, exactly once
 * terminal               claimed; a second claim fails closed
 * retry positively safe? no. The claim commits before the KMS is asked to
 *                        decrypt, so a decrypt or transport failure burns the
 *                        artifact instead of risking a second release
 * crash/reload           a crash before commit leaves the artifact claimable
 * ```
 *
 * @author taek <leekt216@gmail.com>
 */

import { type RelayClock, relayNow } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayKms } from "../security/kms.js";
import type { RelayStore } from "../store/interface.js";
import { withRelayTransaction } from "../store/interface.js";
import { openArtifact } from "./encrypt.js";

export interface ClaimEncryptedArtifactInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  readonly kms: RelayKms;
  /** Authenticated `client` caller; only the bound client may claim. */
  readonly caller: RelayCaller;
  /** Released only by a successful code consume. */
  readonly artifactId: string;
}

export interface ClaimedEncryptedArtifact {
  readonly requestId: string;
  readonly artifact: string;
}

export async function claimEncryptedArtifact(
  input: ClaimEncryptedArtifactInput,
): Promise<ClaimedEncryptedArtifact> {
  const claimedAt = relayNow(input.clock);
  const claimed = await withRelayTransaction(input.store, async (transaction) => {
    const record = await transaction.lockEncryptedArtifact(input.artifactId);
    // An artifact bound to another client is indistinguishable from an unknown one.
    if (!record || record.clientId !== input.caller.clientId) {
      return relayFailure("relay_not_found", "encrypted artifact does not exist");
    }
    if (record.claimedAt !== null) {
      relayFailure("relay_artifact_already_claimed", "encrypted artifact was already claimed");
    }
    if (!(await transaction.claimEncryptedArtifact(input.artifactId, claimedAt))) {
      relayFailure("relay_state_ambiguous", "one-time claim did not apply under its row lock");
    }
    return record;
  });
  return Object.freeze({
    requestId: claimed.requestId,
    artifact: await openArtifact(input.kms, claimed.ciphertextRef),
  });
}
