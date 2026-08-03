/**
 * One-time authorization code consume.
 *
 * ```text
 * state and owner        the code record's `consumedAt` owns "used"
 * transitions            issued -> consumed, exactly once
 * terminal               consumed; a second consume fails closed
 * retry positively safe? no, in either direction: a released code is never
 *                        re-released, and an ambiguous commit is never retried
 * crash/reload           the guarded update and the release decide together in one
 *                        transaction under the code's row lock
 * ```
 *
 * A failed PKCE or redirect binding still burns the code, so a stolen code
 * cannot be brute-forced against the stored challenge.
 *
 * The endpoint is not an oracle for whether a guessed code was correct: an
 * unknown code, a code bound to another client, a wrong redirect URI, and a
 * wrong verifier all leave as the single `relay_code_invalid` code and status.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type RelayClock, relayNow } from "../clock.js";
import { type RelayErrorCode, relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayStore } from "../store/interface.js";
import { sha256Base64Url, verifyPkceS256 } from "./challenge.js";

export interface ConsumeAuthorizationCodeInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  /** Authenticated `client` caller; only the bound client may consume. */
  readonly caller: RelayCaller;
  readonly code: string;
  readonly codeVerifier: string;
  readonly redirectUri: string;
}

export interface ConsumedAuthorizationCode {
  readonly requestId: string;
  /** One-time claim handle for the encrypted artifact. */
  readonly artifactId: string;
}

type ConsumeOutcome =
  | Readonly<{ kind: "released"; released: ConsumedAuthorizationCode }>
  | Readonly<{ kind: "burned"; code: RelayErrorCode }>;

export async function consumeAuthorizationCode(
  input: ConsumeAuthorizationCodeInput,
): Promise<ConsumedAuthorizationCode> {
  const consumedAt = relayNow(input.clock);
  const codeHash = await sha256Base64Url(input.code);
  const transaction = await input.store.begin();
  let outcome: ConsumeOutcome;
  try {
    const record = await transaction.lockAuthorizationCode(codeHash);
    // An unknown code and a code bound to another client are indistinguishable
    // from a code whose binding failed below.
    if (!record || record.clientId !== input.caller.clientId) {
      relayFailure("relay_code_invalid", "authorization code redemption failed");
    }
    if (record.consumedAt !== null) {
      relayFailure("relay_code_already_consumed", "authorization code was already consumed");
    }
    if (consumedAt >= record.expiresAt) {
      // Already dead; nothing left to burn.
      relayFailure("relay_expired", "authorization code expired");
    }
    const bound =
      record.redirectUri === input.redirectUri &&
      (await verifyPkceS256(input.codeVerifier, record.codeChallenge));
    if (!(await transaction.consumeAuthorizationCode(codeHash, consumedAt))) {
      relayFailure("relay_state_ambiguous", "one-time consume did not apply under its row lock");
    }
    if (!bound) {
      // Void the artifact with the code that would have released it. A `false`
      // result means it was already terminal, which is the same outcome.
      await transaction.lockEncryptedArtifact(record.artifactId);
      await transaction.claimEncryptedArtifact(record.artifactId, consumedAt);
    }
    outcome = bound
      ? Object.freeze({
          kind: "released",
          released: Object.freeze({
            requestId: record.requestId,
            artifactId: record.artifactId,
          }),
        })
      : Object.freeze({ kind: "burned", code: "relay_code_invalid" });
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
  // The burn is committed before the failure is reported.
  await transaction.commit();
  if (outcome.kind === "burned") {
    relayFailure(outcome.code, "authorization code redemption failed and the code was burned");
  }
  return outcome.released;
}
