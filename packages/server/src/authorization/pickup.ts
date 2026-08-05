/**
 * Authenticated client pickup of a released authorization code.
 *
 * ```text
 * state and owner        reads the request and decision records; writes nothing
 * transitions            none — pickup is idempotent
 * terminal               follows the decision record
 * retry positively safe? yes: the code stays one-shot at consumption, where the
 *                        PKCE verifier and the code hash lock decide
 * ```
 *
 * The relay mints the code, so releasing the sealed copy to the authenticated
 * creating client adds no authority: consumption still requires the verifier
 * only that client holds. The request's stored clientId owns who may pick up;
 * any other caller reads absence, never existence.
 *
 * @author taek <leekt216@gmail.com>
 */
import { openArtifact } from "../artifact/encrypt.js";
import { type RelayClock, relayNow } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayKms } from "../security/kms.js";
import { type RelayStore, withRelayTransaction } from "../store/interface.js";

export interface FetchAuthorizationCodeInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  readonly kms: RelayKms;
  /** Authenticated `client` caller; only the creating client may pick up. */
  readonly caller: RelayCaller;
  readonly requestId: string;
}

export type FetchedAuthorizationCode =
  | Readonly<{ outcome: "pending" }>
  | Readonly<{ outcome: "rejected"; decidedAt: number }>
  | Readonly<{ outcome: "approved"; decidedAt: number; code: string; codeExpiresAt: number }>;

export async function fetchAuthorizationCode(
  input: FetchAuthorizationCodeInput,
): Promise<FetchedAuthorizationCode> {
  const now = relayNow(input.clock);
  const decided = await withRelayTransaction(input.store, async (transaction) => {
    const request = await transaction.lockAuthorizationRequest(input.requestId);
    if (!request || request.clientId !== input.caller.clientId) {
      return relayFailure("relay_not_found", "authorization request does not exist");
    }
    const decision = await transaction.lockAuthorizationDecision(input.requestId);
    if (!decision) {
      if (now >= request.expiresAt) {
        return relayFailure("relay_expired", "authorization request expired");
      }
      return null;
    }
    return decision;
  });
  if (decided === null) return Object.freeze({ outcome: "pending" });
  if (decided.outcome === "rejected" || decided.codeRef === null) {
    return Object.freeze({ outcome: "rejected", decidedAt: decided.decidedAt });
  }
  const codeExpiresAt = decided.codeExpiresAt ?? 0;
  if (now >= codeExpiresAt) {
    return relayFailure("relay_expired", "authorization code expired");
  }
  // Opened only after every stored fact agreed; the plaintext never persists.
  return Object.freeze({
    outcome: "approved",
    decidedAt: decided.decidedAt,
    code: await openArtifact(input.kms, decided.codeRef),
    codeExpiresAt,
  });
}
