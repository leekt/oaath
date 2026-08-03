/**
 * The four destructive effects, each with exactly one owner.
 *
 * ```text
 * close        releases runtime resources: handles, observers, stores
 * signOut      revokes the caller's relay or application authentication
 * forgetLocal  deletes local key custody and the realm's persisted context
 * revoke       submits and completes on-chain revocation of the Grant
 * ```
 *
 * An effect is a name and one idempotent attempt. It reports nothing but
 * success or a throw, because the coordinator owns ordering, checkpoints, and
 * which failure survives.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { OaathGrantHandle } from "../client/grant-handle.js";
import type {
  OaathCleanupEffectName,
  OaathContextStore,
  OaathKeyStore,
} from "../persistence/interfaces.js";

export interface OaathCleanupEffect {
  readonly name: OaathCleanupEffectName;
  readonly run: () => Promise<void>;
}

function effect(name: OaathCleanupEffectName, run: () => Promise<void>): OaathCleanupEffect {
  return Object.freeze({ name, run });
}

/** Releases runtime resources. Always the last effect: it disables the others. */
export function closeEffect(close: () => Promise<void>): OaathCleanupEffect {
  return effect("close", close);
}

/** Revokes relay or application authentication. */
export function signOutEffect(signOut: () => Promise<void>): OaathCleanupEffect {
  return effect("signOut", signOut);
}

/**
 * Deletes local key custody and the realm's persisted client context. The Grant
 * and Operation records stay: they are the audit of what this realm did, and
 * forgetting locally is not revocation.
 */
export function forgetLocalEffect(input: {
  readonly keys: OaathKeyStore;
  readonly contexts: OaathContextStore;
  readonly bindingId: string;
  readonly keyIds: readonly string[];
}): OaathCleanupEffect {
  return effect("forgetLocal", async () => {
    for (const keyId of input.keyIds) await input.keys.delete(keyId);
    await input.contexts.clear(input.bindingId);
  });
}

/** Submits and completes on-chain revocation through the Grant handle. */
export function revokeEffect(grant: Readonly<OaathGrantHandle>): OaathCleanupEffect {
  return effect("revoke", () => grant.revoke());
}
