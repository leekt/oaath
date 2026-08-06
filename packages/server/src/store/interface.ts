/**
 * Durable relay transaction contract.
 *
 * State model owned by this contract:
 *
 * ```text
 * state and owner        authorization request (immutable), decision (terminal),
 *                        code (one-shot), encrypted artifact (one-shot)
 * persisted evidence     one row per record, one current schema version
 * resource occupied?     yes: a decision row occupies its request; a consumed
 *                        code and a claimed artifact are terminal
 * retry positively safe? no: an ambiguous commit is never retried
 * transitions            request -> decision(approved|rejected) once;
 *                        code: issued -> consumed once;
 *                        artifact: sealed -> claimed once
 * crash/reload           every transition is decided inside one transaction on a
 *                        row locked for update; a crash leaves the prior state
 * cleanup owner          the caller rolls back; the store releases its handle
 * ```
 *
 * Every `lock*` read must acquire an exclusive row lock for the life of the
 * transaction (`SELECT ... FOR UPDATE` semantics). Every one-shot writer
 * (`consumeAuthorizationCode`, `claimEncryptedArtifact`) must additionally
 * guard on the terminal column being null and report whether *this* call
 * performed the transition.
 *
 * @author taek <leekt216@gmail.com>
 */

import type {
  AuthorizationCodeRecord,
  AuthorizationDecisionRecord,
  AuthorizationRequestRecord,
  CapabilityInvalidationRecord,
  EncryptedArtifactRecord,
} from "./records.js";

export interface RelayTransaction {
  lockAuthorizationRequest(requestId: string): Promise<AuthorizationRequestRecord | undefined>;
  /** Returns false when the identifier already exists. */
  insertAuthorizationRequest(record: AuthorizationRequestRecord): Promise<boolean>;

  lockAuthorizationDecision(requestId: string): Promise<AuthorizationDecisionRecord | undefined>;
  /** Returns false when the request was already decided. */
  insertAuthorizationDecision(record: AuthorizationDecisionRecord): Promise<boolean>;

  lockAuthorizationCode(codeHash: string): Promise<AuthorizationCodeRecord | undefined>;
  insertAuthorizationCode(record: AuthorizationCodeRecord): Promise<boolean>;
  /** Returns true only when this call set `consumed_at`. */
  consumeAuthorizationCode(codeHash: string, consumedAt: number): Promise<boolean>;

  lockCapabilityInvalidation(grantId: string): Promise<CapabilityInvalidationRecord | undefined>;
  /** Returns false when the Grant's capability is already invalidated. */
  insertCapabilityInvalidation(record: CapabilityInvalidationRecord): Promise<boolean>;

  lockEncryptedArtifact(artifactId: string): Promise<EncryptedArtifactRecord | undefined>;
  insertEncryptedArtifact(record: EncryptedArtifactRecord): Promise<boolean>;
  /** Returns true only when this call set `claimed_at`. */
  claimEncryptedArtifact(artifactId: string, claimedAt: number): Promise<boolean>;

  /** Throws `relay_state_ambiguous` when the outcome cannot be proven. */
  commit(): Promise<void>;
  /** Never throws; rollback failure is a suppressed diagnostic. */
  rollback(): Promise<void>;
}

export interface RelayStore {
  begin(): Promise<RelayTransaction>;
  close(): Promise<void>;
}

/**
 * Runs one transition inside one transaction. The body commits, or the
 * transaction is rolled back and the canonical failure is preserved.
 */
export async function withRelayTransaction<Value>(
  store: RelayStore,
  run: (transaction: RelayTransaction) => Promise<Value>,
): Promise<Value> {
  const transaction = await store.begin();
  let result: Value;
  try {
    result = await run(transaction);
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
  await transaction.commit();
  return result;
}
