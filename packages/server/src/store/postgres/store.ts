/**
 * PostgreSQL relay store.
 *
 * Every transition reads its row with `SELECT ... FOR UPDATE` and writes through
 * a guarded statement, so concurrent workers cannot both perform a one-shot
 * transition. A `COMMIT` whose outcome cannot be proven is reported as
 * `relay_state_ambiguous`: the caller neither assumes the transition applied nor
 * retries it.
 *
 * @author taek <leekt216@gmail.com>
 */

import type { Pool, PoolClient } from "pg";
import pg from "pg";
import { relayFailure } from "../../relay/errors.js";
import type { RelayStore, RelayTransaction } from "../interface.js";
import {
  type AuthorizationCodeRecord,
  type AuthorizationDecisionRecord,
  type AuthorizationRequestRecord,
  type EncryptedArtifactRecord,
  parseAuthorizationCodeRecord,
  parseAuthorizationDecisionRecord,
  parseAuthorizationRequestRecord,
  parseEncryptedArtifactRecord,
} from "../records.js";
import {
  CLAIM_ENCRYPTED_ARTIFACT,
  CONSUME_AUTHORIZATION_CODE,
  INSERT_AUTHORIZATION_CODE,
  INSERT_AUTHORIZATION_DECISION,
  INSERT_AUTHORIZATION_REQUEST,
  INSERT_ENCRYPTED_ARTIFACT,
  LOCK_AUTHORIZATION_CODE,
  LOCK_AUTHORIZATION_DECISION,
  LOCK_AUTHORIZATION_REQUEST,
  LOCK_ENCRYPTED_ARTIFACT,
} from "./queries.js";

export type PostgresRelayStoreOptions =
  /** The deployment owns the pool: credentials, TLS, limits, and shutdown. */
  | Readonly<{ pool: Pool }>
  /** The store owns a pool created from this connection string. */
  | Readonly<{ connectionString: string }>;

type Row = Record<string, unknown>;

/** `bigint` arrives as a decimal string; the record parser validates the result. */
function sqlTimestamp(value: unknown): unknown {
  if (typeof value !== "string") return value;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : value;
}

function requestRecord(row: Row): AuthorizationRequestRecord {
  return parseAuthorizationRequestRecord({
    version: row.record_version,
    requestId: row.request_id,
    clientId: row.client_id,
    subject: row.subject,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    requestedScope: row.requested_scope,
    createdAt: sqlTimestamp(row.created_at),
    expiresAt: sqlTimestamp(row.expires_at),
  });
}

function decisionRecord(row: Row): AuthorizationDecisionRecord {
  return parseAuthorizationDecisionRecord({
    version: row.record_version,
    requestId: row.request_id,
    outcome: row.outcome,
    decidedAt: sqlTimestamp(row.decided_at),
  });
}

function codeRecord(row: Row): AuthorizationCodeRecord {
  return parseAuthorizationCodeRecord({
    version: row.record_version,
    codeHash: row.code_hash,
    requestId: row.request_id,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    artifactId: row.artifact_id,
    createdAt: sqlTimestamp(row.created_at),
    expiresAt: sqlTimestamp(row.expires_at),
    consumedAt: sqlTimestamp(row.consumed_at),
  });
}

function artifactRecord(row: Row): EncryptedArtifactRecord {
  return parseEncryptedArtifactRecord({
    version: row.record_version,
    artifactId: row.artifact_id,
    requestId: row.request_id,
    clientId: row.client_id,
    ciphertextRef: row.ciphertext_ref,
    createdAt: sqlTimestamp(row.created_at),
    claimedAt: sqlTimestamp(row.claimed_at),
  });
}

function createTransaction(client: PoolClient): RelayTransaction {
  let settled = false;

  async function run(
    sql: string,
    parameters: readonly unknown[],
  ): Promise<{ readonly rows: readonly Row[]; readonly rowCount: number }> {
    if (settled) relayFailure("relay_internal", "relay transaction already settled");
    try {
      const result = await client.query(sql, [...parameters]);
      return { rows: result.rows, rowCount: result.rowCount ?? 0 };
    } catch {
      // Nothing has committed, so nothing is ambiguous yet.
      return relayFailure("relay_store_unavailable", "relay statement failed");
    }
  }

  async function first<Value>(
    sql: string,
    parameters: readonly unknown[],
    map: (row: Row) => Value,
  ): Promise<Value | undefined> {
    const { rows } = await run(sql, parameters);
    if (rows.length === 0) return undefined;
    if (rows.length > 1) {
      return relayFailure("relay_record_unreadable", "relay key matched multiple rows");
    }
    const row = rows[0];
    return row === undefined ? undefined : map(row);
  }

  async function inserted(sql: string, parameters: readonly unknown[]): Promise<boolean> {
    return (await run(sql, parameters)).rowCount === 1;
  }

  return {
    lockAuthorizationRequest(requestId) {
      return first(LOCK_AUTHORIZATION_REQUEST, [requestId], requestRecord);
    },
    insertAuthorizationRequest(record) {
      return inserted(INSERT_AUTHORIZATION_REQUEST, [
        record.requestId,
        record.version,
        record.clientId,
        record.subject,
        record.redirectUri,
        record.codeChallenge,
        record.requestedScope,
        record.createdAt,
        record.expiresAt,
      ]);
    },
    lockAuthorizationDecision(requestId) {
      return first(LOCK_AUTHORIZATION_DECISION, [requestId], decisionRecord);
    },
    insertAuthorizationDecision(record) {
      return inserted(INSERT_AUTHORIZATION_DECISION, [
        record.requestId,
        record.version,
        record.outcome,
        record.decidedAt,
      ]);
    },
    lockAuthorizationCode(codeHash) {
      return first(LOCK_AUTHORIZATION_CODE, [codeHash], codeRecord);
    },
    insertAuthorizationCode(record) {
      return inserted(INSERT_AUTHORIZATION_CODE, [
        record.codeHash,
        record.version,
        record.requestId,
        record.clientId,
        record.redirectUri,
        record.codeChallenge,
        record.artifactId,
        record.createdAt,
        record.expiresAt,
        record.consumedAt,
      ]);
    },
    consumeAuthorizationCode(codeHash, consumedAt) {
      return inserted(CONSUME_AUTHORIZATION_CODE, [codeHash, consumedAt]);
    },
    lockEncryptedArtifact(artifactId) {
      return first(LOCK_ENCRYPTED_ARTIFACT, [artifactId], artifactRecord);
    },
    insertEncryptedArtifact(record) {
      return inserted(INSERT_ENCRYPTED_ARTIFACT, [
        record.artifactId,
        record.version,
        record.requestId,
        record.clientId,
        record.ciphertextRef,
        record.createdAt,
        record.claimedAt,
      ]);
    },
    claimEncryptedArtifact(artifactId, claimedAt) {
      return inserted(CLAIM_ENCRYPTED_ARTIFACT, [artifactId, claimedAt]);
    },
    async commit() {
      if (settled) relayFailure("relay_internal", "relay transaction already settled");
      settled = true;
      let command: unknown;
      try {
        command = (await client.query("COMMIT")).command;
      } catch {
        // A COMMIT that did not answer never proves its own outcome.
        client.release(true);
        return relayFailure("relay_state_ambiguous", "relay commit outcome is unproven");
      }
      if (command !== "COMMIT") {
        // PostgreSQL answers an aborted transaction's COMMIT with ROLLBACK.
        client.release(true);
        return relayFailure("relay_state_ambiguous", "relay commit did not commit");
      }
      client.release();
    },
    async rollback() {
      if (settled) return;
      settled = true;
      try {
        await client.query("ROLLBACK");
        client.release();
      } catch {
        // Cleanup is secondary; discard the connection instead of reusing it.
        client.release(true);
      }
    },
  };
}

export function createPostgresRelayStore(options: PostgresRelayStoreOptions): RelayStore {
  const owned = !("pool" in options);
  const pool: Pool =
    "pool" in options ? options.pool : new pg.Pool({ connectionString: options.connectionString });

  return {
    async begin(): Promise<RelayTransaction> {
      let client: PoolClient;
      try {
        client = await pool.connect();
      } catch {
        return relayFailure("relay_store_unavailable", "relay connection is unavailable");
      }
      try {
        await client.query("BEGIN");
      } catch {
        client.release(true);
        return relayFailure("relay_store_unavailable", "relay transaction could not start");
      }
      return createTransaction(client);
    },
    async close(): Promise<void> {
      // A borrowed pool belongs to the deployment.
      if (!owned) return;
      try {
        await pool.end();
      } catch {
        relayFailure("relay_store_unavailable", "relay pool could not be closed");
      }
    },
  };
}
