/**
 * The current relay schema. There is no migration runner and no reader for any
 * older schema: an obsolete database is dropped and recreated.
 *
 * Constraints that the database can own are owned by the database — one decision
 * per request, one code and one artifact per request, monotonic timestamps.
 *
 * @author taek <leekt216@gmail.com>
 */

export const OAATH_RELAY_POSTGRES_SCHEMA_VERSION = "oaath.relay-postgres-schema/v1" as const;

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

export const OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS: readonly string[] = Object.freeze([
  `CREATE TABLE oaath_relay_schema_v1 (
    schema_id text PRIMARY KEY CHECK (schema_id = 'oaath'),
    version text NOT NULL
  )`,
  `INSERT INTO oaath_relay_schema_v1 (schema_id, version)
   VALUES ('oaath', '${OAATH_RELAY_POSTGRES_SCHEMA_VERSION}')`,
  `CREATE TABLE oaath_relay_authorization_request_v1 (
    request_id text PRIMARY KEY,
    record_version text NOT NULL,
    client_id text NOT NULL,
    subject text NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    requested_scope text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= ${MAX_SAFE_INTEGER}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= ${MAX_SAFE_INTEGER})
  )`,
  `CREATE TABLE oaath_relay_authorization_decision_v1 (
    request_id text PRIMARY KEY
      REFERENCES oaath_relay_authorization_request_v1 (request_id),
    record_version text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('approved', 'rejected')),
    decided_at bigint NOT NULL CHECK (decided_at >= 0 AND decided_at <= ${MAX_SAFE_INTEGER})
  )`,
  `CREATE TABLE oaath_relay_authorization_code_v1 (
    code_hash text PRIMARY KEY,
    record_version text NOT NULL,
    request_id text NOT NULL UNIQUE
      REFERENCES oaath_relay_authorization_request_v1 (request_id),
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    artifact_id text NOT NULL UNIQUE,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= ${MAX_SAFE_INTEGER}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= ${MAX_SAFE_INTEGER}),
    consumed_at bigint CHECK (consumed_at >= created_at AND consumed_at <= ${MAX_SAFE_INTEGER})
  )`,
  `CREATE TABLE oaath_relay_encrypted_artifact_v1 (
    artifact_id text PRIMARY KEY,
    record_version text NOT NULL,
    request_id text NOT NULL UNIQUE
      REFERENCES oaath_relay_authorization_request_v1 (request_id),
    client_id text NOT NULL,
    ciphertext_ref text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= ${MAX_SAFE_INTEGER}),
    claimed_at bigint CHECK (claimed_at >= created_at AND claimed_at <= ${MAX_SAFE_INTEGER})
  )`,
]);

export interface RelaySchemaExecutor {
  query(sql: string): Promise<unknown>;
}

/**
 * Creates the current schema in the executor's `search_path`. It is not a
 * migration: it fails if the objects already exist.
 */
export async function createPostgresRelaySchema(executor: RelaySchemaExecutor): Promise<void> {
  for (const statement of OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS) {
    await executor.query(statement);
  }
}
