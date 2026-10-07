//! PostgreSQL relay store.
//!
//! Every transition reads its row with `SELECT ... FOR UPDATE` and writes
//! through a guarded statement, so concurrent workers cannot both perform a
//! one-shot transition. A `COMMIT` whose outcome cannot be proven is reported
//! as `relay_state_ambiguous`: the caller neither assumes the transition
//! applied nor retries it.
//!
//! The schema is the TypeScript relay's `oaath.relay-postgres-schema/v5`,
//! table for table, so either relay reads the other's rows. There is no
//! migration runner: an obsolete database is dropped and recreated.

use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sqlx::postgres::{PgArguments, PgPool, PgRow};
use sqlx::query::Query;
use sqlx::{Postgres, Row, Transaction};

use super::{RelayStore, RelayTransaction};
use crate::error::{RelayErrorCode, RelayResult};
use crate::oauth::records::{OAuthClientRecord, ParRecord};
use crate::records::{
    AuthorizationCodeRecord, AuthorizationDecisionRecord, AuthorizationRequestRecord,
    CapabilityInvalidationRecord, EncryptedArtifactRecord,
};
use crate::registry::{AccountRecord, AccountSignerRecord, SignerRecord};

pub const RELAY_POSTGRES_SCHEMA_VERSION: &str = "oaath.relay-postgres-schema/v7";

const MAX_SAFE_INTEGER: &str = "9007199254740991";

/// The current schema, statement for statement. Constraints the database can
/// own are owned by the database.
pub fn schema_statements() -> Vec<String> {
    let max = MAX_SAFE_INTEGER;
    vec![
        "CREATE TABLE oaath_relay_schema_v7 (
    schema_id text PRIMARY KEY CHECK (schema_id = 'oaath'),
    version text NOT NULL
  )"
        .to_owned(),
        format!(
            "INSERT INTO oaath_relay_schema_v7 (schema_id, version)
   VALUES ('oaath', '{RELAY_POSTGRES_SCHEMA_VERSION}')"
        ),
        format!(
            "CREATE TABLE oaath_relay_authorization_request_v2 (
    request_id text PRIMARY KEY,
    record_version text NOT NULL,
    client_id text NOT NULL,
    subject text NOT NULL,
    owner_device_id text NOT NULL,
    owner_subject text NOT NULL,
    organization_audience text,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    requested_scope text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oaath_relay_authorization_decision_v2 (
    request_id text PRIMARY KEY
      REFERENCES oaath_relay_authorization_request_v2 (request_id),
    record_version text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('approved', 'rejected', 'withdrawn')),
    decided_at bigint NOT NULL CHECK (decided_at >= 0 AND decided_at <= {max}),
    code_ref text,
    code_expires_at bigint CHECK (code_expires_at >= 0 AND code_expires_at <= {max}),
    CHECK ((outcome = 'approved') = (code_ref IS NOT NULL)),
    CHECK ((code_ref IS NULL) = (code_expires_at IS NULL))
  )"
        ),
        format!(
            "CREATE TABLE oaath_relay_capability_invalidation_v1 (
    grant_id text PRIMARY KEY,
    record_version text NOT NULL,
    client_id text NOT NULL,
    capability_hash text NOT NULL,
    invalidated_at bigint NOT NULL CHECK (invalidated_at >= 0 AND invalidated_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oaath_relay_authorization_code_v1 (
    code_hash text PRIMARY KEY,
    record_version text NOT NULL,
    request_id text NOT NULL UNIQUE
      REFERENCES oaath_relay_authorization_request_v2 (request_id),
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    artifact_id text NOT NULL UNIQUE,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= {max}),
    consumed_at bigint CHECK (consumed_at >= created_at AND consumed_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oaath_relay_encrypted_artifact_v1 (
    artifact_id text PRIMARY KEY,
    record_version text NOT NULL,
    request_id text NOT NULL UNIQUE
      REFERENCES oaath_relay_authorization_request_v2 (request_id),
    client_id text NOT NULL,
    ciphertext_ref text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    claimed_at bigint CHECK (claimed_at >= created_at AND claimed_at <= {max})
  )"
        ),
        "CREATE TABLE oaath_relay_revocation_request_v1 (
    operation_id text PRIMARY KEY,
    record jsonb NOT NULL CHECK (record->>'operationId' = operation_id)
  )"
        .to_owned(),
        "CREATE TABLE oaath_relay_revocation_decision_v1 (
    operation_id text PRIMARY KEY REFERENCES oaath_relay_revocation_request_v1 (operation_id),
    record jsonb NOT NULL CHECK (record->>'operationId' = operation_id)
  )"
        .to_owned(),
        "CREATE INDEX oaath_relay_revocation_scope_created_v1 ON oaath_relay_revocation_request_v1 (
    (record #>> '{signingRequest,permissionRequest,requestId}'),
    (record #>> '{signingRequest,chainId}'), ((record->>'createdAt')::bigint) DESC
  )"
        .to_owned(),
        format!(
            "CREATE TABLE oaath_signer_v1 (
    signer_id text PRIMARY KEY,
    record_version text NOT NULL,
    profile_hash text NOT NULL UNIQUE,
    authenticator_id_hash text,
    profile text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max})
  )"
        ),
        "CREATE INDEX oaath_signer_authenticator_v1 ON oaath_signer_v1 (authenticator_id_hash)"
            .to_owned(),
        format!(
            "CREATE TABLE oaath_account_v1 (
    account_id text PRIMARY KEY,
    record_version text NOT NULL,
    address text NOT NULL UNIQUE,
    root_signer_id text NOT NULL REFERENCES oaath_signer_v1 (signer_id),
    account_index bigint NOT NULL CHECK (account_index >= 0 AND account_index <= {max}),
    owner_validator text,
    profile text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    UNIQUE (root_signer_id, account_index)
  )"
        ),
        format!(
            "CREATE TABLE oaath_account_signer_v1 (
    account_id text NOT NULL REFERENCES oaath_account_v1 (account_id),
    signer_id text NOT NULL REFERENCES oaath_signer_v1 (signer_id),
    record_version text NOT NULL,
    role text NOT NULL CHECK (role IN ('root', 'permission')),
    request_id text REFERENCES oaath_relay_authorization_request_v2 (request_id),
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    CHECK ((role = 'root') = (request_id IS NULL)),
    UNIQUE (account_id, signer_id, request_id)
  )"
        ),
        "CREATE UNIQUE INDEX oaath_account_signer_root_v1 ON oaath_account_signer_v1 (account_id)
    WHERE role = 'root'"
            .to_owned(),
        format!(
            "CREATE TABLE oauth_client_v1 (
    client_id text PRIMARY KEY,
    record_version text NOT NULL,
    client_name text NOT NULL,
    redirect_uris text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oauth_par_v1 (
    par_id text PRIMARY KEY,
    record_version text NOT NULL,
    client_id text NOT NULL REFERENCES oauth_client_v1 (client_id),
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    state text,
    nonce text,
    scope text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= {max})
  )"
        ),
    ]
}

/// Creates the current schema in the pool's `search_path`, in one transaction.
/// It is not a migration: it fails if any object already exists.
pub async fn create_relay_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    for statement in schema_statements() {
        sqlx::raw_sql(&statement).execute(&mut *transaction).await?;
    }
    transaction.commit().await
}

const REQUEST_COLUMNS: &str = "request_id, record_version, client_id, subject, owner_device_id, \
     owner_subject, organization_audience, redirect_uri, code_challenge, requested_scope, \
     created_at, expires_at";
const CODE_COLUMNS: &str = "code_hash, record_version, request_id, client_id, redirect_uri, \
     code_challenge, artifact_id, created_at, expires_at, consumed_at";
const ARTIFACT_COLUMNS: &str =
    "artifact_id, record_version, request_id, client_id, ciphertext_ref, created_at, claimed_at";

pub struct PostgresRelayStore {
    pool: PgPool,
    /// Whether `close` ends the pool. A borrowed pool belongs to the deployment.
    owned: bool,
}

impl PostgresRelayStore {
    /// The store owns this pool and closes it on `close`.
    pub fn owning(pool: PgPool) -> Self {
        Self { pool, owned: true }
    }

    /// The deployment owns the pool: credentials, TLS, limits, and shutdown.
    pub fn borrowing(pool: PgPool) -> Self {
        Self { pool, owned: false }
    }
}

#[async_trait]
impl RelayStore for PostgresRelayStore {
    async fn begin(&self) -> RelayResult<Box<dyn RelayTransaction>> {
        let transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        Ok(Box::new(PostgresTransaction { transaction }))
    }

    async fn close(&self) -> RelayResult<()> {
        if self.owned {
            self.pool.close().await;
        }
        Ok(())
    }
}

struct PostgresTransaction {
    transaction: Transaction<'static, Postgres>,
}

/// One relay timestamp as a bigint parameter. Every record timestamp was
/// validated as a safe integer, so this never saturates.
fn bigint(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn text(row: &PgRow, column: &str) -> RelayResult<Value> {
    let value: Option<String> = row
        .try_get(column)
        .map_err(|_| RelayErrorCode::RecordUnreadable)?;
    Ok(value.map_or(Value::Null, Value::String))
}

fn number(row: &PgRow, column: &str) -> RelayResult<Value> {
    let value: Option<i64> = row
        .try_get(column)
        .map_err(|_| RelayErrorCode::RecordUnreadable)?;
    Ok(value.map_or(Value::Null, |value| json!(value)))
}

/// Builds the record JSON from named columns; the record parser decides.
fn columns(row: &PgRow, fields: &[(&str, &str, bool)]) -> RelayResult<Value> {
    let mut record = Map::new();
    for (key, column, numeric) in fields {
        let value = if *numeric {
            number(row, column)?
        } else {
            text(row, column)?
        };
        record.insert((*key).to_owned(), value);
    }
    Ok(Value::Object(record))
}

fn request_record(row: &PgRow) -> RelayResult<AuthorizationRequestRecord> {
    AuthorizationRequestRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("requestId", "request_id", false),
            ("clientId", "client_id", false),
            ("subject", "subject", false),
            ("ownerDeviceId", "owner_device_id", false),
            ("ownerSubject", "owner_subject", false),
            ("organizationAudience", "organization_audience", false),
            ("redirectUri", "redirect_uri", false),
            ("codeChallenge", "code_challenge", false),
            ("requestedScope", "requested_scope", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
        ],
    )?)
}

fn decision_record(row: &PgRow) -> RelayResult<AuthorizationDecisionRecord> {
    AuthorizationDecisionRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("requestId", "request_id", false),
            ("outcome", "outcome", false),
            ("decidedAt", "decided_at", true),
            ("codeRef", "code_ref", false),
            ("codeExpiresAt", "code_expires_at", true),
        ],
    )?)
}

fn invalidation_record(row: &PgRow) -> RelayResult<CapabilityInvalidationRecord> {
    CapabilityInvalidationRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("grantId", "grant_id", false),
            ("clientId", "client_id", false),
            ("capabilityHash", "capability_hash", false),
            ("invalidatedAt", "invalidated_at", true),
        ],
    )?)
}

fn code_record(row: &PgRow) -> RelayResult<AuthorizationCodeRecord> {
    AuthorizationCodeRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("codeHash", "code_hash", false),
            ("requestId", "request_id", false),
            ("clientId", "client_id", false),
            ("redirectUri", "redirect_uri", false),
            ("codeChallenge", "code_challenge", false),
            ("artifactId", "artifact_id", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
            ("consumedAt", "consumed_at", true),
        ],
    )?)
}

fn artifact_record(row: &PgRow) -> RelayResult<EncryptedArtifactRecord> {
    EncryptedArtifactRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("artifactId", "artifact_id", false),
            ("requestId", "request_id", false),
            ("clientId", "client_id", false),
            ("ciphertextRef", "ciphertext_ref", false),
            ("createdAt", "created_at", true),
            ("claimedAt", "claimed_at", true),
        ],
    )?)
}

fn signer_record(row: &PgRow) -> RelayResult<SignerRecord> {
    SignerRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("signerId", "signer_id", false),
            ("profileHash", "profile_hash", false),
            ("profile", "profile", false),
            ("createdAt", "created_at", true),
        ],
    )?)
}

const ACCOUNT_FIELDS: [(&str, &str, bool); 8] = [
    ("version", "account_version", false),
    ("accountId", "account_id", false),
    ("address", "address", false),
    ("rootSignerId", "root_signer_id", false),
    ("accountIndex", "account_index", true),
    ("ownerValidator", "owner_validator", false),
    ("profile", "profile", false),
    ("createdAt", "account_created_at", true),
];

const MEMBERSHIP_FIELDS: [(&str, &str, bool); 6] = [
    ("version", "membership_version", false),
    ("accountId", "account_id", false),
    ("signerId", "signer_id", false),
    ("role", "role", false),
    ("requestId", "request_id", false),
    ("createdAt", "membership_created_at", true),
];

fn membership_row(row: &PgRow) -> RelayResult<(AccountRecord, AccountSignerRecord)> {
    Ok((
        AccountRecord::parse(&columns(row, &ACCOUNT_FIELDS)?)?,
        AccountSignerRecord::parse(&columns(row, &MEMBERSHIP_FIELDS)?)?,
    ))
}

fn client_record(row: &PgRow) -> RelayResult<OAuthClientRecord> {
    let mut record = columns(
        row,
        &[
            ("version", "record_version", false),
            ("clientId", "client_id", false),
            ("clientName", "client_name", false),
            ("createdAt", "created_at", true),
        ],
    )?;
    let uris: String = row
        .try_get("redirect_uris")
        .map_err(|_| RelayErrorCode::RecordUnreadable)?;
    record["redirectUris"] =
        serde_json::from_str(&uris).map_err(|_| RelayErrorCode::RecordUnreadable)?;
    OAuthClientRecord::parse(&record)
}

fn par_record(row: &PgRow) -> RelayResult<ParRecord> {
    ParRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("parId", "par_id", false),
            ("clientId", "client_id", false),
            ("redirectUri", "redirect_uri", false),
            ("codeChallenge", "code_challenge", false),
            ("state", "state", false),
            ("nonce", "nonce", false),
            ("scope", "scope", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
        ],
    )?)
}

const ACCOUNT_COLUMNS: &str = "record_version AS account_version, account_id, address, \
     root_signer_id, account_index, owner_validator, profile, created_at AS account_created_at";

type PgQuery<'q> = Query<'q, Postgres, PgArguments>;

impl PostgresTransaction {
    /// At most one row; a key matching several rows is unreadable.
    async fn first<Record>(
        &mut self,
        query: PgQuery<'_>,
        map: fn(&PgRow) -> RelayResult<Record>,
    ) -> RelayResult<Option<Record>> {
        // Nothing has committed, so a failed statement is not ambiguous yet.
        let rows = query
            .fetch_all(&mut *self.transaction)
            .await
            .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => map(row).map(Some),
            _ => Err(RelayErrorCode::RecordUnreadable),
        }
    }

    /// Whether the guarded statement affected exactly one row.
    async fn applied(&mut self, query: PgQuery<'_>) -> RelayResult<bool> {
        let result = query
            .execute(&mut *self.transaction)
            .await
            .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        Ok(result.rows_affected() == 1)
    }
}

#[async_trait]
impl RelayTransaction for PostgresTransaction {
    async fn lock_authorization_request(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<AuthorizationRequestRecord>> {
        let sql = format!(
            "SELECT {REQUEST_COLUMNS} FROM oaath_relay_authorization_request_v2 \
             WHERE request_id = $1 FOR UPDATE"
        );
        self.first(sqlx::query(&sql).bind(request_id), request_record)
            .await
    }

    async fn insert_authorization_request(
        &mut self,
        record: &AuthorizationRequestRecord,
    ) -> RelayResult<bool> {
        let sql = format!(
            "INSERT INTO oaath_relay_authorization_request_v2 ({REQUEST_COLUMNS}) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (request_id) DO NOTHING"
        );
        self.applied(
            sqlx::query(&sql)
                .bind(&record.request_id)
                .bind(record.version)
                .bind(&record.client_id)
                .bind(&record.subject)
                .bind(&record.owner_device_id)
                .bind(&record.owner_subject)
                .bind(&record.organization_audience)
                .bind(&record.redirect_uri)
                .bind(&record.code_challenge)
                .bind(&record.requested_scope)
                .bind(bigint(record.created_at))
                .bind(bigint(record.expires_at)),
        )
        .await
    }

    async fn lock_authorization_decision(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<AuthorizationDecisionRecord>> {
        self.first(
            sqlx::query(
                "SELECT request_id, record_version, outcome, decided_at, code_ref, code_expires_at \
                 FROM oaath_relay_authorization_decision_v2 WHERE request_id = $1 FOR UPDATE",
            )
            .bind(request_id),
            decision_record,
        )
        .await
    }

    async fn insert_authorization_decision(
        &mut self,
        record: &AuthorizationDecisionRecord,
    ) -> RelayResult<bool> {
        self.applied(
            sqlx::query(
                "INSERT INTO oaath_relay_authorization_decision_v2 (\
                 request_id, record_version, outcome, decided_at, code_ref, code_expires_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (request_id) DO NOTHING",
            )
            .bind(&record.request_id)
            .bind(record.version)
            .bind(record.outcome.as_str())
            .bind(bigint(record.decided_at))
            .bind(&record.code_ref)
            .bind(record.code_expires_at.map(bigint)),
        )
        .await
    }

    async fn lock_authorization_code(
        &mut self,
        code_hash: &str,
    ) -> RelayResult<Option<AuthorizationCodeRecord>> {
        let sql = format!(
            "SELECT {CODE_COLUMNS} FROM oaath_relay_authorization_code_v1 \
             WHERE code_hash = $1 FOR UPDATE"
        );
        self.first(sqlx::query(&sql).bind(code_hash), code_record)
            .await
    }

    async fn insert_authorization_code(
        &mut self,
        record: &AuthorizationCodeRecord,
    ) -> RelayResult<bool> {
        let sql = format!(
            "INSERT INTO oaath_relay_authorization_code_v1 ({CODE_COLUMNS}) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING"
        );
        self.applied(
            sqlx::query(&sql)
                .bind(&record.code_hash)
                .bind(record.version)
                .bind(&record.request_id)
                .bind(&record.client_id)
                .bind(&record.redirect_uri)
                .bind(&record.code_challenge)
                .bind(&record.artifact_id)
                .bind(bigint(record.created_at))
                .bind(bigint(record.expires_at))
                .bind(record.consumed_at.map(bigint)),
        )
        .await
    }

    async fn consume_authorization_code(
        &mut self,
        code_hash: &str,
        consumed_at: u64,
    ) -> RelayResult<bool> {
        // One-shot: the guard makes a second consume affect zero rows.
        self.applied(
            sqlx::query(
                "UPDATE oaath_relay_authorization_code_v1 SET consumed_at = $2 \
                 WHERE code_hash = $1 AND consumed_at IS NULL",
            )
            .bind(code_hash)
            .bind(bigint(consumed_at)),
        )
        .await
    }

    async fn lock_capability_invalidation(
        &mut self,
        grant_id: &str,
    ) -> RelayResult<Option<CapabilityInvalidationRecord>> {
        self.first(
            sqlx::query(
                "SELECT grant_id, record_version, client_id, capability_hash, invalidated_at \
                 FROM oaath_relay_capability_invalidation_v1 WHERE grant_id = $1 FOR UPDATE",
            )
            .bind(grant_id),
            invalidation_record,
        )
        .await
    }

    async fn insert_capability_invalidation(
        &mut self,
        record: &CapabilityInvalidationRecord,
    ) -> RelayResult<bool> {
        self.applied(
            sqlx::query(
                "INSERT INTO oaath_relay_capability_invalidation_v1 (\
                 grant_id, record_version, client_id, capability_hash, invalidated_at\
                 ) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (grant_id) DO NOTHING",
            )
            .bind(&record.grant_id)
            .bind(record.version)
            .bind(&record.client_id)
            .bind(&record.capability_hash)
            .bind(bigint(record.invalidated_at)),
        )
        .await
    }

    async fn lock_encrypted_artifact(
        &mut self,
        artifact_id: &str,
    ) -> RelayResult<Option<EncryptedArtifactRecord>> {
        let sql = format!(
            "SELECT {ARTIFACT_COLUMNS} FROM oaath_relay_encrypted_artifact_v1 \
             WHERE artifact_id = $1 FOR UPDATE"
        );
        self.first(sqlx::query(&sql).bind(artifact_id), artifact_record)
            .await
    }

    async fn lock_encrypted_artifact_by_request_id(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<EncryptedArtifactRecord>> {
        let sql = format!(
            "SELECT {ARTIFACT_COLUMNS} FROM oaath_relay_encrypted_artifact_v1 \
             WHERE request_id = $1 FOR UPDATE"
        );
        self.first(sqlx::query(&sql).bind(request_id), artifact_record)
            .await
    }

    async fn insert_encrypted_artifact(
        &mut self,
        record: &EncryptedArtifactRecord,
    ) -> RelayResult<bool> {
        let sql = format!(
            "INSERT INTO oaath_relay_encrypted_artifact_v1 ({ARTIFACT_COLUMNS}) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING"
        );
        self.applied(
            sqlx::query(&sql)
                .bind(&record.artifact_id)
                .bind(record.version)
                .bind(&record.request_id)
                .bind(&record.client_id)
                .bind(&record.ciphertext_ref)
                .bind(bigint(record.created_at))
                .bind(record.claimed_at.map(bigint)),
        )
        .await
    }

    async fn claim_encrypted_artifact(
        &mut self,
        artifact_id: &str,
        claimed_at: u64,
    ) -> RelayResult<bool> {
        // One-shot: the guard makes a second claim affect zero rows.
        self.applied(
            sqlx::query(
                "UPDATE oaath_relay_encrypted_artifact_v1 SET claimed_at = $2 \
                 WHERE artifact_id = $1 AND claimed_at IS NULL",
            )
            .bind(artifact_id)
            .bind(bigint(claimed_at)),
        )
        .await
    }

    async fn lock_signer(&mut self, signer_id: &str) -> RelayResult<Option<SignerRecord>> {
        self.first(
            sqlx::query(
                "SELECT signer_id, record_version, profile_hash, profile, created_at \
                 FROM oaath_signer_v1 WHERE signer_id = $1 FOR UPDATE",
            )
            .bind(signer_id),
            signer_record,
        )
        .await
    }

    async fn lock_signer_by_profile_hash(
        &mut self,
        profile_hash: &str,
    ) -> RelayResult<Option<SignerRecord>> {
        self.first(
            sqlx::query(
                "SELECT signer_id, record_version, profile_hash, profile, created_at \
                 FROM oaath_signer_v1 WHERE profile_hash = $1 FOR UPDATE",
            )
            .bind(profile_hash),
            signer_record,
        )
        .await
    }

    async fn list_signers_by_authenticator(
        &mut self,
        authenticator_id_hash: &str,
    ) -> RelayResult<Vec<SignerRecord>> {
        let rows = sqlx::query(
            "SELECT signer_id, record_version, profile_hash, profile, created_at \
             FROM oaath_signer_v1 WHERE authenticator_id_hash = $1 \
             ORDER BY created_at, signer_id COLLATE \"C\"",
        )
        .bind(authenticator_id_hash)
        .fetch_all(&mut *self.transaction)
        .await
        .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        let signers = rows
            .iter()
            .map(signer_record)
            .collect::<RelayResult<Vec<_>>>()?;
        // The index column is a copy; the stored profile owns the fact.
        for signer in &signers {
            if signer.authenticator_id_hash()?.as_deref() != Some(authenticator_id_hash) {
                return Err(RelayErrorCode::RecordUnreadable);
            }
        }
        Ok(signers)
    }

    async fn insert_signer(&mut self, record: &SignerRecord) -> RelayResult<bool> {
        self.applied(
            sqlx::query(
                "INSERT INTO oaath_signer_v1 (\
                 signer_id, record_version, profile_hash, authenticator_id_hash, profile, \
                 created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            )
            .bind(&record.signer_id)
            .bind(record.version)
            .bind(&record.profile_hash)
            .bind(record.authenticator_id_hash()?)
            .bind(&record.profile)
            .bind(bigint(record.created_at)),
        )
        .await
    }

    async fn list_signer_accounts(
        &mut self,
        signer_id: &str,
    ) -> RelayResult<Vec<(AccountRecord, AccountSignerRecord)>> {
        let rows = sqlx::query(
            "SELECT account.record_version AS account_version, account.account_id, \
             account.address, account.root_signer_id, account.account_index, \
             account.owner_validator, account.profile, \
             account.created_at AS account_created_at, \
             membership.record_version AS membership_version, membership.signer_id, \
             membership.role, membership.request_id, \
             membership.created_at AS membership_created_at \
             FROM oaath_account_signer_v1 AS membership \
             JOIN oaath_account_v1 AS account ON account.account_id = membership.account_id \
             WHERE membership.signer_id = $1 \
             ORDER BY account.created_at, account.account_id COLLATE \"C\"",
        )
        .bind(signer_id)
        .fetch_all(&mut *self.transaction)
        .await
        .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        rows.iter().map(membership_row).collect()
    }

    async fn insert_account(&mut self, record: &AccountRecord) -> RelayResult<bool> {
        // An unknown root signer inserts nothing instead of aborting.
        self.applied(
            sqlx::query(
                "INSERT INTO oaath_account_v1 (\
                 account_id, record_version, address, root_signer_id, account_index, \
                 owner_validator, profile, created_at) SELECT $1, $2, $3, $4, $5, $6, $7, $8 \
                 WHERE EXISTS (SELECT 1 FROM oaath_signer_v1 WHERE signer_id = $4) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.account_id)
            .bind(record.version)
            .bind(&record.address)
            .bind(&record.root_signer_id)
            .bind(bigint(record.account_index))
            .bind(&record.owner_validator)
            .bind(&record.profile)
            .bind(bigint(record.created_at)),
        )
        .await
    }

    async fn insert_account_signer(&mut self, record: &AccountSignerRecord) -> RelayResult<bool> {
        // An unknown account or signer inserts nothing instead of aborting;
        // the partial unique index refuses a second root.
        self.applied(
            sqlx::query(
                "INSERT INTO oaath_account_signer_v1 (\
                 account_id, signer_id, record_version, role, request_id, created_at\
                 ) SELECT $1, $2, $3, $4, $5, $6 \
                 WHERE EXISTS (SELECT 1 FROM oaath_account_v1 WHERE account_id = $1) \
                 AND EXISTS (SELECT 1 FROM oaath_signer_v1 WHERE signer_id = $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.account_id)
            .bind(&record.signer_id)
            .bind(record.version)
            .bind(record.role.as_str())
            .bind(&record.request_id)
            .bind(bigint(record.created_at)),
        )
        .await
    }

    async fn lock_account(&mut self, account_id: &str) -> RelayResult<Option<AccountRecord>> {
        let sql = format!(
            "SELECT {ACCOUNT_COLUMNS} FROM oaath_account_v1 WHERE account_id = $1 FOR UPDATE"
        );
        self.first(sqlx::query(&sql).bind(account_id), |row| {
            AccountRecord::parse(&columns(row, &ACCOUNT_FIELDS)?)
        })
        .await
    }

    async fn lock_oauth_client(
        &mut self,
        client_id: &str,
    ) -> RelayResult<Option<OAuthClientRecord>> {
        self.first(
            sqlx::query(
                "SELECT client_id, record_version, client_name, redirect_uris, created_at \
                 FROM oauth_client_v1 WHERE client_id = $1 FOR UPDATE",
            )
            .bind(client_id),
            client_record,
        )
        .await
    }

    async fn insert_oauth_client(&mut self, record: &OAuthClientRecord) -> RelayResult<bool> {
        let uris =
            serde_json::to_string(&record.redirect_uris).map_err(|_| RelayErrorCode::Internal)?;
        self.applied(
            sqlx::query(
                "INSERT INTO oauth_client_v1 (\
                 client_id, record_version, client_name, redirect_uris, created_at\
                 ) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            )
            .bind(&record.client_id)
            .bind(record.version)
            .bind(&record.client_name)
            .bind(uris)
            .bind(bigint(record.created_at)),
        )
        .await
    }

    async fn lock_par(&mut self, par_id: &str) -> RelayResult<Option<ParRecord>> {
        self.first(
            sqlx::query(
                "SELECT par_id, record_version, client_id, redirect_uri, code_challenge, state, \
                 nonce, scope, created_at, expires_at FROM oauth_par_v1 \
                 WHERE par_id = $1 FOR UPDATE",
            )
            .bind(par_id),
            par_record,
        )
        .await
    }

    async fn insert_par(&mut self, record: &ParRecord) -> RelayResult<bool> {
        // An unknown client inserts nothing instead of aborting.
        self.applied(
            sqlx::query(
                "INSERT INTO oauth_par_v1 (\
                 par_id, record_version, client_id, redirect_uri, code_challenge, state, nonce, \
                 scope, created_at, expires_at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 \
                 WHERE EXISTS (SELECT 1 FROM oauth_client_v1 WHERE client_id = $3) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.par_id)
            .bind(record.version)
            .bind(&record.client_id)
            .bind(&record.redirect_uri)
            .bind(&record.code_challenge)
            .bind(&record.state)
            .bind(&record.nonce)
            .bind(&record.scope)
            .bind(bigint(record.created_at))
            .bind(bigint(record.expires_at)),
        )
        .await
    }

    async fn commit(self: Box<Self>) -> RelayResult<()> {
        // A COMMIT that did not answer never proves its own outcome. Every
        // statement before it succeeded, so the transaction was not aborted.
        self.transaction
            .commit()
            .await
            .map_err(|_| RelayErrorCode::StateAmbiguous)
    }

    async fn rollback(self: Box<Self>) {
        // Cleanup is secondary; a failed rollback leaves sqlx to discard the
        // connection instead of reusing it.
        let _ = self.transaction.rollback().await;
    }
}
