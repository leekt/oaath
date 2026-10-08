//! PostgreSQL relay store.
//!
//! Every transition reads its row with `SELECT ... FOR UPDATE` and writes
//! through a guarded statement, so concurrent workers cannot both perform a
//! one-shot transition. A `COMMIT` whose outcome cannot be proven is reported
//! as `relay_state_ambiguous`: the caller neither assumes the transition
//! applied nor retries it.
//!
//! One current schema, `oaath.relay-postgres-schema/v1`. There is no
//! migration runner: an obsolete database is dropped and recreated.

use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sqlx::postgres::{PgArguments, PgPool, PgRow};
use sqlx::query::Query;
use sqlx::{Postgres, Row, Transaction};

use super::{RelayStore, RelayTransaction};
use crate::account_import::AccountImportRecord;
use crate::error::{RelayErrorCode, RelayResult};
use crate::link::{LinkOutcome, LinkRequestRecord};
use crate::oauth::pending::{PendingGrantRecord, PendingOutcome};
use crate::oauth::records::{AccessTokenRecord, OAuthClientRecord, ParRecord};
use crate::policy::PolicyTemplateRecord;
use crate::records::{
    AuthorizationCodeRecord, AuthorizationDecisionRecord, AuthorizationRequestRecord,
    CapabilityInvalidationRecord, EncryptedArtifactRecord,
};
use crate::registry::{AccountRecord, AccountSignerRecord, MembershipStatus, SignerRecord};
use crate::revocation::{RevocationDelivery, RevocationRecord};
use crate::session::{PortalChallengeRecord, PortalSessionRecord};
use oaath_protocol::capture::parse_json;

pub const RELAY_POSTGRES_SCHEMA_VERSION: &str = "oaath.relay-postgres-schema/v1";

const MAX_SAFE_INTEGER: &str = "9007199254740991";

/// The current schema, statement for statement. Constraints the database can
/// own are owned by the database.
pub fn schema_statements() -> Vec<String> {
    let max = MAX_SAFE_INTEGER;
    vec![
        "CREATE TABLE oaath_relay_schema_v1 (
    schema_id text PRIMARY KEY CHECK (schema_id = 'oaath'),
    version text NOT NULL
  )"
        .to_owned(),
        format!(
            "INSERT INTO oaath_relay_schema_v1 (schema_id, version)
   VALUES ('oaath', '{RELAY_POSTGRES_SCHEMA_VERSION}')"
        ),
        format!(
            "CREATE TABLE oaath_relay_authorization_request_v1 (
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
            "CREATE TABLE oaath_relay_authorization_decision_v1 (
    request_id text PRIMARY KEY
      REFERENCES oaath_relay_authorization_request_v1 (request_id),
    record_version text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('approved', 'rejected', 'withdrawn')),
    decided_at bigint NOT NULL CHECK (decided_at >= 0 AND decided_at <= {max}),
    code_ref text,
    code_expires_at bigint CHECK (code_expires_at >= 0 AND code_expires_at <= {max}),
    CHECK (code_ref IS NULL OR outcome = 'approved'),
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
      REFERENCES oaath_relay_authorization_request_v1 (request_id),
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
      REFERENCES oaath_relay_authorization_request_v1 (request_id),
    client_id text NOT NULL,
    ciphertext_ref text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    claimed_at bigint CHECK (claimed_at >= created_at AND claimed_at <= {max})
  )"
        ),
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
        "CREATE UNIQUE INDEX oaath_signer_authenticator_v1 ON oaath_signer_v1 (authenticator_id_hash)"
            .to_owned(),
        format!(
            "CREATE TABLE oaath_account_v1 (
    account_id text PRIMARY KEY,
    record_version text NOT NULL,
    address text NOT NULL UNIQUE,
    root_signer_id text NOT NULL REFERENCES oaath_signer_v1 (signer_id),
    account_index bigint CHECK (account_index >= 0 AND account_index <= {max}),
    creation_key text,
    owner_validator text,
    profile text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    UNIQUE (root_signer_id, account_index),
    UNIQUE (root_signer_id, creation_key),
    CHECK ((account_index IS NULL) = (creation_key IS NULL))
  )"
        ),
        format!(
            "CREATE TABLE oaath_link_request_v1 (
    link_id text PRIMARY KEY,
    record_version text NOT NULL,
    account_id text NOT NULL REFERENCES oaath_account_v1 (account_id),
    signer_id text NOT NULL REFERENCES oaath_signer_v1 (signer_id),
    label text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at > created_at AND expires_at <= {max}),
    outcome text CHECK (outcome IN ('approved', 'rejected')),
    decided_at bigint CHECK (decided_at >= 0 AND decided_at <= {max}),
    approval_signature text,
    grant_id text,
    removed_at bigint CHECK (removed_at >= 0 AND removed_at <= {max}),
    CHECK ((outcome IS NULL) = (decided_at IS NULL)),
    CHECK ((outcome IS NOT DISTINCT FROM 'approved')
      = ((approval_signature IS NOT NULL) <> (grant_id IS NOT NULL))),
    CHECK (approval_signature IS NULL OR grant_id IS NULL),
    CHECK (grant_id IS NULL OR grant_id = link_id),
    CHECK (removed_at IS NULL OR outcome = 'approved')
  )"
        ),
        format!(
            "CREATE TABLE oaath_account_signer_v1 (
    account_id text NOT NULL REFERENCES oaath_account_v1 (account_id),
    signer_id text NOT NULL REFERENCES oaath_signer_v1 (signer_id),
    record_version text NOT NULL,
    role text NOT NULL CHECK (role IN ('root', 'permission')),
    request_id text REFERENCES oaath_relay_authorization_request_v1 (request_id),
    link_id text REFERENCES oaath_link_request_v1 (link_id),
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    CHECK ((role = 'root') = (request_id IS NULL AND link_id IS NULL)),
    CHECK (request_id IS NULL OR link_id IS NULL),
    status text NOT NULL CHECK (status IN ('active', 'suspended')),
    suspended_at bigint CHECK (suspended_at >= 0 AND suspended_at <= {max}),
    restored_at bigint CHECK (restored_at >= 0 AND restored_at <= {max}),
    CHECK (role = 'permission' OR (status = 'active' AND suspended_at IS NULL)),
    CHECK (status = 'active' OR suspended_at IS NOT NULL),
    CHECK (restored_at IS NULL OR suspended_at IS NOT NULL)
  )"
        ),
        "CREATE UNIQUE INDEX oaath_account_signer_root_v1 ON oaath_account_signer_v1 (account_id)
    WHERE role = 'root'"
            .to_owned(),
        "CREATE UNIQUE INDEX oaath_account_signer_grant_v1
    ON oaath_account_signer_v1 (account_id, signer_id, request_id) WHERE request_id IS NOT NULL"
            .to_owned(),
        "CREATE UNIQUE INDEX oaath_account_signer_link_v1
    ON oaath_account_signer_v1 (account_id, signer_id, link_id) WHERE link_id IS NOT NULL"
            .to_owned(),
        format!(
            "CREATE TABLE oauth_client_v1 (
    client_id text PRIMARY KEY,
    record_version text NOT NULL,
    client_name text NOT NULL,
    redirect_uris text NOT NULL,
    revocation_delivery text NOT NULL CHECK (revocation_delivery IN ('relay', 'dapp')),
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
    authorization_details text,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oauth_access_token_v1 (
    token_hash text PRIMARY KEY,
    record_version text NOT NULL,
    client_id text NOT NULL REFERENCES oauth_client_v1 (client_id),
    request_id text NOT NULL REFERENCES oaath_relay_authorization_request_v1 (request_id),
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= {max}),
    revoked_at bigint CHECK (revoked_at >= created_at AND revoked_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oaath_portal_challenge_v1 (
    nonce text PRIMARY KEY,
    record_version text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= {max}),
    consumed_at bigint CHECK (consumed_at >= created_at AND consumed_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oaath_portal_session_v1 (
    token_hash text PRIMARY KEY,
    record_version text NOT NULL,
    signer_id text NOT NULL REFERENCES oaath_signer_v1 (signer_id),
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at >= created_at AND expires_at <= {max}),
    signed_out_at bigint CHECK (signed_out_at >= created_at AND signed_out_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oaath_account_import_v1 (
    account_id text PRIMARY KEY REFERENCES oaath_account_v1 (account_id),
    record_version text NOT NULL,
    inventory_fingerprint text NOT NULL,
    issued_at bigint NOT NULL CHECK (issued_at >= 0 AND issued_at <= {max}),
    nonce text NOT NULL,
    signature text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max})
  )"
        ),
        format!(
            "CREATE TABLE oaath_write_budget_v1 (
    bucket text NOT NULL,
    window_start bigint NOT NULL CHECK (window_start >= 0 AND window_start <= {max}),
    count bigint NOT NULL CHECK (count >= 1),
    PRIMARY KEY (bucket, window_start)
  )"
        ),
        "CREATE INDEX oaath_write_budget_window_v1 ON oaath_write_budget_v1 (window_start)"
            .to_owned(),
        "CREATE TABLE oaath_revocation_v1 (
    grant_id text PRIMARY KEY
      REFERENCES oaath_relay_authorization_request_v1 (request_id),
    record_version text NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    record text NOT NULL
  )"
        .to_owned(),
        format!(
            "CREATE TABLE oaath_pending_grant_v1 (
    request_id text PRIMARY KEY
      REFERENCES oaath_relay_authorization_request_v1 (request_id),
    record_version text NOT NULL,
    account_id text NOT NULL REFERENCES oaath_account_v1 (account_id),
    member_signer_id text NOT NULL REFERENCES oaath_signer_v1 (signer_id),
    artifact_id text NOT NULL UNIQUE,
    code_ref text NOT NULL,
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    expires_at bigint NOT NULL CHECK (expires_at > created_at AND expires_at <= {max}),
    outcome text CHECK (outcome IN ('approved', 'rejected')),
    decided_at bigint CHECK (decided_at >= 0 AND decided_at <= {max}),
    CHECK ((outcome IS NULL) = (decided_at IS NULL))
  )"
        ),
        "CREATE INDEX oaath_pending_grant_account_v1 ON oaath_pending_grant_v1 (account_id)"
            .to_owned(),
        format!(
            "CREATE TABLE oaath_policy_template_v1 (
    template_id text PRIMARY KEY,
    record_version text NOT NULL,
    account_id text NOT NULL REFERENCES oaath_account_v1 (account_id),
    name text NOT NULL,
    policy text NOT NULL,
    lifetime_seconds bigint NOT NULL CHECK (lifetime_seconds > 0 AND lifetime_seconds <= {max}),
    created_at bigint NOT NULL CHECK (created_at >= 0 AND created_at <= {max}),
    updated_at bigint NOT NULL CHECK (updated_at >= created_at AND updated_at <= {max})
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

const ACCOUNT_FIELDS: [(&str, &str, bool); 9] = [
    ("version", "account_version", false),
    ("accountId", "account_id", false),
    ("address", "address", false),
    ("rootSignerId", "root_signer_id", false),
    ("accountIndex", "account_index", true),
    ("creationKey", "creation_key", false),
    ("ownerValidator", "owner_validator", false),
    ("profile", "profile", false),
    ("createdAt", "account_created_at", true),
];

const MEMBERSHIP_FIELDS: [(&str, &str, bool); 10] = [
    ("version", "membership_version", false),
    ("accountId", "account_id", false),
    ("signerId", "signer_id", false),
    ("role", "role", false),
    ("requestId", "request_id", false),
    ("linkId", "link_id", false),
    ("createdAt", "membership_created_at", true),
    ("status", "status", false),
    ("suspendedAt", "suspended_at", true),
    ("restoredAt", "restored_at", true),
];

const SIGNER_FIELDS: [(&str, &str, bool); 5] = [
    ("version", "signer_version", false),
    ("signerId", "signer_id", false),
    ("profileHash", "profile_hash", false),
    ("profile", "profile", false),
    ("createdAt", "signer_created_at", true),
];

const TEMPLATE_COLUMNS: &str = "template_id, record_version, account_id, name, policy, lifetime_seconds, created_at, updated_at";

fn template_record(row: &PgRow) -> RelayResult<PolicyTemplateRecord> {
    PolicyTemplateRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("templateId", "template_id", false),
            ("accountId", "account_id", false),
            ("name", "name", false),
            ("policy", "policy", false),
            ("lifetimeSeconds", "lifetime_seconds", true),
            ("createdAt", "created_at", true),
            ("updatedAt", "updated_at", true),
        ],
    )?)
}

/// The record text owns the fact; its key columns must agree with it.
fn revocation_record(row: &PgRow) -> RelayResult<RevocationRecord> {
    let unreadable = |_| RelayErrorCode::RecordUnreadable;
    let text: String = row.try_get("record").map_err(unreadable)?;
    let grant_id: String = row.try_get("grant_id").map_err(unreadable)?;
    let version: String = row.try_get("record_version").map_err(unreadable)?;
    let revision: i64 = row.try_get("revision").map_err(unreadable)?;
    let record =
        RevocationRecord::parse(&parse_json(&text).map_err(|_| RelayErrorCode::RecordUnreadable)?)?;
    if record.grant_id != grant_id
        || record.version != version
        || i64::try_from(record.revision).ok() != Some(revision)
    {
        return Err(RelayErrorCode::RecordUnreadable);
    }
    Ok(record)
}

const PENDING_COLUMNS: &str = "request_id, record_version, account_id, member_signer_id, \
     artifact_id, code_ref, created_at, expires_at, outcome, decided_at";

fn pending_record(row: &PgRow) -> RelayResult<PendingGrantRecord> {
    PendingGrantRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("requestId", "request_id", false),
            ("accountId", "account_id", false),
            ("memberSignerId", "member_signer_id", false),
            ("artifactId", "artifact_id", false),
            ("codeRef", "code_ref", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
            ("outcome", "outcome", false),
            ("decidedAt", "decided_at", true),
        ],
    )?)
}

const LINK_COLUMNS: &str = "link_id, record_version, account_id, signer_id, label, created_at, \
     expires_at, outcome, decided_at, approval_signature, grant_id, removed_at";

fn link_record(row: &PgRow) -> RelayResult<LinkRequestRecord> {
    LinkRequestRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("linkId", "link_id", false),
            ("accountId", "account_id", false),
            ("signerId", "signer_id", false),
            ("label", "label", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
            ("outcome", "outcome", false),
            ("decidedAt", "decided_at", true),
            ("approvalSignature", "approval_signature", false),
            ("grantId", "grant_id", false),
            ("removedAt", "removed_at", true),
        ],
    )?)
}

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
            ("revocationDelivery", "revocation_delivery", false),
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
            ("authorizationDetails", "authorization_details", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
        ],
    )?)
}

fn access_token_record(row: &PgRow) -> RelayResult<AccessTokenRecord> {
    AccessTokenRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("tokenHash", "token_hash", false),
            ("clientId", "client_id", false),
            ("requestId", "request_id", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
            ("revokedAt", "revoked_at", true),
        ],
    )?)
}

fn challenge_record(row: &PgRow) -> RelayResult<PortalChallengeRecord> {
    PortalChallengeRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("nonce", "nonce", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
            ("consumedAt", "consumed_at", true),
        ],
    )?)
}

fn session_record(row: &PgRow) -> RelayResult<PortalSessionRecord> {
    PortalSessionRecord::parse(&columns(
        row,
        &[
            ("version", "record_version", false),
            ("tokenHash", "token_hash", false),
            ("signerId", "signer_id", false),
            ("createdAt", "created_at", true),
            ("expiresAt", "expires_at", true),
            ("signedOutAt", "signed_out_at", true),
        ],
    )?)
}

const ACCOUNT_COLUMNS: &str = "record_version AS account_version, account_id, address, \
     root_signer_id, account_index, creation_key, owner_validator, profile, \
     created_at AS account_created_at";

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
            "SELECT {REQUEST_COLUMNS} FROM oaath_relay_authorization_request_v1 \
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
            "INSERT INTO oaath_relay_authorization_request_v1 ({REQUEST_COLUMNS}) \
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
                 FROM oaath_relay_authorization_decision_v1 WHERE request_id = $1 FOR UPDATE",
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
                "INSERT INTO oaath_relay_authorization_decision_v1 (\
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

    async fn lock_signer_by_authenticator(
        &mut self,
        authenticator_id_hash: &str,
    ) -> RelayResult<Option<SignerRecord>> {
        let signer = self
            .first(
                sqlx::query(
                    "SELECT signer_id, record_version, profile_hash, profile, created_at \
                     FROM oaath_signer_v1 WHERE authenticator_id_hash = $1 FOR UPDATE",
                )
                .bind(authenticator_id_hash),
                signer_record,
            )
            .await?;
        // The index column is a copy; the stored profile owns the fact.
        if let Some(signer) = &signer
            && signer.authenticator_id_hash()?.as_deref() != Some(authenticator_id_hash)
        {
            return Err(RelayErrorCode::RecordUnreadable);
        }
        Ok(signer)
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
             account.creation_key, account.owner_validator, account.profile, \
             account.created_at AS account_created_at, \
             membership.record_version AS membership_version, membership.signer_id, \
             membership.role, membership.request_id, membership.link_id, \
             membership.created_at AS membership_created_at, membership.status, \
             membership.suspended_at, membership.restored_at \
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
                 creation_key, owner_validator, profile, created_at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 \
                 WHERE EXISTS (SELECT 1 FROM oaath_signer_v1 WHERE signer_id = $4) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.account_id)
            .bind(record.version)
            .bind(&record.address)
            .bind(&record.root_signer_id)
            .bind(record.account_index.map(bigint))
            .bind(&record.creation_key)
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
                 account_id, signer_id, record_version, role, request_id, link_id, created_at, \
                 status, suspended_at, restored_at\
                 ) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 \
                 WHERE EXISTS (SELECT 1 FROM oaath_account_v1 WHERE account_id = $1) \
                 AND EXISTS (SELECT 1 FROM oaath_signer_v1 WHERE signer_id = $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.account_id)
            .bind(&record.signer_id)
            .bind(record.version)
            .bind(record.role.as_str())
            .bind(&record.request_id)
            .bind(&record.link_id)
            .bind(bigint(record.created_at))
            .bind(record.status.as_str())
            .bind(record.suspended_at.map(bigint))
            .bind(record.restored_at.map(bigint)),
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

    async fn lock_account_by_creation_key(
        &mut self,
        root_signer_id: &str,
        creation_key: &str,
    ) -> RelayResult<Option<AccountRecord>> {
        let sql = format!(
            "SELECT {ACCOUNT_COLUMNS} FROM oaath_account_v1 \
             WHERE root_signer_id = $1 AND creation_key = $2 FOR UPDATE"
        );
        self.first(
            sqlx::query(&sql).bind(root_signer_id).bind(creation_key),
            |row| AccountRecord::parse(&columns(row, &ACCOUNT_FIELDS)?),
        )
        .await
    }

    async fn lock_account_by_address(
        &mut self,
        address: &str,
    ) -> RelayResult<Option<AccountRecord>> {
        let sql =
            format!("SELECT {ACCOUNT_COLUMNS} FROM oaath_account_v1 WHERE address = $1 FOR UPDATE");
        self.first(sqlx::query(&sql).bind(address), |row| {
            AccountRecord::parse(&columns(row, &ACCOUNT_FIELDS)?)
        })
        .await
    }

    async fn list_account_signers(
        &mut self,
        account_id: &str,
    ) -> RelayResult<Vec<(SignerRecord, AccountSignerRecord)>> {
        let rows = sqlx::query(
            "SELECT signer.record_version AS signer_version, signer.signer_id, \
             signer.profile_hash, signer.profile, signer.created_at AS signer_created_at, \
             membership.record_version AS membership_version, membership.account_id, \
             membership.role, membership.request_id, membership.link_id, \
             membership.created_at AS membership_created_at, membership.status, \
             membership.suspended_at, membership.restored_at \
             FROM oaath_account_signer_v1 AS membership \
             JOIN oaath_signer_v1 AS signer ON signer.signer_id = membership.signer_id \
             WHERE membership.account_id = $1 \
             ORDER BY membership.role <> 'root', membership.created_at, signer.signer_id COLLATE \"C\" FOR UPDATE",
        )
        .bind(account_id)
        .fetch_all(&mut *self.transaction)
        .await
        .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        rows.iter()
            .map(|row| {
                Ok((
                    SignerRecord::parse(&columns(row, &SIGNER_FIELDS)?)?,
                    AccountSignerRecord::parse(&columns(row, &MEMBERSHIP_FIELDS)?)?,
                ))
            })
            .collect()
    }

    async fn delete_account_signers(
        &mut self,
        account_id: &str,
        signer_id: &str,
    ) -> RelayResult<bool> {
        // One signer may hold several permission memberships (a link and grants).
        let result = sqlx::query(
            "DELETE FROM oaath_account_signer_v1 \
             WHERE account_id = $1 AND signer_id = $2 AND role = 'permission'",
        )
        .bind(account_id)
        .bind(signer_id)
        .execute(&mut *self.transaction)
        .await
        .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        Ok(result.rows_affected() > 0)
    }

    async fn set_account_signer_status(
        &mut self,
        account_id: &str,
        signer_id: &str,
        status: MembershipStatus,
        at: u64,
    ) -> RelayResult<bool> {
        // Guarded on the current status, so a repeated move changes nothing.
        let sql = match status {
            MembershipStatus::Suspended => {
                "UPDATE oaath_account_signer_v1 SET status = 'suspended', suspended_at = $3 \
                 WHERE account_id = $1 AND signer_id = $2 AND role = 'permission' \
                 AND status = 'active'"
            }
            MembershipStatus::Active => {
                "UPDATE oaath_account_signer_v1 SET status = 'active', restored_at = $3 \
                 WHERE account_id = $1 AND signer_id = $2 AND role = 'permission' \
                 AND status = 'suspended'"
            }
        };
        let result = sqlx::query(sql)
            .bind(account_id)
            .bind(signer_id)
            .bind(bigint(at))
            .execute(&mut *self.transaction)
            .await
            .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        Ok(result.rows_affected() > 0)
    }

    async fn insert_account_import(&mut self, record: &AccountImportRecord) -> RelayResult<bool> {
        // An unknown account inserts nothing instead of aborting.
        self.applied(
            sqlx::query(
                "INSERT INTO oaath_account_import_v1 (\
                 account_id, record_version, inventory_fingerprint, issued_at, nonce, signature, \
                 created_at) SELECT $1, $2, $3, $4, $5, $6, $7 \
                 WHERE EXISTS (SELECT 1 FROM oaath_account_v1 WHERE account_id = $1) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.account_id)
            .bind(record.version)
            .bind(&record.inventory_fingerprint)
            .bind(bigint(record.issued_at))
            .bind(&record.nonce)
            .bind(&record.signature)
            .bind(bigint(record.created_at)),
        )
        .await
    }

    async fn lock_account_import(
        &mut self,
        account_id: &str,
    ) -> RelayResult<Option<AccountImportRecord>> {
        self.first(
            sqlx::query(
                "SELECT account_id, record_version, inventory_fingerprint, issued_at, nonce, \
                 signature, created_at FROM oaath_account_import_v1 \
                 WHERE account_id = $1 FOR UPDATE",
            )
            .bind(account_id),
            |row| {
                AccountImportRecord::parse(&columns(
                    row,
                    &[
                        ("version", "record_version", false),
                        ("accountId", "account_id", false),
                        ("inventoryFingerprint", "inventory_fingerprint", false),
                        ("issuedAt", "issued_at", true),
                        ("nonce", "nonce", false),
                        ("signature", "signature", false),
                        ("createdAt", "created_at", true),
                    ],
                )?)
            },
        )
        .await
    }

    async fn spend_write_budget(&mut self, bucket: &str, window_start: u64) -> RelayResult<u64> {
        sqlx::query("DELETE FROM oaath_write_budget_v1 WHERE window_start < $1")
            .bind(bigint(window_start))
            .execute(&mut *self.transaction)
            .await
            .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        let count: i64 = sqlx::query_scalar(
            "INSERT INTO oaath_write_budget_v1 (bucket, window_start, count) VALUES ($1, $2, 1) \
             ON CONFLICT (bucket, window_start) \
             DO UPDATE SET count = oaath_write_budget_v1.count + 1 RETURNING count",
        )
        .bind(bucket)
        .bind(bigint(window_start))
        .fetch_one(&mut *self.transaction)
        .await
        .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        u64::try_from(count).map_err(|_| RelayErrorCode::RecordUnreadable)
    }

    async fn lock_revocation(&mut self, grant_id: &str) -> RelayResult<Option<RevocationRecord>> {
        self.first(
            sqlx::query(
                "SELECT grant_id, record_version, revision, record FROM oaath_revocation_v1 \
                 WHERE grant_id = $1 FOR UPDATE",
            )
            .bind(grant_id),
            revocation_record,
        )
        .await
    }

    async fn save_revocation(&mut self, record: &RevocationRecord) -> RelayResult<bool> {
        let text = serde_json::to_string(record).map_err(|_| RelayErrorCode::Internal)?;
        let query = if record.revision == 1 {
            sqlx::query(
                "INSERT INTO oaath_revocation_v1 (grant_id, record_version, revision, record) \
                 SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM \
                 oaath_relay_authorization_request_v1 WHERE request_id = $1) \
                 ON CONFLICT DO NOTHING",
            )
        } else {
            sqlx::query(
                "UPDATE oaath_revocation_v1 SET record_version = $2, revision = $3, record = $4 \
                 WHERE grant_id = $1 AND revision = $3 - 1",
            )
        };
        self.applied(
            query
                .bind(&record.grant_id)
                .bind(record.version)
                .bind(bigint(record.revision))
                .bind(text),
        )
        .await
    }

    async fn lock_pending_grant(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<PendingGrantRecord>> {
        let sql = format!(
            "SELECT {PENDING_COLUMNS} FROM oaath_pending_grant_v1 WHERE request_id = $1 FOR UPDATE"
        );
        self.first(sqlx::query(&sql).bind(request_id), pending_record)
            .await
    }

    async fn insert_pending_grant(&mut self, record: &PendingGrantRecord) -> RelayResult<bool> {
        // An unknown account, member or request inserts nothing instead of aborting.
        let sql = format!(
            "INSERT INTO oaath_pending_grant_v1 ({PENDING_COLUMNS}) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL \
             WHERE EXISTS (SELECT 1 FROM oaath_account_v1 WHERE account_id = $3) \
             AND EXISTS (SELECT 1 FROM oaath_signer_v1 WHERE signer_id = $4) \
             AND EXISTS (SELECT 1 FROM oaath_relay_authorization_request_v1 \
             WHERE request_id = $1) ON CONFLICT DO NOTHING"
        );
        self.applied(
            sqlx::query(&sql)
                .bind(&record.request_id)
                .bind(record.version)
                .bind(&record.account_id)
                .bind(&record.member_signer_id)
                .bind(&record.artifact_id)
                .bind(&record.code_ref)
                .bind(bigint(record.created_at))
                .bind(bigint(record.expires_at)),
        )
        .await
    }

    async fn decide_pending_grant(
        &mut self,
        request_id: &str,
        outcome: PendingOutcome,
        decided_at: u64,
    ) -> RelayResult<bool> {
        let outcome = match outcome {
            PendingOutcome::Approved => "approved",
            PendingOutcome::Rejected => "rejected",
        };
        self.applied(
            sqlx::query(
                "UPDATE oaath_pending_grant_v1 SET outcome = $2, decided_at = $3 \
                 WHERE request_id = $1 AND outcome IS NULL",
            )
            .bind(request_id)
            .bind(outcome)
            .bind(bigint(decided_at)),
        )
        .await
    }

    async fn list_pending_grants(
        &mut self,
        account_id: &str,
    ) -> RelayResult<Vec<PendingGrantRecord>> {
        let sql = format!(
            "SELECT {PENDING_COLUMNS} FROM oaath_pending_grant_v1 WHERE account_id = $1 \
             ORDER BY created_at, request_id COLLATE \"C\" FOR UPDATE"
        );
        let rows = sqlx::query(&sql)
            .bind(account_id)
            .fetch_all(&mut *self.transaction)
            .await
            .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        rows.iter().map(pending_record).collect()
    }

    async fn lock_link_request(&mut self, link_id: &str) -> RelayResult<Option<LinkRequestRecord>> {
        let sql = format!(
            "SELECT {LINK_COLUMNS} FROM oaath_link_request_v1 WHERE link_id = $1 FOR UPDATE"
        );
        self.first(sqlx::query(&sql).bind(link_id), link_record)
            .await
    }

    async fn insert_link_request(&mut self, record: &LinkRequestRecord) -> RelayResult<bool> {
        // An unknown account or signer inserts nothing instead of aborting.
        let sql = format!(
            "INSERT INTO oaath_link_request_v1 ({LINK_COLUMNS}) \
             SELECT $1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, NULL, NULL \
             WHERE EXISTS (SELECT 1 FROM oaath_account_v1 WHERE account_id = $3) \
             AND EXISTS (SELECT 1 FROM oaath_signer_v1 WHERE signer_id = $4) \
             ON CONFLICT DO NOTHING"
        );
        self.applied(
            sqlx::query(&sql)
                .bind(&record.link_id)
                .bind(record.version)
                .bind(&record.account_id)
                .bind(&record.signer_id)
                .bind(&record.label)
                .bind(bigint(record.created_at))
                .bind(bigint(record.expires_at)),
        )
        .await
    }

    async fn decide_link_request(
        &mut self,
        link_id: &str,
        outcome: LinkOutcome,
        approval_signature: Option<&str>,
        grant_id: Option<&str>,
        decided_at: u64,
    ) -> RelayResult<bool> {
        let outcome = match outcome {
            LinkOutcome::Approved => "approved",
            LinkOutcome::Rejected => "rejected",
        };
        // One-shot: the guard makes a second decision affect zero rows.
        self.applied(
            sqlx::query(
                "UPDATE oaath_link_request_v1 \
                 SET outcome = $2, approval_signature = $3, grant_id = $4, decided_at = $5 \
                 WHERE link_id = $1 AND outcome IS NULL",
            )
            .bind(link_id)
            .bind(outcome)
            .bind(approval_signature)
            .bind(grant_id)
            .bind(bigint(decided_at)),
        )
        .await
    }

    async fn list_policy_templates(
        &mut self,
        account_id: &str,
    ) -> RelayResult<Vec<PolicyTemplateRecord>> {
        let sql = format!(
            "SELECT {TEMPLATE_COLUMNS} FROM oaath_policy_template_v1 WHERE account_id = $1 \
             ORDER BY created_at, template_id COLLATE \"C\""
        );
        let rows = sqlx::query(&sql)
            .bind(account_id)
            .fetch_all(&mut *self.transaction)
            .await
            .map_err(|_| RelayErrorCode::StoreUnavailable)?;
        rows.iter().map(template_record).collect()
    }

    async fn lock_policy_template(
        &mut self,
        template_id: &str,
    ) -> RelayResult<Option<PolicyTemplateRecord>> {
        let sql = format!(
            "SELECT {TEMPLATE_COLUMNS} FROM oaath_policy_template_v1 \
             WHERE template_id = $1 FOR UPDATE"
        );
        self.first(sqlx::query(&sql).bind(template_id), template_record)
            .await
    }

    async fn insert_policy_template(&mut self, record: &PolicyTemplateRecord) -> RelayResult<bool> {
        // An unknown account inserts nothing instead of aborting.
        let sql = format!(
            "INSERT INTO oaath_policy_template_v1 ({TEMPLATE_COLUMNS}) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8 \
             WHERE EXISTS (SELECT 1 FROM oaath_account_v1 WHERE account_id = $3) \
             ON CONFLICT DO NOTHING"
        );
        self.applied(
            sqlx::query(&sql)
                .bind(&record.template_id)
                .bind(record.version)
                .bind(&record.account_id)
                .bind(&record.name)
                .bind(&record.policy)
                .bind(bigint(record.lifetime_seconds))
                .bind(bigint(record.created_at))
                .bind(bigint(record.updated_at)),
        )
        .await
    }

    async fn update_policy_template(&mut self, record: &PolicyTemplateRecord) -> RelayResult<bool> {
        self.applied(
            sqlx::query(
                "UPDATE oaath_policy_template_v1 \
                 SET name = $3, policy = $4, lifetime_seconds = $5, updated_at = $6 \
                 WHERE template_id = $1 AND account_id = $2",
            )
            .bind(&record.template_id)
            .bind(&record.account_id)
            .bind(&record.name)
            .bind(&record.policy)
            .bind(bigint(record.lifetime_seconds))
            .bind(bigint(record.updated_at)),
        )
        .await
    }

    async fn delete_policy_template(&mut self, template_id: &str) -> RelayResult<bool> {
        self.applied(
            sqlx::query("DELETE FROM oaath_policy_template_v1 WHERE template_id = $1")
                .bind(template_id),
        )
        .await
    }

    async fn remove_link_request(&mut self, link_id: &str, removed_at: u64) -> RelayResult<bool> {
        self.applied(
            sqlx::query(
                "UPDATE oaath_link_request_v1 SET removed_at = $2 \
                 WHERE link_id = $1 AND outcome = 'approved' AND removed_at IS NULL",
            )
            .bind(link_id)
            .bind(bigint(removed_at)),
        )
        .await
    }

    async fn lock_oauth_client(
        &mut self,
        client_id: &str,
    ) -> RelayResult<Option<OAuthClientRecord>> {
        self.first(
            sqlx::query(
                "SELECT client_id, record_version, client_name, redirect_uris, \
                 revocation_delivery, created_at FROM oauth_client_v1 WHERE client_id = $1 FOR UPDATE",
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
                 client_id, record_version, client_name, redirect_uris, revocation_delivery, \
                 created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            )
            .bind(&record.client_id)
            .bind(record.version)
            .bind(&record.client_name)
            .bind(uris)
            .bind(match record.revocation_delivery {
                RevocationDelivery::Relay => "relay",
                RevocationDelivery::Dapp => "dapp",
            })
            .bind(bigint(record.created_at)),
        )
        .await
    }

    async fn lock_par(&mut self, par_id: &str) -> RelayResult<Option<ParRecord>> {
        self.first(
            sqlx::query(
                "SELECT par_id, record_version, client_id, redirect_uri, code_challenge, state, \
                 nonce, scope, authorization_details, created_at, expires_at FROM oauth_par_v1 \
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
                 scope, authorization_details, created_at, expires_at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11 \
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
            .bind(&record.authorization_details)
            .bind(bigint(record.created_at))
            .bind(bigint(record.expires_at)),
        )
        .await
    }

    async fn lock_access_token(
        &mut self,
        token_hash: &str,
    ) -> RelayResult<Option<AccessTokenRecord>> {
        self.first(
            sqlx::query(
                "SELECT token_hash, record_version, client_id, request_id, created_at, \
                 expires_at, revoked_at FROM oauth_access_token_v1 \
                 WHERE token_hash = $1 FOR UPDATE",
            )
            .bind(token_hash),
            access_token_record,
        )
        .await
    }

    async fn insert_access_token(&mut self, record: &AccessTokenRecord) -> RelayResult<bool> {
        // An unknown client or request inserts nothing instead of aborting.
        self.applied(
            sqlx::query(
                "INSERT INTO oauth_access_token_v1 (\
                 token_hash, record_version, client_id, request_id, created_at, expires_at, \
                 revoked_at) SELECT $1, $2, $3, $4, $5, $6, NULL \
                 WHERE EXISTS (SELECT 1 FROM oauth_client_v1 WHERE client_id = $3) \
                 AND EXISTS (SELECT 1 FROM oaath_relay_authorization_request_v1 \
                 WHERE request_id = $4) ON CONFLICT DO NOTHING",
            )
            .bind(&record.token_hash)
            .bind(record.version)
            .bind(&record.client_id)
            .bind(&record.request_id)
            .bind(bigint(record.created_at))
            .bind(bigint(record.expires_at)),
        )
        .await
    }

    async fn revoke_access_token(
        &mut self,
        token_hash: &str,
        revoked_at: u64,
    ) -> RelayResult<bool> {
        // One-shot: the guard makes a second revocation affect zero rows.
        self.applied(
            sqlx::query(
                "UPDATE oauth_access_token_v1 SET revoked_at = $2 \
                 WHERE token_hash = $1 AND revoked_at IS NULL",
            )
            .bind(token_hash)
            .bind(bigint(revoked_at)),
        )
        .await
    }

    async fn lock_portal_challenge(
        &mut self,
        nonce: &str,
    ) -> RelayResult<Option<PortalChallengeRecord>> {
        self.first(
            sqlx::query(
                "SELECT nonce, record_version, created_at, expires_at, consumed_at \
                 FROM oaath_portal_challenge_v1 WHERE nonce = $1 FOR UPDATE",
            )
            .bind(nonce),
            challenge_record,
        )
        .await
    }

    async fn insert_portal_challenge(
        &mut self,
        record: &PortalChallengeRecord,
    ) -> RelayResult<bool> {
        self.applied(
            sqlx::query(
                "INSERT INTO oaath_portal_challenge_v1 (\
                 nonce, record_version, created_at, expires_at, consumed_at) \
                 VALUES ($1, $2, $3, $4, NULL) ON CONFLICT DO NOTHING",
            )
            .bind(&record.nonce)
            .bind(record.version)
            .bind(bigint(record.created_at))
            .bind(bigint(record.expires_at)),
        )
        .await
    }

    async fn consume_portal_challenge(
        &mut self,
        nonce: &str,
        consumed_at: u64,
    ) -> RelayResult<bool> {
        self.applied(
            sqlx::query(
                "UPDATE oaath_portal_challenge_v1 SET consumed_at = $2 \
                 WHERE nonce = $1 AND consumed_at IS NULL",
            )
            .bind(nonce)
            .bind(bigint(consumed_at)),
        )
        .await
    }

    async fn lock_portal_session(
        &mut self,
        token_hash: &str,
    ) -> RelayResult<Option<PortalSessionRecord>> {
        self.first(
            sqlx::query(
                "SELECT token_hash, record_version, signer_id, created_at, expires_at, \
                 signed_out_at FROM oaath_portal_session_v1 WHERE token_hash = $1 FOR UPDATE",
            )
            .bind(token_hash),
            session_record,
        )
        .await
    }

    async fn insert_portal_session(&mut self, record: &PortalSessionRecord) -> RelayResult<bool> {
        // An unknown signer inserts nothing instead of aborting.
        self.applied(
            sqlx::query(
                "INSERT INTO oaath_portal_session_v1 (\
                 token_hash, record_version, signer_id, created_at, expires_at, signed_out_at) \
                 SELECT $1, $2, $3, $4, $5, NULL \
                 WHERE EXISTS (SELECT 1 FROM oaath_signer_v1 WHERE signer_id = $3) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.token_hash)
            .bind(record.version)
            .bind(&record.signer_id)
            .bind(bigint(record.created_at))
            .bind(bigint(record.expires_at)),
        )
        .await
    }

    async fn end_portal_session(
        &mut self,
        token_hash: &str,
        signed_out_at: u64,
    ) -> RelayResult<bool> {
        self.applied(
            sqlx::query(
                "UPDATE oaath_portal_session_v1 SET signed_out_at = $2 \
                 WHERE token_hash = $1 AND signed_out_at IS NULL",
            )
            .bind(token_hash)
            .bind(bigint(signed_out_at)),
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
