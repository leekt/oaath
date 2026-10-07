//! In-memory relay store implementing the same transaction contract as
//! PostgreSQL. It lives only as long as the process: use it for local
//! development and tests, never for a deployment that must survive a restart.
//!
//! One process-wide writer lock stands in for row locks. It is strictly
//! stronger than `SELECT ... FOR UPDATE`, so one-shot semantics are identical.
//! Rows are kept as JSON and re-validated on every read, exactly as the SQL
//! store validates rows.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::{RelayStore, RelayTransaction};
use crate::error::{RelayErrorCode, RelayResult};
use crate::records::{
    AuthorizationCodeRecord, AuthorizationDecisionRecord, AuthorizationRequestRecord,
    CapabilityInvalidationRecord, EncryptedArtifactRecord, to_value,
};

#[derive(Clone, Default)]
struct Tables {
    requests: HashMap<String, Value>,
    decisions: HashMap<String, Value>,
    codes: HashMap<String, Value>,
    artifacts: HashMap<String, Value>,
    invalidations: HashMap<String, Value>,
}

#[derive(Default)]
pub struct MemoryRelayStore {
    committed: Arc<Mutex<Tables>>,
    closed: AtomicBool,
}

impl MemoryRelayStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RelayStore for MemoryRelayStore {
    async fn begin(&self) -> RelayResult<Box<dyn RelayTransaction>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(RelayErrorCode::StoreUnavailable);
        }
        let guard = self.committed.clone().lock_owned().await;
        let staged = guard.clone();
        Ok(Box::new(MemoryTransaction { guard, staged }))
    }

    async fn close(&self) -> RelayResult<()> {
        self.closed.store(true, Ordering::SeqCst);
        *self.committed.lock().await = Tables::default();
        Ok(())
    }
}

struct MemoryTransaction {
    guard: OwnedMutexGuard<Tables>,
    staged: Tables,
}

fn insert(table: &mut HashMap<String, Value>, key: &str, record: Value) -> bool {
    if table.contains_key(key) {
        return false;
    }
    table.insert(key.to_owned(), record);
    true
}

fn read<Record>(
    table: &HashMap<String, Value>,
    key: &str,
    parse: fn(&Value) -> RelayResult<Record>,
) -> RelayResult<Option<Record>> {
    table.get(key).map(parse).transpose()
}

fn artifact_by_request(
    tables: &Tables,
    request_id: &str,
) -> RelayResult<Option<EncryptedArtifactRecord>> {
    let mut found = None;
    for value in tables.artifacts.values() {
        let record = EncryptedArtifactRecord::parse(value)?;
        if record.request_id != request_id {
            continue;
        }
        if found.is_some() {
            return Err(RelayErrorCode::RecordUnreadable);
        }
        found = Some(record);
    }
    Ok(found)
}

#[async_trait]
impl RelayTransaction for MemoryTransaction {
    async fn lock_authorization_request(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<AuthorizationRequestRecord>> {
        read(
            &self.staged.requests,
            request_id,
            AuthorizationRequestRecord::parse,
        )
    }

    async fn insert_authorization_request(
        &mut self,
        record: &AuthorizationRequestRecord,
    ) -> RelayResult<bool> {
        Ok(insert(
            &mut self.staged.requests,
            &record.request_id,
            to_value(record),
        ))
    }

    async fn lock_authorization_decision(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<AuthorizationDecisionRecord>> {
        read(
            &self.staged.decisions,
            request_id,
            AuthorizationDecisionRecord::parse,
        )
    }

    async fn insert_authorization_decision(
        &mut self,
        record: &AuthorizationDecisionRecord,
    ) -> RelayResult<bool> {
        Ok(insert(
            &mut self.staged.decisions,
            &record.request_id,
            to_value(record),
        ))
    }

    async fn lock_authorization_code(
        &mut self,
        code_hash: &str,
    ) -> RelayResult<Option<AuthorizationCodeRecord>> {
        read(
            &self.staged.codes,
            code_hash,
            AuthorizationCodeRecord::parse,
        )
    }

    async fn insert_authorization_code(
        &mut self,
        record: &AuthorizationCodeRecord,
    ) -> RelayResult<bool> {
        // The SQL schema also keeps request_id and artifact_id unique.
        let duplicate = self.staged.codes.values().any(|stored| {
            stored["requestId"] == json!(record.request_id)
                || stored["artifactId"] == json!(record.artifact_id)
        });
        Ok(!duplicate && insert(&mut self.staged.codes, &record.code_hash, to_value(record)))
    }

    async fn consume_authorization_code(
        &mut self,
        code_hash: &str,
        consumed_at: u64,
    ) -> RelayResult<bool> {
        let Some(mut record) = read(
            &self.staged.codes,
            code_hash,
            AuthorizationCodeRecord::parse,
        )?
        else {
            return Ok(false);
        };
        if record.consumed_at.is_some() {
            return Ok(false);
        }
        record.consumed_at = Some(consumed_at);
        self.staged
            .codes
            .insert(code_hash.to_owned(), to_value(&record));
        Ok(true)
    }

    async fn lock_capability_invalidation(
        &mut self,
        grant_id: &str,
    ) -> RelayResult<Option<CapabilityInvalidationRecord>> {
        read(
            &self.staged.invalidations,
            grant_id,
            CapabilityInvalidationRecord::parse,
        )
    }

    async fn insert_capability_invalidation(
        &mut self,
        record: &CapabilityInvalidationRecord,
    ) -> RelayResult<bool> {
        Ok(insert(
            &mut self.staged.invalidations,
            &record.grant_id,
            to_value(record),
        ))
    }

    async fn lock_encrypted_artifact(
        &mut self,
        artifact_id: &str,
    ) -> RelayResult<Option<EncryptedArtifactRecord>> {
        read(
            &self.staged.artifacts,
            artifact_id,
            EncryptedArtifactRecord::parse,
        )
    }

    async fn lock_encrypted_artifact_by_request_id(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<EncryptedArtifactRecord>> {
        artifact_by_request(&self.staged, request_id)
    }

    async fn insert_encrypted_artifact(
        &mut self,
        record: &EncryptedArtifactRecord,
    ) -> RelayResult<bool> {
        if artifact_by_request(&self.staged, &record.request_id)?.is_some() {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.artifacts,
            &record.artifact_id,
            to_value(record),
        ))
    }

    async fn claim_encrypted_artifact(
        &mut self,
        artifact_id: &str,
        claimed_at: u64,
    ) -> RelayResult<bool> {
        let Some(mut record) = read(
            &self.staged.artifacts,
            artifact_id,
            EncryptedArtifactRecord::parse,
        )?
        else {
            return Ok(false);
        };
        if record.claimed_at.is_some() {
            return Ok(false);
        }
        record.claimed_at = Some(claimed_at);
        self.staged
            .artifacts
            .insert(artifact_id.to_owned(), to_value(&record));
        Ok(true)
    }

    async fn commit(self: Box<Self>) -> RelayResult<()> {
        let MemoryTransaction { mut guard, staged } = *self;
        *guard = staged;
        Ok(())
    }

    async fn rollback(self: Box<Self>) {}
}
