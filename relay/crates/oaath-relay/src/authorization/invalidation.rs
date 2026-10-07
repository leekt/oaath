//! Durable capability invalidation.
//!
//! ```text
//! state and owner        the invalidation record owns "this service no longer
//!                        acts for the Grant"; it never mutates
//! transitions            absent -> invalidated, once per Grant
//! retry positively safe? yes: a replay answers the stored record, so one Grant
//!                        has exactly one invalidation time and evidence hash
//! crash/reload           insert and read decide under the Grant's row lock
//! ```
//!
//! Chain execution routes enforce the record in a later stage. Consuming the
//! on-chain install nonce stays the chain-local revocation's separate evidence.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::authentication::RelayCaller;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::records::{CAPABILITY_INVALIDATION_RECORD_VERSION, CapabilityInvalidationRecord};
use crate::store::{RelayStore, RelayTransaction, settle};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvalidationEvidence {
    pub evidence_hash: String,
    /// Protocol-facing, so it speaks the protocol's seconds domain.
    pub invalidated_at: u64,
}

pub async fn record_capability_invalidation(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    caller: &RelayCaller,
    grant_id: &str,
    capability_hash: &str,
) -> RelayResult<InvalidationEvidence> {
    let mut transaction = store.begin().await?;
    let result = invalidate(&mut *transaction, clock, caller, grant_id, capability_hash).await;
    let record = settle(transaction, result).await?;
    Ok(InvalidationEvidence {
        evidence_hash: evidence_hash(&record),
        invalidated_at: record.invalidated_at / 1_000,
    })
}

async fn invalidate(
    transaction: &mut dyn RelayTransaction,
    clock: &dyn RelayClock,
    caller: &RelayCaller,
    grant_id: &str,
    capability_hash: &str,
) -> RelayResult<CapabilityInvalidationRecord> {
    if let Some(existing) = transaction.lock_capability_invalidation(grant_id).await? {
        // Reported as absence: not an existence oracle for another client's Grant.
        if existing.client_id != caller.client_id {
            return Err(RelayErrorCode::NotFound);
        }
        return Ok(existing);
    }
    let created = CapabilityInvalidationRecord {
        version: CAPABILITY_INVALIDATION_RECORD_VERSION,
        grant_id: grant_id.to_owned(),
        client_id: caller.client_id.clone(),
        capability_hash: capability_hash.to_owned(),
        invalidated_at: relay_now(clock)?,
    };
    if !transaction.insert_capability_invalidation(&created).await? {
        return Err(RelayErrorCode::Internal);
    }
    Ok(created)
}

pub fn evidence_hash(record: &CapabilityInvalidationRecord) -> String {
    let digest = Sha256::digest(
        format!(
            "oaath-relay-invalidation:v1:{}:{}:{}:{}",
            record.client_id, record.grant_id, record.capability_hash, record.invalidated_at
        )
        .as_bytes(),
    );
    format!("0x{}", hex::encode(digest))
}
