//! One-time encrypted artifact release.
//!
//! ```text
//! state and owner        the artifact record's `claimedAt` owns "released"
//! transitions            sealed -> claimed, exactly once
//! terminal               claimed; a second claim fails closed
//! retry positively safe? no. The claim commits before the KMS is asked to
//!                        decrypt, so a decrypt or transport failure burns the
//!                        artifact instead of risking a second release
//! crash/reload           a crash before commit leaves the artifact claimable
//! ```

use serde::Serialize;

use crate::authentication::RelayCaller;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::kms::{RelayKms, open_artifact};
use crate::records::EncryptedArtifactRecord;
use crate::store::{RelayStore, RelayTransaction, settle};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimedEncryptedArtifact {
    pub request_id: String,
    pub artifact: String,
}

pub async fn claim_encrypted_artifact(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    caller: &RelayCaller,
    artifact_id: &str,
) -> RelayResult<ClaimedEncryptedArtifact> {
    let claimed_at = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = claim(&mut *transaction, caller, artifact_id, claimed_at).await;
    let claimed = settle(transaction, result).await?;
    Ok(ClaimedEncryptedArtifact {
        artifact: open_artifact(kms, &claimed.ciphertext_ref).await?,
        request_id: claimed.request_id,
    })
}

async fn claim(
    transaction: &mut dyn RelayTransaction,
    caller: &RelayCaller,
    artifact_id: &str,
    claimed_at: u64,
) -> RelayResult<EncryptedArtifactRecord> {
    // An artifact bound to another client is indistinguishable from an unknown one.
    let record = transaction
        .lock_encrypted_artifact(artifact_id)
        .await?
        .filter(|record| record.client_id == caller.client_id)
        .ok_or(RelayErrorCode::NotFound)?;
    if record.claimed_at.is_some() {
        return Err(RelayErrorCode::ArtifactAlreadyClaimed);
    }
    if !transaction
        .claim_encrypted_artifact(artifact_id, claimed_at)
        .await?
    {
        return Err(RelayErrorCode::StateAmbiguous);
    }
    Ok(record)
}
