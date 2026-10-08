//! Authenticated OAuth app management. The client record owns its immutable signer binding.
//!
//! state/owner: unregistered -> registered with a session-derived owner -> metadata updated
//! persisted evidence: oauth-client-record/v2, ownerSignerId null only for open registration
//! resource: one client ID; ownership cannot transfer or be claimed afterward
//! retry: updates replace metadata; uncertain creation is resolved by listing, not auto-retrying
//! forbidden: unauthenticated access, foreign updates, claiming public clients, owner mutation
//! reload: list reads durable records; no in-memory authority; transaction owns partial cleanup

use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::oauth::{RegisteredClient, capture_client};
use crate::store::{RelayStore, settle};
use serde_json::{Map, Value, json};

pub async fn list(store: &dyn RelayStore, signer: &str) -> RelayResult<Value> {
    let mut tx = store.begin().await?;
    let result = tx.list_oauth_clients(signer).await;
    let clients: Vec<RegisteredClient> = settle(tx, result)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(json!({"clients": clients}))
}

pub async fn save(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    signer: &str,
    id: Option<&str>,
    body: &Map<String, Value>,
) -> RelayResult<RegisteredClient> {
    let mut proposed = capture_client(body, relay_now(clock)?).map_err(|error| error.code)?;
    let mut tx = store.begin().await?;
    let result = async {
        if let Some(id) = id {
            let current = tx
                .lock_oauth_client(id)
                .await?
                .ok_or(RelayErrorCode::NotFound)?;
            if current.owner_signer_id.as_deref() != Some(signer) {
                return Err(RelayErrorCode::NotFound);
            }
            proposed.client_id = current.client_id;
            proposed.created_at = current.created_at;
            proposed.owner_signer_id = current.owner_signer_id;
            if !tx.update_oauth_client(&proposed).await? {
                return Err(RelayErrorCode::NotFound);
            }
        } else {
            proposed.owner_signer_id = Some(signer.to_owned());
            if !tx.insert_oauth_client(&proposed).await? {
                return Err(RelayErrorCode::Internal);
            }
        }
        Ok(proposed.into())
    }
    .await;
    settle(tx, result).await
}
