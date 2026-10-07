//! One-time authorization code consume, for the OAuth token exchange.
//!
//! Consume:
//!
//! ```text
//! state and owner        the code record's `consumedAt` owns "used"
//! transitions            issued -> consumed, exactly once
//! terminal               consumed; a second consume fails closed
//! retry positively safe? no, in either direction: a released code is never
//!                        re-released, and an ambiguous commit is never retried
//! crash/reload           the guarded update and the release decide together in
//!                        one transaction under the code's row lock
//! ```
//!
//! A failed PKCE or redirect binding still burns the code (and voids its
//! artifact), so a stolen code cannot be brute-forced against the stored
//! challenge. An unknown code, another client's code, a wrong redirect URI, and
//! a wrong verifier all leave as the single `relay_code_invalid`.

use serde::Serialize;

use super::challenge::{sha256_base64url, verify_pkce_s256};
use crate::authentication::RelayCaller;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::store::{RelayStore, RelayTransaction, settle};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumedAuthorizationCode {
    pub request_id: String,
    /// One-time claim handle for the encrypted artifact.
    pub artifact_id: String,
}

pub struct ConsumeAuthorizationCode<'a> {
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub redirect_uri: &'a str,
}

enum ConsumeOutcome {
    Released(ConsumedAuthorizationCode),
    Burned,
}

pub async fn consume_authorization_code(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    caller: &RelayCaller,
    input: ConsumeAuthorizationCode<'_>,
) -> RelayResult<ConsumedAuthorizationCode> {
    let consumed_at = relay_now(clock)?;
    let code_hash = sha256_base64url(input.code);
    let mut transaction = store.begin().await?;
    let result = consume(&mut *transaction, caller, &input, &code_hash, consumed_at).await;
    // The burn is committed before the failure is reported.
    match settle(transaction, result).await? {
        ConsumeOutcome::Released(released) => Ok(released),
        ConsumeOutcome::Burned => Err(RelayErrorCode::CodeInvalid),
    }
}

async fn consume(
    transaction: &mut dyn RelayTransaction,
    caller: &RelayCaller,
    input: &ConsumeAuthorizationCode<'_>,
    code_hash: &str,
    consumed_at: u64,
) -> RelayResult<ConsumeOutcome> {
    // An unknown code and a code bound to another client are indistinguishable
    // from a code whose binding failed below.
    let record = transaction
        .lock_authorization_code(code_hash)
        .await?
        .filter(|record| record.client_id == caller.client_id)
        .ok_or(RelayErrorCode::CodeInvalid)?;
    if record.consumed_at.is_some() {
        return Err(RelayErrorCode::CodeAlreadyConsumed);
    }
    if consumed_at >= record.expires_at {
        // Already dead; nothing left to burn.
        return Err(RelayErrorCode::Expired);
    }
    let bound = record.redirect_uri == input.redirect_uri
        && verify_pkce_s256(input.code_verifier, &record.code_challenge);
    if !transaction
        .consume_authorization_code(code_hash, consumed_at)
        .await?
    {
        return Err(RelayErrorCode::StateAmbiguous);
    }
    if !bound {
        // Void the artifact with the code that would have released it. A
        // `false` result means it was already terminal: the same outcome.
        transaction
            .lock_encrypted_artifact(&record.artifact_id)
            .await?;
        transaction
            .claim_encrypted_artifact(&record.artifact_id, consumed_at)
            .await?;
        return Ok(ConsumeOutcome::Burned);
    }
    Ok(ConsumeOutcome::Released(ConsumedAuthorizationCode {
        request_id: record.request_id,
        artifact_id: record.artifact_id,
    }))
}
