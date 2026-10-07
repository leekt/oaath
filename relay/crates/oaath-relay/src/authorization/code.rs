//! One-time authorization code consume, authenticated pickup, and withdrawal.
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
use crate::authentication::{RelayCaller, RelayCallerRole};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::kms::{RelayKms, open_artifact};
use crate::records::{
    AUTHORIZATION_DECISION_RECORD_VERSION, AuthorizationDecisionRecord, DecisionOutcome,
};
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

/// Authenticated client pickup of a released authorization code.
///
/// Pickup writes nothing and is idempotent: the code stays one-shot at
/// consumption, where the PKCE verifier and the code hash lock decide. Only the
/// creating client and subject may pick up; anyone else reads absence.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum FetchedAuthorizationCode {
    Pending,
    #[serde(rename_all = "camelCase")]
    Rejected {
        decided_at: u64,
    },
    #[serde(rename_all = "camelCase")]
    Withdrawn {
        decided_at: u64,
    },
    #[serde(rename_all = "camelCase")]
    Approved {
        decided_at: u64,
        code: String,
        code_expires_at: u64,
    },
}

pub async fn fetch_authorization_code(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    caller: &RelayCaller,
    request_id: &str,
) -> RelayResult<FetchedAuthorizationCode> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = pickup(&mut *transaction, caller, request_id, now).await;
    let Some(decided) = settle(transaction, result).await? else {
        return Ok(FetchedAuthorizationCode::Pending);
    };
    let decided_at = decided.decided_at;
    let (code_ref, code_expires_at) = match decided.outcome {
        DecisionOutcome::Rejected => return Ok(FetchedAuthorizationCode::Rejected { decided_at }),
        DecisionOutcome::Withdrawn => {
            return Ok(FetchedAuthorizationCode::Withdrawn { decided_at });
        }
        DecisionOutcome::Approved => (decided.code_ref, decided.code_expires_at.unwrap_or(0)),
    };
    if now >= code_expires_at {
        return Err(RelayErrorCode::Expired);
    }
    // Opened only after every stored fact agreed; the plaintext never persists.
    let code_ref = code_ref.ok_or(RelayErrorCode::Internal)?;
    Ok(FetchedAuthorizationCode::Approved {
        decided_at,
        code: open_artifact(kms, &code_ref).await?,
        code_expires_at,
    })
}

async fn pickup(
    transaction: &mut dyn RelayTransaction,
    caller: &RelayCaller,
    request_id: &str,
    now: u64,
) -> RelayResult<Option<AuthorizationDecisionRecord>> {
    let request = transaction
        .lock_authorization_request(request_id)
        .await?
        .filter(|request| {
            request.client_id == caller.client_id && request.subject == caller.subject
        })
        .ok_or(RelayErrorCode::NotFound)?;
    let decision = transaction.lock_authorization_decision(request_id).await?;
    if decision.is_none() && now >= request.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    Ok(decision)
}

/// Creator withdrawal shares the immutable decision row and request lock with
/// owner approval. Retrying reads the committed winner; an approval is never
/// revoked.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawnAuthorization {
    pub request_id: String,
    /// A decision outcome, or `expired`.
    pub outcome: &'static str,
    pub decided_at: Option<u64>,
}

pub async fn withdraw_authorization_request(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    caller: &RelayCaller,
    request_id: &str,
) -> RelayResult<WithdrawnAuthorization> {
    if caller.role != RelayCallerRole::Client {
        return Err(RelayErrorCode::Forbidden);
    }
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = withdraw(&mut *transaction, caller, request_id, now).await;
    settle(transaction, result).await
}

async fn withdraw(
    transaction: &mut dyn RelayTransaction,
    caller: &RelayCaller,
    request_id: &str,
    now: u64,
) -> RelayResult<WithdrawnAuthorization> {
    let request = transaction
        .lock_authorization_request(request_id)
        .await?
        .filter(|request| {
            request.client_id == caller.client_id && request.subject == caller.subject
        })
        .ok_or(RelayErrorCode::NotFound)?;
    if let Some(decision) = transaction.lock_authorization_decision(request_id).await? {
        return Ok(WithdrawnAuthorization {
            request_id: request.request_id,
            outcome: decision.outcome.as_str(),
            decided_at: Some(decision.decided_at),
        });
    }
    if now >= request.expires_at {
        return Ok(WithdrawnAuthorization {
            request_id: request.request_id,
            outcome: "expired",
            decided_at: None,
        });
    }
    let inserted = transaction
        .insert_authorization_decision(&AuthorizationDecisionRecord {
            version: AUTHORIZATION_DECISION_RECORD_VERSION,
            request_id: request.request_id.clone(),
            outcome: DecisionOutcome::Withdrawn,
            decided_at: now,
            code_ref: None,
            code_expires_at: None,
        })
        .await?;
    if !inserted {
        return Err(RelayErrorCode::StateAmbiguous);
    }
    Ok(WithdrawnAuthorization {
        request_id: request.request_id,
        outcome: "withdrawn",
        decided_at: Some(now),
    })
}
