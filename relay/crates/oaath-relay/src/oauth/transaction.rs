//! Owner transactions: one exact plain transaction a dapp asks an OAAth
//! signer's own wallet to send from the portal (a factory call with value, a
//! contract creation, an EntryPoint `handleOps`), released once with the token.
//!
//! ```text
//! state and owner      PAR (exact request) -> decision (the signer whose
//!                      ECDSA address is `from` reports the hash its wallet
//!                      returned) + request + code + sealed {request, hash},
//!                      one transaction -> code consumed once -> released once
//!                      with the token
//! resource occupied?   one decision per PAR
//! retry safe?          a second decision is refused; the wallet sent before
//!                      the decision, so a lost decision leaves an unreported
//!                      hash the dapp observes on chain, never a resend
//! forbidden            a signer other than `from`, or without a portal
//!                      session (a hash proves nothing); a non-member of the
//!                      selected account; a malformed hash; a second decision
//! ```
//!
//! OAAth never sends: the signer's wallet does, in the portal. The relay
//! cannot prove the hash is the request's transaction; the dapp observes it.

use oaath_protocol::capture::parse_json;
use oaath_protocol::identity::OwnerCredentialProfile;
use oaath_protocol::owner_transaction::{OwnerTransactionRequest, parse_owner_transaction_request};
use serde_json::{Value, json};

use super::records::ParRecord;
use super::{LoginRedirect, OAuthConfiguration, redirect_url};
use crate::authorization::challenge::{random_identifier, sha256_base64url};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::kms::{RelayKms, seal_artifact};
use crate::records::{
    AUTHORIZATION_CODE_RECORD_VERSION, AUTHORIZATION_DECISION_RECORD_VERSION,
    AUTHORIZATION_REQUEST_RECORD_VERSION, AuthorizationCodeRecord, AuthorizationDecisionRecord,
    AuthorizationRequestRecord, DecisionOutcome, ENCRYPTED_ARTIFACT_RECORD_VERSION,
    EncryptedArtifactRecord,
};
use crate::store::{RelayStore, RelayTransaction, settle};

pub const TRANSACTION_DETAIL_TYPE: &str = "oaath_transaction";
/// The stored scope of an owner-transaction decision: a kind marker; the
/// request stays with the PAR.
pub const TRANSACTION_SCOPE: &str = r#"{"version":"oaath.owner-transaction-selection/v1"}"#;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;

/// The owner-transaction request in PAR `authorization_details`, or `None`
/// when they name something else. Exactly one `{type, request}` entry.
pub fn transaction_request(details: &Value) -> RelayResult<Option<OwnerTransactionRequest>> {
    let Some(entries) = details.as_array() else {
        return Ok(None);
    };
    if !entries
        .iter()
        .any(|entry| entry.get("type").and_then(Value::as_str) == Some(TRANSACTION_DETAIL_TYPE))
    {
        return Ok(None);
    }
    let [entry] = entries.as_slice() else {
        return Err(INVALID);
    };
    let record = entry.as_object().ok_or(INVALID)?;
    if record.len() != 2 {
        return Err(INVALID);
    }
    let request = record.get("request").ok_or(INVALID)?;
    parse_owner_transaction_request(request)
        .map(Some)
        .map_err(|_| INVALID)
}

/// The canonical stored `authorization_details` of one request.
pub fn stored_details(request: &OwnerTransactionRequest) -> String {
    json!([{ "type": TRANSACTION_DETAIL_TYPE, "request": request.to_json() }]).to_string()
}

/// The PAR's stored request, if it is an owner transaction.
pub fn par_transaction(par: &ParRecord) -> RelayResult<Option<OwnerTransactionRequest>> {
    match par.authorization_details.as_deref() {
        None => Ok(None),
        Some(text) => {
            transaction_request(&parse_json(text).map_err(|_| RelayErrorCode::RecordUnreadable)?)
                .map_err(|_| RelayErrorCode::RecordUnreadable)
        }
    }
}

/// Whether `transaction_id` is an owner-transaction PAR.
pub async fn is_transaction_request(
    store: &dyn RelayStore,
    transaction_id: &str,
) -> RelayResult<bool> {
    let mut transaction = store.begin().await?;
    let result = transaction.lock_par(transaction_id).await;
    let par = settle(transaction, result).await?;
    match par {
        Some(par) => Ok(par_transaction(&par)?.is_some()),
        None => Ok(false),
    }
}

/// An undecided, unexpired transaction PAR and its request, decided by the
/// ECDSA signer that sends it as an active member of `account_id`.
async fn selection(
    transaction: &mut dyn RelayTransaction,
    transaction_id: &str,
    signer_id: &str,
    account_id: &str,
    now: u64,
) -> RelayResult<(ParRecord, OwnerTransactionRequest)> {
    let par = transaction
        .lock_par(transaction_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let request = par_transaction(&par)?.ok_or(INVALID)?;
    if transaction
        .lock_authorization_request(&par.par_id)
        .await?
        .is_some()
    {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    if now >= par.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    let signer = transaction
        .lock_signer(signer_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let sends = matches!(
        signer.credential()?,
        OwnerCredentialProfile::Ecdsa { address } if address == request.from
    );
    let member = transaction
        .list_signer_accounts(signer_id)
        .await?
        .into_iter()
        .any(|(account, membership)| account.account_id == account_id && membership.is_active());
    if !sends || !member {
        return Err(RelayErrorCode::Forbidden);
    }
    Ok((par, request))
}

/// `0x` and 32 lowercase hex bytes.
fn transaction_hash(artifact: &str) -> RelayResult<&str> {
    artifact
        .strip_prefix("0x")
        .filter(|digits| {
            digits.len() == 64
                && digits
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
        .map(|_| artifact)
        .ok_or(INVALID)
}

/// Records the hash the signer's wallet returned for one owner transaction.
/// The write transaction reselects under the PAR's lock and refuses a second
/// decision.
#[allow(clippy::too_many_arguments)]
pub async fn decide_transaction(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    oauth: &OAuthConfiguration,
    code_ttl_ms: u64,
    transaction_id: &str,
    signer_id: &str,
    account_id: &str,
    artifact: &str,
) -> RelayResult<LoginRedirect> {
    let hash = transaction_hash(artifact)?;
    let decided_at = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = selection(
        &mut *transaction,
        transaction_id,
        signer_id,
        account_id,
        decided_at,
    )
    .await;
    let (_, request) = settle(transaction, result).await?;
    let released = json!({ "request": request.to_json(), "transactionHash": hash });
    let code = random_identifier();
    let code_ref = seal_artifact(kms, &code).await?;
    let artifact_ref = seal_artifact(kms, &released.to_string()).await?;

    let mut transaction = store.begin().await?;
    let result = async {
        let (par, reselected) = selection(
            &mut *transaction,
            transaction_id,
            signer_id,
            account_id,
            decided_at,
        )
        .await?;
        // The PAR is immutable, so this only fails if the store contradicts itself.
        if reselected != request {
            return Err(RelayErrorCode::Internal);
        }
        let artifact_id = random_identifier();
        let inserted = transaction
            .insert_authorization_request(&AuthorizationRequestRecord {
                version: AUTHORIZATION_REQUEST_RECORD_VERSION,
                request_id: par.par_id.clone(),
                client_id: par.client_id.clone(),
                subject: account_id.to_owned(),
                owner_device_id: signer_id.to_owned(),
                owner_subject: signer_id.to_owned(),
                organization_audience: None,
                redirect_uri: par.redirect_uri.clone(),
                code_challenge: par.code_challenge.clone(),
                requested_scope: TRANSACTION_SCOPE.to_owned(),
                created_at: par.created_at,
                expires_at: par.expires_at,
            })
            .await?
            && transaction
                .insert_authorization_decision(&AuthorizationDecisionRecord {
                    version: AUTHORIZATION_DECISION_RECORD_VERSION,
                    request_id: par.par_id.clone(),
                    outcome: DecisionOutcome::Approved,
                    decided_at,
                    code_ref: Some(code_ref.clone()),
                    code_expires_at: Some(decided_at + code_ttl_ms),
                })
                .await?
            && transaction
                .insert_authorization_code(&AuthorizationCodeRecord {
                    version: AUTHORIZATION_CODE_RECORD_VERSION,
                    code_hash: sha256_base64url(&code),
                    request_id: par.par_id.clone(),
                    client_id: par.client_id.clone(),
                    redirect_uri: par.redirect_uri.clone(),
                    code_challenge: par.code_challenge.clone(),
                    artifact_id: artifact_id.clone(),
                    created_at: decided_at,
                    expires_at: decided_at + code_ttl_ms,
                    consumed_at: None,
                })
                .await?
            && transaction
                .insert_encrypted_artifact(&EncryptedArtifactRecord {
                    version: ENCRYPTED_ARTIFACT_RECORD_VERSION,
                    artifact_id,
                    request_id: par.par_id.clone(),
                    client_id: par.client_id.clone(),
                    ciphertext_ref: artifact_ref.clone(),
                    created_at: decided_at,
                    claimed_at: None,
                })
                .await?;
        if !inserted {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        Ok(par)
    }
    .await;
    let par = settle(transaction, result).await?;
    Ok(LoginRedirect {
        redirect: redirect_url(&oauth.issuer, &par, Ok(&code))?,
    })
}

/// The token response's `authorization_details` entry for a released transaction.
pub fn transaction_detail(plaintext: &str) -> RelayResult<Value> {
    let released = parse_json(plaintext).map_err(|_| RelayErrorCode::RecordUnreadable)?;
    Ok(json!({
        "type": TRANSACTION_DETAIL_TYPE,
        "request": released["request"],
        "transaction_hash": released["transactionHash"],
    }))
}
