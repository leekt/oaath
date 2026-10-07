//! Owner operations: one exact UserOperation a dapp asks an account's root to
//! sign, approved in the portal and released once with the token.
//!
//! ```text
//! state and owner      PAR (exact unsigned request, bound to a registry
//!                      account) -> decision (root signature verified) +
//!                      request + code + sealed signed operation, one
//!                      transaction -> code consumed once -> signed operation
//!                      claimed once with the token
//! resource occupied?   one decision per PAR
//! retry safe?          decision: refused once decided, the redirect is
//!                      recovered from the sealed code; token: never retried
//! forbidden            an account outside the registry, or whose profile,
//!                      address, factory or EntryPoint the request contradicts;
//!                      a non-root approver; a signature that is
//!                      not the root's over the request's UserOperation hash;
//!                      a second decision
//! crash/reload         one transaction per transition; verification is pure
//! ```
//!
//! OAAth never submits the operation: the dapp verifies the released artifact
//! and submits it through its own bundler.

use oaath_protocol::capture::parse_json;
use oaath_protocol::owner_operation::{
    OwnerOperationRequest, SignedOwnerOperation, parse_owner_operation_request,
    verify_owner_operation_binding,
};
use serde_json::{Value, json};

use super::grant::relying_party;
use super::records::ParRecord;
use super::{LoginRedirect, OAuthConfiguration, redirect_url};
use crate::authorization::challenge::{random_identifier, sha256_base64url};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::signature::{RelyingParty, verify_root_signature};
use crate::kms::{RelayKms, seal_artifact};
use crate::records::{
    AUTHORIZATION_CODE_RECORD_VERSION, AUTHORIZATION_DECISION_RECORD_VERSION,
    AUTHORIZATION_REQUEST_RECORD_VERSION, AuthorizationCodeRecord, AuthorizationDecisionRecord,
    AuthorizationRequestRecord, DecisionOutcome, ENCRYPTED_ARTIFACT_RECORD_VERSION,
    EncryptedArtifactRecord,
};
use crate::registry::{AccountRecord, MembershipRole};
use crate::store::{RelayStore, RelayTransaction, settle};

pub const OPERATION_DETAIL_TYPE: &str = "oaath_operation";
/// The stored scope of an owner-operation decision: a kind marker; the request
/// stays with the PAR.
pub const OPERATION_SCOPE: &str = r#"{"version":"oaath.owner-operation-selection/v1"}"#;
/// A WebAuthn assertion envelope is the largest root signature.
const MAX_SIGNATURE_HEX: usize = 2 + 2 * 8 * 1024;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;

/// The owner-operation request in PAR `authorization_details`, or `None` when
/// they name something else. Exactly one `{type, request}` entry is accepted.
pub fn operation_request(details: &Value) -> RelayResult<Option<OwnerOperationRequest>> {
    let Some(entries) = details.as_array() else {
        return Ok(None);
    };
    if !entries
        .iter()
        .any(|entry| entry.get("type").and_then(Value::as_str) == Some(OPERATION_DETAIL_TYPE))
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
    parse_owner_operation_request(request)
        .map(Some)
        .map_err(|_| INVALID)
}

/// The canonical stored `authorization_details` of one request.
pub fn stored_details(request: &OwnerOperationRequest) -> String {
    json!([{ "type": OPERATION_DETAIL_TYPE, "request": request.to_json() }]).to_string()
}

/// The PAR's stored request, if it is an owner operation.
pub fn par_operation(par: &ParRecord) -> RelayResult<Option<OwnerOperationRequest>> {
    match par.authorization_details.as_deref() {
        None => Ok(None),
        Some(text) => {
            operation_request(&parse_json(text).map_err(|_| RelayErrorCode::RecordUnreadable)?)
                .map_err(|_| RelayErrorCode::RecordUnreadable)
        }
    }
}

/// The registry account the request executes on: its address, profile,
/// derived address, factory deployment and EntryPoint must all agree.
pub async fn bound_account(
    transaction: &mut dyn RelayTransaction,
    request: &OwnerOperationRequest,
) -> RelayResult<AccountRecord> {
    let account = transaction
        .lock_account_by_address(&request.user_operation.sender)
        .await?
        .ok_or(INVALID)?;
    if account.account_profile()? != request.account
        || verify_owner_operation_binding(request, account.owner_validator.as_deref()).is_err()
    {
        return Err(INVALID);
    }
    Ok(account)
}

/// Whether `transaction_id` is an owner-operation PAR.
pub async fn is_operation_transaction(
    store: &dyn RelayStore,
    transaction_id: &str,
) -> RelayResult<bool> {
    let mut transaction = store.begin().await?;
    let result = transaction.lock_par(transaction_id).await;
    let par = settle(transaction, result).await?;
    match par {
        Some(par) => Ok(par_operation(&par)?.is_some()),
        None => Ok(false),
    }
}

/// An undecided, unexpired operation PAR, its request, and the account it
/// binds, which `signer_id` must hold as root and `account_id` must name.
async fn selection(
    transaction: &mut dyn RelayTransaction,
    transaction_id: &str,
    signer_id: &str,
    account_id: &str,
    now: u64,
) -> RelayResult<(ParRecord, OwnerOperationRequest, AccountRecord)> {
    let par = transaction
        .lock_par(transaction_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let request = par_operation(&par)?.ok_or(INVALID)?;
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
    let account = bound_account(transaction, &request)
        .await
        .map_err(|_| RelayErrorCode::RecordUnreadable)?;
    let root = transaction
        .list_signer_accounts(signer_id)
        .await?
        .into_iter()
        .any(|(member, membership)| {
            member.account_id == account.account_id
                && membership.role == MembershipRole::Root
                && membership.is_active()
        });
    if account.account_id != account_id || !root {
        return Err(RelayErrorCode::Forbidden);
    }
    Ok((par, request, account))
}

fn signature_bytes(artifact: &str) -> RelayResult<Vec<u8>> {
    let digits = artifact
        .strip_prefix("0x")
        .filter(|digits| artifact.len() <= MAX_SIGNATURE_HEX && !digits.is_empty())
        .filter(|digits| {
            digits
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or(INVALID)?;
    hex::decode(digits).map_err(|_| INVALID)
}

/// Records the root's signature over one owner operation. Verification is
/// pure and happens before anything is sealed; the write transaction reselects
/// under the PAR's lock and refuses a second decision.
#[allow(clippy::too_many_arguments)]
pub async fn decide_operation(
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
    let (_, request, _) = settle(transaction, result).await?;
    let signature = signature_bytes(artifact)?;
    let (rp_id, origin) = relying_party(&oauth.issuer)?;
    if !verify_root_signature(
        request.owner_credential(),
        request.digest(),
        &signature,
        &RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        },
    ) {
        return Err(INVALID);
    }
    let signed = SignedOwnerOperation {
        request,
        signature: artifact.to_owned(),
    };
    let code = random_identifier();
    let code_ref = seal_artifact(kms, &code).await?;
    let artifact_ref = seal_artifact(kms, &signed.to_json().to_string()).await?;

    let mut transaction = store.begin().await?;
    let result = async {
        let (par, reselected, _) = selection(
            &mut *transaction,
            transaction_id,
            signer_id,
            account_id,
            decided_at,
        )
        .await?;
        // The PAR is immutable, so this only fails if the store contradicts itself.
        if reselected != signed.request {
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
                requested_scope: OPERATION_SCOPE.to_owned(),
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

/// The token response's `authorization_details` entry for a released operation.
pub fn operation_detail(plaintext: &str) -> RelayResult<Value> {
    let signed = parse_json(plaintext).map_err(|_| RelayErrorCode::RecordUnreadable)?;
    Ok(json!({ "type": OPERATION_DETAIL_TYPE, "signed": signed }))
}
