//! Grant decisions, their release at `/oauth/token`, and the bearer grant
//! endpoints.
//!
//! ```text
//! state and owner      PAR (intent) -> request (composed PermissionRequest) +
//!                      decision + code + sealed artifact + dapp signer +
//!                      permission membership, one transaction
//!                      -> code consumed once -> artifact claimed once with the
//!                      token -> access token (hash only) until expiry or revoke
//! resource occupied?   one decision per grant; one permission membership per
//!                      (account, signer, grant); one access token per hash
//! retry safe?          decision: refused once decided, the redirect is recovered
//!                      from the sealed code; token: never retried
//! forbidden            a non-root approver; an artifact the root did not sign
//!                      for the recomposed request; a widened policy; a
//!                      revoked or expired token; another grant's token
//! crash/reload         one transaction per transition; verification is pure
//! ```
//!
//! The retained artifact (permission decision + `installApproval`) is the one
//! owner of what was approved: the token response and `GET /oauth/grants/{id}`
//! both reopen it. Off-chain invalidation is `/invalidate`, never "revoke":
//! on-chain revocation is a separate operation.

use axum::http::HeaderMap;
use oaath_protocol::capture::parse_json;
use oaath_protocol::identity::{OwnerCredentialProfile, parse_owner_credential_profile};
use oaath_protocol::permission::PermissionRequest;
use serde::Serialize;
use serde_json::{Map, Value, json};
use url::Url;

use super::records::{ACCESS_TOKEN_TTL_MS, AccessTokenRecord, OAUTH_ACCESS_TOKEN_RECORD_VERSION};
use super::{
    LoginRedirect, OAuthConfiguration, OAuthFailure, OAuthResult, grant_selection, redirect_url,
};
use crate::authentication::{RelayCaller, RelayCallerRole, bearer_token};
use crate::authority::stored_permission_request;
use crate::authorization::challenge::{random_identifier, sha256_base64url};
use crate::authorization::invalidation::{InvalidationEvidence, record_capability_invalidation};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::approval::verify_grant_approval;
use crate::grant::signature::RelyingParty;
use crate::kms::{RelayKms, open_artifact, seal_artifact};
use crate::portal::{register, signer_record};
use crate::records::{
    AUTHORIZATION_CODE_RECORD_VERSION, AUTHORIZATION_DECISION_RECORD_VERSION,
    AUTHORIZATION_REQUEST_RECORD_VERSION, AuthorizationCodeRecord, AuthorizationDecisionRecord,
    AuthorizationRequestRecord, DecisionOutcome, ENCRYPTED_ARTIFACT_RECORD_VERSION,
    EncryptedArtifactRecord, canonical_str,
};
use crate::registry::{
    ACCOUNT_SIGNER_RECORD_VERSION, AccountSignerRecord, MembershipRole, MembershipStatus,
};
use crate::store::{RelayStore, RelayTransaction, settle};

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;

/// The relying party a WebAuthn root asserts to: the issuer itself.
pub(crate) fn relying_party(issuer: &str) -> RelayResult<(String, String)> {
    let url = Url::parse(issuer).map_err(|_| RelayErrorCode::Internal)?;
    let host = url.host_str().ok_or(RelayErrorCode::Internal)?.to_owned();
    Ok((host, url.origin().ascii_serialization()))
}

/// The stored scope of a grant: the composed request without its relay id,
/// exactly as the SDK stores a permission scope.
pub(crate) fn stored_scope(request: &Value) -> String {
    let mut scope = request.clone();
    if let Some(record) = scope.as_object_mut() {
        record.shift_remove("requestId");
    }
    scope.to_string()
}

/// Records the root-approved grant: verification is pure and happens before
/// anything is sealed; the write transaction recomposes the request under the
/// PAR's lock and refuses if it no longer hashes the same.
#[allow(clippy::too_many_arguments)]
pub async fn decide_grant(
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
    let result = grant_selection(
        &mut *transaction,
        transaction_id,
        signer_id,
        account_id,
        decided_at,
    )
    .await;
    let (_, request, account) = settle(transaction, result).await?;
    let (rp_id, origin) = relying_party(&oauth.issuer)?;
    let verified = verify_grant_approval(
        &request,
        &account.address,
        artifact,
        decided_at,
        &RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        },
    )?;
    let code = random_identifier();
    let code_ref = seal_artifact(kms, &code).await?;
    let artifact_ref = seal_artifact(kms, artifact).await?;
    let dapp_signer = dapp_signer_profile(&request)?;

    let mut transaction = store.begin().await?;
    let result = async {
        let (par, recomposed, _) = grant_selection(
            &mut *transaction,
            transaction_id,
            signer_id,
            account_id,
            decided_at,
        )
        .await?;
        // The PAR and the account are immutable, so this only fails if the
        // store contradicts itself.
        if recomposed.hash() != request.hash() || verified.decision.request_id != par.par_id {
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
                requested_scope: stored_scope(&request.to_json()),
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
        join_dapp_signer(
            &mut *transaction,
            &dapp_signer,
            account_id,
            &par.par_id,
            decided_at,
        )
        .await?;
        Ok(par)
    }
    .await;
    let par = settle(transaction, result).await?;
    Ok(LoginRedirect {
        redirect: redirect_url(&oauth.issuer, &par, Ok(&code))?,
    })
}

/// The dapp's signer as an owner-credential profile, for its registry signer.
pub(crate) fn dapp_signer_profile(
    request: &PermissionRequest,
) -> RelayResult<OwnerCredentialProfile> {
    let mut profile = request.operator_credential.to_json();
    profile["version"] = json!("oaath.owner-credential-profile/v1");
    parse_owner_credential_profile(&profile).map_err(|_| RelayErrorCode::Internal)
}

/// The approved grant's dapp signer joins the account as a permission signer.
pub(crate) async fn join_dapp_signer(
    transaction: &mut dyn RelayTransaction,
    dapp_signer: &OwnerCredentialProfile,
    account_id: &str,
    grant_id: &str,
    decided_at: u64,
) -> RelayResult<()> {
    let dapp_signer_id = register(transaction, &signer_record(dapp_signer, decided_at)).await?;
    let joined = transaction
        .insert_account_signer(&AccountSignerRecord {
            version: ACCOUNT_SIGNER_RECORD_VERSION,
            account_id: account_id.to_owned(),
            signer_id: dapp_signer_id,
            role: MembershipRole::Permission,
            request_id: Some(grant_id.to_owned()),
            link_id: None,
            created_at: decided_at,
            status: MembershipStatus::Active,
            suspended_at: None,
            restored_at: None,
        })
        .await?;
    if !joined {
        return Err(RelayErrorCode::Internal);
    }
    Ok(())
}

/// The decision without its install approval, and the install approval.
fn split_artifact(plaintext: &str) -> RelayResult<(Value, Value)> {
    let Ok(Value::Object(mut decision)) = parse_json(plaintext) else {
        return Err(RelayErrorCode::RecordUnreadable);
    };
    let enable = decision
        .shift_remove("installApproval")
        .ok_or(RelayErrorCode::RecordUnreadable)?;
    Ok((Value::Object(decision), enable))
}

/// The token response's `authorization_details` entry for one grant.
pub fn grant_detail(
    grant_id: &str,
    permission_request: &Value,
    plaintext: &str,
) -> RelayResult<Value> {
    let (decision, enable) = split_artifact(plaintext)?;
    Ok(json!({
        "type": "oaath_grant",
        "grant_id": grant_id,
        "permission_request": permission_request,
        "decision": decision,
        "enable": enable,
    }))
}

/// Stores one opaque access token for the request and answers it.
pub async fn issue_access_token(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    client_id: &str,
    request_id: &str,
) -> RelayResult<String> {
    let token = random_identifier();
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = transaction
        .insert_access_token(&AccessTokenRecord {
            version: OAUTH_ACCESS_TOKEN_RECORD_VERSION,
            token_hash: sha256_base64url(&token),
            client_id: client_id.to_owned(),
            request_id: request_id.to_owned(),
            created_at: now,
            expires_at: now + ACCESS_TOKEN_TTL_MS,
            revoked_at: None,
        })
        .await
        .and_then(|inserted| inserted.then_some(()).ok_or(RelayErrorCode::Internal));
    settle(transaction, result).await?;
    Ok(token)
}

fn invalid_token() -> OAuthFailure {
    OAuthFailure {
        status: 401,
        error: "invalid_token",
        code: RelayErrorCode::Unauthenticated,
        description: None,
    }
}

/// The live token for exactly this grant, or `invalid_token` (RFC 6750).
async fn bearer(
    transaction: &mut dyn RelayTransaction,
    headers: &HeaderMap,
    grant_id: &str,
    now: u64,
) -> OAuthResult<AccessTokenRecord> {
    let token = bearer_token(headers).ok_or_else(invalid_token)?;
    let record = transaction
        .lock_access_token(&sha256_base64url(token))
        .await?
        .filter(|record| {
            record.revoked_at.is_none() && now < record.expires_at && record.request_id == grant_id
        })
        .ok_or_else(invalid_token)?;
    Ok(record)
}

#[derive(Debug, Serialize)]
pub struct GrantView {
    pub grant_id: String,
    /// `approved`, `rejected`, or `invalidated`.
    pub status: &'static str,
    pub permission_request: Value,
    pub decision: Option<Value>,
    pub enable: Option<Value>,
}

pub(crate) async fn read_grant(
    transaction: &mut dyn RelayTransaction,
    kms: &dyn RelayKms,
    grant_id: &str,
) -> RelayResult<GrantView> {
    let request = transaction
        .lock_authorization_request(grant_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let permission = stored_permission_request(&request.requested_scope, grant_id)
        .ok_or(RelayErrorCode::NotFound)?;
    let decision = transaction
        .lock_authorization_decision(grant_id)
        .await?
        .ok_or(RelayErrorCode::RecordUnreadable)?;
    if decision.outcome != DecisionOutcome::Approved {
        return Ok(GrantView {
            grant_id: grant_id.to_owned(),
            status: "rejected",
            permission_request: permission.to_json(),
            decision: None,
            enable: None,
        });
    }
    let artifact = transaction
        .lock_encrypted_artifact_by_request_id(grant_id)
        .await?
        .ok_or(RelayErrorCode::RecordUnreadable)?;
    let (decision, enable) = split_artifact(&open_artifact(kms, &artifact.ciphertext_ref).await?)?;
    let invalidated = transaction
        .lock_capability_invalidation(grant_id)
        .await?
        .is_some();
    Ok(GrantView {
        grant_id: grant_id.to_owned(),
        status: if invalidated {
            "invalidated"
        } else {
            "approved"
        },
        permission_request: permission.to_json(),
        decision: Some(decision),
        enable: Some(enable),
    })
}

/// An approved, not yet invalidated grant's client and capability hash, for
/// invalidation by its account's root; `None` otherwise.
pub(crate) async fn granted_capability(
    transaction: &mut dyn RelayTransaction,
    kms: &dyn RelayKms,
    grant_id: &str,
) -> RelayResult<Option<(String, String)>> {
    let view = read_grant(transaction, kms, grant_id).await?;
    if view.status != "approved" {
        return Ok(None);
    }
    let client_id = transaction
        .lock_authorization_request(grant_id)
        .await?
        .ok_or(RelayErrorCode::RecordUnreadable)?
        .client_id;
    let capability_hash = view
        .decision
        .as_ref()
        .and_then(|decision| decision.get("capabilityHash"))
        .and_then(Value::as_str)
        .ok_or(RelayErrorCode::RecordUnreadable)?;
    Ok(Some((client_id, capability_hash.to_owned())))
}

/// `GET /oauth/grants/{id}` with the grant's own bearer token.
pub async fn grant_view(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    headers: &HeaderMap,
    grant_id: &str,
) -> OAuthResult<GrantView> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        bearer(&mut *transaction, headers, grant_id, now).await?;
        Ok(read_grant(&mut *transaction, kms, grant_id).await?)
    }
    .await;
    finish(transaction, result).await
}

/// `POST /oauth/grants/{id}/invalidate {capability_hash}`: off-chain, through
/// the existing capability-invalidation owner. The hash must be the grant's.
pub async fn invalidate_grant(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    headers: &HeaderMap,
    grant_id: &str,
    body: &Map<String, Value>,
) -> OAuthResult<InvalidationEvidence> {
    let capability_hash = match (body.len(), body.get("capability_hash")) {
        (1, Some(Value::String(hash))) => hash.clone(),
        _ => return Err(INVALID.into()),
    };
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let token = bearer(&mut *transaction, headers, grant_id, now).await?;
        let view = read_grant(&mut *transaction, kms, grant_id).await?;
        let granted = view
            .decision
            .as_ref()
            .and_then(|decision| decision.get("capabilityHash"))
            .and_then(Value::as_str);
        if granted != Some(capability_hash.as_str()) {
            return Err(INVALID.into());
        }
        Ok(token.client_id)
    }
    .await;
    let client_id = finish(transaction, result).await?;
    let caller = RelayCaller {
        role: RelayCallerRole::Client,
        client_id: client_id.clone(),
        subject: client_id,
        redirect_uris: Vec::new(),
        organization_audience: None,
    };
    Ok(record_capability_invalidation(store, clock, &caller, grant_id, &capability_hash).await?)
}

/// RFC 7009: revokes the client's own access token. Any other token, unknown
/// or another client's, answers the same success and changes nothing.
pub async fn revoke_token(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    form: &Map<String, Value>,
) -> OAuthResult<Value> {
    let text = |key| {
        form.get(key)
            .and_then(Value::as_str)
            .filter(|value: &&str| !value.is_empty())
    };
    let token = text("token").ok_or(INVALID)?;
    let client_id = canonical_str(text("client_id").ok_or(INVALID)?, INVALID)?;
    let now = relay_now(clock)?;
    let hash = sha256_base64url(token);
    let mut transaction = store.begin().await?;
    let result = async {
        if let Some(record) = transaction.lock_access_token(&hash).await?
            && record.client_id == client_id
        {
            transaction.revoke_access_token(&hash, now).await?;
        }
        Ok(())
    }
    .await;
    settle(transaction, result).await?;
    Ok(json!({}))
}

async fn finish<T>(
    transaction: Box<dyn RelayTransaction>,
    result: OAuthResult<T>,
) -> OAuthResult<T> {
    match result {
        Ok(value) => {
            transaction.commit().await?;
            Ok(value)
        }
        Err(failure) => {
            transaction.rollback().await;
            Err(failure)
        }
    }
}
