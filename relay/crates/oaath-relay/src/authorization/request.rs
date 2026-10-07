//! Create and read an authorization request.
//!
//! The request record snapshots the resolved approving device separately from
//! the requesting member. It is immutable once created; reads and decisions
//! never re-resolve the owner. A refused route creates no row. Its decision is
//! a separate terminal record, so "was this decided?" has one owner.

use async_trait::async_trait;
use serde::Serialize;

use super::challenge::{is_code_challenge_s256, random_identifier};
use crate::authentication::RelayCaller;
use crate::clock::{RelayClock, relay_now};
use crate::display::owner_phone_display_payload;
use crate::error::{RelayErrorCode, RelayResult};
use crate::records::{
    AUTHORIZATION_REQUEST_RECORD_VERSION, AuthorizationOwnerRoute, AuthorizationRequestRecord,
    DecisionOutcome, canonical_str,
};
use crate::store::{RelayStore, RelayTransaction, settle};

/// Resolves once at creation; existing requests never follow later routing changes.
#[async_trait]
pub trait RelayOwnerRouting: Send + Sync {
    /// `Ok(None)` when no approving device is assigned.
    async fn resolve_owner(
        &self,
        caller: &RelayCaller,
        request_id: &str,
        requested_scope: &str,
    ) -> RelayResult<Option<AuthorizationOwnerRoute>>;
}

/// DEV ONLY: every request routes to one configured device and subject.
pub struct StaticOwnerRouting(pub AuthorizationOwnerRoute);

#[async_trait]
impl RelayOwnerRouting for StaticOwnerRouting {
    async fn resolve_owner(
        &self,
        _caller: &RelayCaller,
        _request_id: &str,
        _requested_scope: &str,
    ) -> RelayResult<Option<AuthorizationOwnerRoute>> {
        Ok(Some(self.0.clone()))
    }
}

pub struct CreateAuthorizationRequest<'a> {
    pub caller: &'a RelayCaller,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub requested_scope: &'a str,
    pub request_ttl_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedAuthorizationRequest {
    pub request_id: String,
    pub expires_at: u64,
    /// Non-secret comparison code shown by the approving phone.
    pub match_code: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionSummary {
    pub outcome: DecisionOutcome,
    pub decided_at: u64,
}

/// The request state body served by fetch and resume.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationState {
    pub request_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub requested_scope: String,
    pub expires_at: u64,
    pub expired: bool,
    pub decision: Option<DecisionSummary>,
}

pub async fn create_authorization_request(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    owner_routing: &dyn RelayOwnerRouting,
    input: CreateAuthorizationRequest<'_>,
) -> RelayResult<CreatedAuthorizationRequest> {
    if !is_code_challenge_s256(input.code_challenge) {
        return Err(RelayErrorCode::RequestInvalid);
    }
    // The deployment owns client registration, so only a redirect URI it bound
    // to this client may receive an authorization code.
    if !input
        .caller
        .redirect_uris
        .iter()
        .any(|uri| uri == input.redirect_uri)
    {
        return Err(RelayErrorCode::Forbidden);
    }
    let request_id = random_identifier();
    let owner = owner_routing
        .resolve_owner(input.caller, &request_id, input.requested_scope)
        .await?
        .ok_or(RelayErrorCode::Forbidden)?;
    canonical_str(&owner.owner_device_id, RelayErrorCode::Internal)?;
    canonical_str(&owner.owner_subject, RelayErrorCode::Internal)?;
    let created_at = relay_now(clock)?;
    let record = AuthorizationRequestRecord {
        version: AUTHORIZATION_REQUEST_RECORD_VERSION,
        request_id,
        client_id: input.caller.client_id.clone(),
        subject: input.caller.subject.clone(),
        owner_device_id: owner.owner_device_id,
        owner_subject: owner.owner_subject,
        organization_audience: input.caller.organization_audience.clone(),
        redirect_uri: input.redirect_uri.to_owned(),
        code_challenge: input.code_challenge.to_owned(),
        requested_scope: input.requested_scope.to_owned(),
        created_at,
        expires_at: created_at + input.request_ttl_ms,
    };
    let match_code = owner_phone_display_payload(&record.owner_subject, &record.request_id);
    let mut transaction = store.begin().await?;
    let inserted = transaction.insert_authorization_request(&record).await;
    // 256 bits of CSPRNG output collided, or the store contradicts itself.
    let result =
        inserted.and_then(|inserted| inserted.then_some(()).ok_or(RelayErrorCode::Internal));
    settle(transaction, result).await?;
    Ok(CreatedAuthorizationRequest {
        request_id: record.request_id,
        expires_at: record.expires_at,
        match_code,
    })
}

/// Row-locked read of the request and its decision. A caller that is not
/// entitled to the request learns only that it is absent.
pub async fn read_authorization_state(
    transaction: &mut dyn RelayTransaction,
    request_id: &str,
    now: u64,
    entitled: impl Fn(&AuthorizationRequestRecord) -> bool + Send,
) -> RelayResult<AuthorizationState> {
    let request = transaction
        .lock_authorization_request(request_id)
        .await?
        .filter(|request| entitled(request))
        .ok_or(RelayErrorCode::NotFound)?;
    let decision = transaction.lock_authorization_decision(request_id).await?;
    Ok(AuthorizationState {
        expired: now >= request.expires_at,
        request_id: request.request_id,
        client_id: request.client_id,
        redirect_uri: request.redirect_uri,
        requested_scope: request.requested_scope,
        expires_at: request.expires_at,
        decision: decision.map(|decision| DecisionSummary {
            outcome: decision.outcome,
            decided_at: decision.decided_at,
        }),
    })
}

/// Read for the approving owner: only the snapshotted owner subject may read.
pub async fn fetch_authorization_request(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    caller: &RelayCaller,
    request_id: &str,
) -> RelayResult<AuthorizationState> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = read_authorization_state(&mut *transaction, request_id, now, |request| {
        request.owner_subject == caller.subject
    })
    .await;
    settle(transaction, result).await
}

/// Resume: fresh authentication plus a recovery read for the creating client.
/// It never transitions anything and never re-releases a code or an artifact.
pub async fn resume_authorization(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    caller: &RelayCaller,
    request_id: &str,
) -> RelayResult<AuthorizationState> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = read_authorization_state(&mut *transaction, request_id, now, |request| {
        request.client_id == caller.client_id && request.subject == caller.subject
    })
    .await;
    settle(transaction, result).await
}
