//! Member grants with asynchronous root approval.
//!
//! A dapp pushes an `oaath_grant` as for any grant. When an active member
//! that is not the account's root chooses the account, the portal records a
//! pending request and redirects back with a code at once. The code is not
//! released: until the account's root decides, its exchange answers
//! `authorization_pending`. After the root's one enable signature it releases
//! the grant like a root-approved one; after a rejection it answers
//! `access_denied`.
//!
//! ```text
//! POST /portal/transactions/{id}/decision {outcome: "request_approval", signer_id, account_id}
//! GET  /portal/accounts/{a}/requests        the root's pending requests
//! GET  /portal/requests/{id}                the root or the requesting member
//! POST /portal/requests/{id}/prepare        what the root signs
//! POST /portal/requests/{id}/approve        {artifact}
//! POST /portal/requests/{id}/reject         {}
//! ```
//!
//! ```text
//! state and owner      pending request: requested -> approved | rejected
//!                      (once, by the account's root) | expired (by time);
//!                      the authorization request and the code are written at
//!                      the request, the decision and sealed artifact at the
//!                      root's decision
//! persisted evidence   oaath_pending_grant_v1 (member, account, the sealed
//!                      code for redirect recovery, the artifact handle) and
//!                      the usual request, code, decision and artifact rows
//! resource occupied?   one decision per PAR; the code is one-time and is not
//!                      consumed while the request is pending
//! retry safe?          the request redirect is recovered from the sealed
//!                      code; a pending exchange changes nothing; a decided
//!                      request refuses a second decision
//! forbidden            a root requesting (it signs directly); a non-member or
//!                      suspended member; a non-root decision; an approval the
//!                      root did not sign for the composed request; deciding
//!                      after expiry
//! cleanup owner        expiry; the root's rejection; suspending or removing
//!                      the requesting member rejects its pending requests and
//!                      invalidates its approved ones (`link.rs`)
//! ```
//!
//! A pending code lives until the grant's own expiry, at most
//! `MAX_PENDING_MS`. The dapp's signer joins the account as a permission
//! signer only when the root approves.

use oaath_protocol::capture::parse_json;
use oaath_protocol::permission::PermissionRequest;
use serde::Serialize;
use serde_json::{Map, Value};

use super::grant::{dapp_signer_profile, join_dapp_signer, relying_party, stored_scope};
use super::records::ParRecord;
use super::{LoginRedirect, PreparedGrant, compose_par_grant, redirect_origin, redirect_url};
use crate::authority::stored_permission_request;
use crate::authorization::challenge::{random_identifier, sha256_base64url, verify_pkce_s256};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::approval::verify_grant_approval;
use crate::grant::grant_signing_request;
use crate::grant::signature::RelyingParty;
use crate::kms::{RelayKms, open_artifact, seal_artifact};
use crate::records::{
    AUTHORIZATION_CODE_RECORD_VERSION, AUTHORIZATION_DECISION_RECORD_VERSION,
    AUTHORIZATION_REQUEST_RECORD_VERSION, AuthorizationCodeRecord, AuthorizationDecisionRecord,
    AuthorizationRequestRecord, DecisionOutcome, ENCRYPTED_ARTIFACT_RECORD_VERSION,
    EncryptedArtifactRecord, bounded_text, canonical_identifier, exact_record, limits, timestamp,
};
use crate::registry::{AccountRecord, require_active_member};
use crate::store::{RelayStore, RelayTransaction, settle};

pub const PENDING_GRANT_RECORD_VERSION: &str = "oaath.pending-grant-record/v1";
/// The longest a member's request waits for its root.
pub const MAX_PENDING_MS: u64 = 7 * 86_400_000;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;
const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingOutcome {
    Approved,
    Rejected,
}

/// One member's grant request waiting for its account's root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingGrantRecord {
    pub version: &'static str,
    /// The PAR, authorization request and grant id.
    pub request_id: String,
    pub account_id: String,
    pub member_signer_id: String,
    /// The handle the code releases the sealed approval under.
    pub artifact_id: String,
    /// The sealed code, reopened only to recover a lost redirect.
    pub code_ref: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub outcome: Option<PendingOutcome>,
    pub decided_at: Option<u64>,
}

impl PendingGrantRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "requestId",
                "accountId",
                "memberSignerId",
                "artifactId",
                "codeRef",
                "createdAt",
                "expiresAt",
                "outcome",
                "decidedAt",
            ],
            UNREADABLE,
        )?;
        if r.get("version").and_then(Value::as_str) != Some(PENDING_GRANT_RECORD_VERSION) {
            return Err(UNREADABLE);
        }
        let outcome = match r.get("outcome") {
            Some(Value::Null) => None,
            Some(Value::String(text)) if text == "approved" => Some(PendingOutcome::Approved),
            Some(Value::String(text)) if text == "rejected" => Some(PendingOutcome::Rejected),
            _ => return Err(UNREADABLE),
        };
        let decided_at = match r.get("decidedAt") {
            Some(Value::Null) => None,
            other => Some(timestamp(other, UNREADABLE)?),
        };
        let record = Self {
            version: PENDING_GRANT_RECORD_VERSION,
            request_id: canonical_identifier(r.get("requestId"), UNREADABLE)?.to_owned(),
            account_id: canonical_identifier(r.get("accountId"), UNREADABLE)?.to_owned(),
            member_signer_id: canonical_identifier(r.get("memberSignerId"), UNREADABLE)?.to_owned(),
            artifact_id: canonical_identifier(r.get("artifactId"), UNREADABLE)?.to_owned(),
            code_ref: bounded_text(r.get("codeRef"), limits::CIPHERTEXT_REF, UNREADABLE)?
                .to_owned(),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            expires_at: timestamp(r.get("expiresAt"), UNREADABLE)?,
            outcome,
            decided_at,
        };
        if record.expires_at <= record.created_at
            || record.outcome.is_some() != record.decided_at.is_some()
        {
            return Err(UNREADABLE);
        }
        Ok(record)
    }

    /// `pending`, `approved`, `rejected`, or `expired` at `now`.
    pub fn status(&self, now: u64) -> &'static str {
        match self.outcome {
            Some(PendingOutcome::Approved) => "approved",
            Some(PendingOutcome::Rejected) => "rejected",
            None if now >= self.expires_at => "expired",
            None => "pending",
        }
    }
}

/// The member asks the account's root to approve the PAR's grant: the
/// request and its code are recorded, and the dapp gets its redirect now.
pub async fn request_root_approval(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    issuer: &str,
    transaction_id: &str,
    signer_id: &str,
    account_id: &str,
) -> RelayResult<LoginRedirect> {
    let now = relay_now(clock)?;
    let code = random_identifier();
    let code_ref = seal_artifact(kms, &code).await?;
    let mut transaction = store.begin().await?;
    let result = async {
        let par = transaction
            .lock_par(transaction_id)
            .await?
            .ok_or(RelayErrorCode::NotFound)?;
        if par.authorization_details.is_none() || super::operation::par_operation(&par)?.is_some() {
            return Err(INVALID);
        }
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
        let account = transaction
            .lock_account(account_id)
            .await?
            .ok_or(RelayErrorCode::NotFound)?;
        require_active_member(&mut *transaction, signer_id, account_id).await?;
        // The root approves its own account's grants directly.
        if account.root_signer_id == signer_id {
            return Err(INVALID);
        }
        let request = compose_par_grant(&par, &account)?;
        let expires_at = (request.expires_at * 1_000).min(now + MAX_PENDING_MS);
        if expires_at <= now {
            return Err(RelayErrorCode::Expired);
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
                expires_at,
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
                    created_at: now,
                    expires_at,
                    consumed_at: None,
                })
                .await?
            && transaction
                .insert_pending_grant(&PendingGrantRecord {
                    version: PENDING_GRANT_RECORD_VERSION,
                    request_id: par.par_id.clone(),
                    account_id: account_id.to_owned(),
                    member_signer_id: signer_id.to_owned(),
                    artifact_id,
                    code_ref: code_ref.clone(),
                    created_at: now,
                    expires_at,
                    outcome: None,
                    decided_at: None,
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
        redirect: redirect_url(issuer, &par, Ok(&code))?,
    })
}

/// The redirect of a member's request after a lost reply, from its sealed
/// code; `None` when the PAR has no pending request.
pub async fn recover_pending_redirect(
    transaction: &mut dyn RelayTransaction,
    kms: &dyn RelayKms,
    issuer: &str,
    par: &ParRecord,
    now: u64,
) -> RelayResult<Option<LoginRedirect>> {
    let Some(pending) = transaction.lock_pending_grant(&par.par_id).await? else {
        return Ok(None);
    };
    if now >= pending.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    let code = open_artifact(kms, &pending.code_ref).await?;
    Ok(Some(LoginRedirect {
        redirect: redirect_url(issuer, par, Ok(&code))?,
    }))
}

/// What a code exchange for a member's request may do before the code is
/// consumed.
pub enum PendingGate {
    /// Not a member request, or approved: the usual exchange.
    Exchange,
    /// The root has not decided: nothing is consumed.
    Pending,
    /// The root rejected it: the code is consumed and the exchange is denied.
    Denied,
}

/// For a code bound to this client, redirect and PKCE verifier, whether its
/// member request is still pending or was rejected. Any other code takes the
/// usual exchange, which refuses or burns it as it would any code.
pub async fn gate_exchange(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    client_id: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> RelayResult<PendingGate> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let Some(record) = transaction
            .lock_authorization_code(&sha256_base64url(code))
            .await?
        else {
            return Ok(PendingGate::Exchange);
        };
        let bound = record.client_id == client_id
            && record.redirect_uri == redirect_uri
            && verify_pkce_s256(code_verifier, &record.code_challenge)
            && record.consumed_at.is_none()
            && now < record.expires_at;
        if !bound {
            return Ok(PendingGate::Exchange);
        }
        let Some(pending) = transaction.lock_pending_grant(&record.request_id).await? else {
            return Ok(PendingGate::Exchange);
        };
        Ok(match pending.outcome {
            None => PendingGate::Pending,
            Some(PendingOutcome::Approved) => PendingGate::Exchange,
            Some(PendingOutcome::Rejected) => {
                // The denial is the code's one use.
                transaction
                    .consume_authorization_code(&record.code_hash, now)
                    .await?;
                PendingGate::Denied
            }
        })
    }
    .await;
    settle(transaction, result).await
}

#[derive(Debug, Serialize)]
pub struct PendingMember {
    pub signer_id: String,
    pub kind: &'static str,
    pub profile: Value,
}

#[derive(Debug, Serialize)]
pub struct PendingView {
    pub request_id: String,
    /// `pending`, `approved`, `rejected`, or `expired`.
    pub status: &'static str,
    pub account_id: String,
    pub address: String,
    pub client_name: String,
    pub redirect_origin: String,
    pub member: PendingMember,
    /// The composed request the root approves: the dapp's signer and policy.
    pub permission_request: Value,
    /// The chains the dapp names; display-only, the approval is all-chain.
    pub chains: Value,
    /// Unix seconds.
    pub created_at: u64,
    pub expires_at: u64,
}

struct Locked {
    pending: PendingGrantRecord,
    request: PermissionRequest,
    account: AccountRecord,
    view: PendingView,
}

async fn locked(
    transaction: &mut dyn RelayTransaction,
    request_id: &str,
    now: u64,
) -> RelayResult<Locked> {
    let pending = transaction
        .lock_pending_grant(request_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let stored = transaction
        .lock_authorization_request(request_id)
        .await?
        .ok_or(UNREADABLE)?;
    let request =
        stored_permission_request(&stored.requested_scope, request_id).ok_or(UNREADABLE)?;
    let account = transaction
        .lock_account(&pending.account_id)
        .await?
        .ok_or(UNREADABLE)?;
    let par = transaction.lock_par(request_id).await?.ok_or(UNREADABLE)?;
    let client = transaction
        .lock_oauth_client(&par.client_id)
        .await?
        .ok_or(UNREADABLE)?;
    let member = transaction
        .lock_signer(&pending.member_signer_id)
        .await?
        .ok_or(UNREADABLE)?;
    let credential = member.credential()?;
    let chains = par
        .authorization_details
        .as_deref()
        .and_then(|text| parse_json(text).ok())
        .and_then(|details| {
            details
                .get(0)
                .and_then(|detail| detail.get("chains"))
                .cloned()
        })
        .ok_or(UNREADABLE)?;
    let view = PendingView {
        request_id: request_id.to_owned(),
        status: pending.status(now),
        account_id: account.account_id.clone(),
        address: account.address.clone(),
        client_name: client.client_name,
        redirect_origin: redirect_origin(&par.redirect_uri).map_err(|_| UNREADABLE)?,
        member: PendingMember {
            signer_id: member.signer_id,
            kind: credential.kind(),
            profile: credential.to_json(),
        },
        permission_request: request.to_json(),
        chains,
        created_at: pending.created_at / 1_000,
        expires_at: pending.expires_at / 1_000,
    };
    Ok(Locked {
        pending,
        request,
        account,
        view,
    })
}

/// A request, for its account's root or the member who asked.
pub async fn read_pending(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    request_id: &str,
    session: &str,
) -> RelayResult<PendingView> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let Locked {
            pending,
            account,
            view,
            ..
        } = locked(&mut *transaction, request_id, now).await?;
        if session != account.root_signer_id && session != pending.member_signer_id {
            return Err(RelayErrorCode::Forbidden);
        }
        Ok(view)
    }
    .await;
    settle(transaction, result).await
}

#[derive(Debug, Serialize)]
pub struct PendingRequests {
    pub requests: Vec<PendingView>,
}

/// The account's undecided, unexpired requests, for its root.
pub async fn list_pending(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    account_id: &str,
    session: &str,
) -> RelayResult<PendingRequests> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let account = transaction
            .lock_account(account_id)
            .await?
            .ok_or(RelayErrorCode::NotFound)?;
        if account.root_signer_id != session {
            return Err(RelayErrorCode::Forbidden);
        }
        let mut requests = Vec::new();
        for pending in transaction.list_pending_grants(account_id).await? {
            if pending.status(now) == "pending" {
                requests.push(
                    locked(&mut *transaction, &pending.request_id, now)
                        .await?
                        .view,
                );
            }
        }
        Ok(PendingRequests { requests })
    }
    .await;
    settle(transaction, result).await
}

/// The request, still undecided and unexpired, for its account's root.
async fn for_root(
    transaction: &mut dyn RelayTransaction,
    request_id: &str,
    session: &str,
    now: u64,
) -> RelayResult<Locked> {
    let locked = locked(transaction, request_id, now).await?;
    if session != locked.account.root_signer_id {
        return Err(RelayErrorCode::Forbidden);
    }
    if locked.pending.outcome.is_some() {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    if now >= locked.pending.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    Ok(locked)
}

/// What the root signs to approve the request; nothing is persisted.
pub async fn prepare_pending(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    request_id: &str,
    session: &str,
) -> RelayResult<PreparedGrant> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = for_root(&mut *transaction, request_id, session, now).await;
    let Locked {
        request, account, ..
    } = settle(transaction, result).await?;
    let signing = grant_signing_request(&request, &request.policy, &account.address)?;
    Ok(PreparedGrant {
        permission_request: request.to_json(),
        request_hash: format!("{:#x}", request.hash()),
        approved_policy: request.policy.to_json(),
        signing_request: signing.to_json(),
    })
}

/// The root approves with its signed artifact, or rejects (`artifact` none).
#[allow(clippy::too_many_arguments)]
pub async fn decide_pending(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    issuer: &str,
    request_id: &str,
    body: &Map<String, Value>,
    session: &str,
    approve: bool,
) -> RelayResult<PendingView> {
    let artifact = if approve {
        exact_record(&Value::Object(body.clone()), &["artifact"], INVALID)?;
        Some(bounded_text(body.get("artifact"), limits::ARTIFACT_PLAINTEXT, INVALID)?.to_owned())
    } else {
        exact_record(&Value::Object(body.clone()), &[], INVALID)?;
        None
    };
    let now = relay_now(clock)?;
    // An approval is verified, and its artifact sealed, before the write.
    let sealed = match &artifact {
        Some(artifact) => {
            let mut transaction = store.begin().await?;
            let result = for_root(&mut *transaction, request_id, session, now).await;
            let Locked {
                request, account, ..
            } = settle(transaction, result).await?;
            let (rp_id, origin) = relying_party(issuer)?;
            let verified = verify_grant_approval(
                &request,
                &account.address,
                artifact,
                now,
                &RelyingParty {
                    rp_id: &rp_id,
                    origin: &origin,
                },
            )?;
            if verified.decision.request_id != request_id {
                return Err(INVALID);
            }
            Some(seal_artifact(kms, artifact).await?)
        }
        None => None,
    };
    let mut transaction = store.begin().await?;
    let result = async {
        let Locked {
            pending,
            request,
            mut view,
            ..
        } = for_root(&mut *transaction, request_id, session, now).await?;
        let decision = AuthorizationDecisionRecord {
            version: AUTHORIZATION_DECISION_RECORD_VERSION,
            request_id: request_id.to_owned(),
            outcome: if sealed.is_some() {
                DecisionOutcome::Approved
            } else {
                DecisionOutcome::Rejected
            },
            decided_at: now,
            code_ref: sealed.as_ref().map(|_| pending.code_ref.clone()),
            code_expires_at: sealed.as_ref().map(|_| pending.expires_at),
        };
        if !transaction.insert_authorization_decision(&decision).await? {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        if let Some(artifact_ref) = &sealed {
            let stored = transaction
                .lock_authorization_request(request_id)
                .await?
                .ok_or(UNREADABLE)?;
            if !transaction
                .insert_encrypted_artifact(&EncryptedArtifactRecord {
                    version: ENCRYPTED_ARTIFACT_RECORD_VERSION,
                    artifact_id: pending.artifact_id.clone(),
                    request_id: request_id.to_owned(),
                    client_id: stored.client_id,
                    ciphertext_ref: artifact_ref.clone(),
                    created_at: now,
                    claimed_at: None,
                })
                .await?
            {
                return Err(RelayErrorCode::Internal);
            }
            join_dapp_signer(
                &mut *transaction,
                &dapp_signer_profile(&request)?,
                &pending.account_id,
                request_id,
                now,
            )
            .await?;
        }
        let outcome = if sealed.is_some() {
            PendingOutcome::Approved
        } else {
            PendingOutcome::Rejected
        };
        if !transaction
            .decide_pending_grant(request_id, outcome, now)
            .await?
        {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        view.status = match outcome {
            PendingOutcome::Approved => "approved",
            PendingOutcome::Rejected => "rejected",
        };
        Ok(view)
    }
    .await;
    settle(transaction, result).await
}

/// Rejects the member's undecided requests on the account, in the caller's
/// transaction, and answers its approved grant ids so they can be
/// invalidated. Used when the root suspends or removes the member.
pub async fn retire_member_requests(
    transaction: &mut dyn RelayTransaction,
    account_id: &str,
    member_signer_id: &str,
    now: u64,
) -> RelayResult<Vec<String>> {
    let mut approved = Vec::new();
    for pending in transaction.list_pending_grants(account_id).await? {
        if pending.member_signer_id != member_signer_id {
            continue;
        }
        match pending.outcome {
            Some(PendingOutcome::Approved) => approved.push(pending.request_id),
            Some(PendingOutcome::Rejected) => {}
            None => {
                let rejected = transaction
                    .insert_authorization_decision(&AuthorizationDecisionRecord {
                        version: AUTHORIZATION_DECISION_RECORD_VERSION,
                        request_id: pending.request_id.clone(),
                        outcome: DecisionOutcome::Rejected,
                        decided_at: now,
                        code_ref: None,
                        code_expires_at: None,
                    })
                    .await?
                    && transaction
                        .decide_pending_grant(&pending.request_id, PendingOutcome::Rejected, now)
                        .await?;
                if !rejected {
                    return Err(UNREADABLE);
                }
            }
        }
    }
    Ok(approved)
}
