//! Grants the account root gives a member from a policy template, with the
//! portal itself as the client: at a link's approval, or later to an existing
//! member.
//!
//! ```text
//! POST /portal/links/{id}/prepare                           {template_id} -> prepared grant
//! POST /portal/links/{id}/approve           {template_id, artifact}      -> link view
//! POST /portal/accounts/{a}/members/{s}/grants/prepare      {template_id} -> prepared grant
//! POST /portal/accounts/{a}/members/{s}/grants
//!                 {template_id, request_id, requested_at, artifact}      -> {grant_id}
//! GET  /portal/grants/{id}                                                -> grant view
//! ```
//!
//! ```text
//! state and owner      the same records as an OAuth grant (`oauth/grant.rs`):
//!                      request (composed PermissionRequest) + approved
//!                      decision + sealed artifact + a permission membership,
//!                      one transaction; no code is released, because the
//!                      portal is its own client
//! resource occupied?   one decision per request id; a template edit after
//!                      prepare changes the recomposed request, so the
//!                      approval no longer verifies
//! retry safe?          a decided request id refuses a second decision
//! forbidden            a non-root approver; a P-256 member (no operator
//!                      kind); a suspended member; an approval the root did not
//!                      sign for the recomposed request; a stale request time
//! crash/reload         one transaction per decision; verification is pure
//! ```
//!
//! What the root signs is the dapp-grant pipeline unchanged: `compose`,
//! `grant_signing_request` (Kernel v4 enable-mode replayable install of the
//! member's own key under the template's policy), and `verify_grant_approval`.
//! The member's first covered UserOperation installs it.

use oaath_protocol::identity::{OperatorCredentialProfile, OwnerCredentialProfile};
use oaath_protocol::permission::PermissionRequest;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::authorization::challenge::random_identifier;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::approval::verify_grant_approval;
use crate::grant::details::{Composition, GrantDetail, compose};
use crate::grant::grant_signing_request;
use crate::grant::signature::RelyingParty;
use crate::kms::{RelayKms, seal_artifact};
use crate::oauth::PreparedGrant;
use crate::oauth::grant::{GrantView, read_grant, relying_party};
use crate::policy::{PolicyTemplateRecord, root_template};
use crate::records::{
    AUTHORIZATION_DECISION_RECORD_VERSION, AUTHORIZATION_REQUEST_RECORD_VERSION,
    AuthorizationDecisionRecord, AuthorizationRequestRecord, DecisionOutcome,
    ENCRYPTED_ARTIFACT_RECORD_VERSION, EncryptedArtifactRecord, canonical_identifier, exact_record,
    timestamp,
};
use crate::registry::{
    ACCOUNT_SIGNER_RECORD_VERSION, AccountRecord, AccountSignerRecord, MembershipRole,
    MembershipStatus, SignerRecord,
};
use crate::store::{RelayStore, RelayTransaction, settle};

/// The portal as the grant's application: client id and application id.
pub const PORTAL_CLIENT_ID: &str = "oaath-portal";
/// A prepared assignment must be decided within this long.
pub const PREPARE_TTL_SECONDS: u64 = 600;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;
const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

/// The member's own key as a policy-bound operator; P-256 has no operator kind.
fn operator_for(owner: &OwnerCredentialProfile) -> RelayResult<OperatorCredentialProfile> {
    match owner {
        OwnerCredentialProfile::Ecdsa { address } => Ok(OperatorCredentialProfile::Ecdsa {
            address: address.clone(),
        }),
        OwnerCredentialProfile::WebAuthn {
            public_key,
            authenticator_id_hash,
        } => Ok(OperatorCredentialProfile::WebAuthn {
            public_key: public_key.clone(),
            authenticator_id_hash: authenticator_id_hash.clone(),
        }),
        OwnerCredentialProfile::P256 { .. } => Err(INVALID),
    }
}

/// What one member grant binds.
pub struct MemberGrant<'a> {
    pub request_id: &'a str,
    /// Unix seconds; the policy is valid from here.
    pub requested_at: u64,
    pub account: &'a AccountRecord,
    pub member: &'a SignerRecord,
    pub template: &'a PolicyTemplateRecord,
}

/// The one deterministic request for a member grant, through `compose`.
pub fn compose_member_request(
    issuer: &str,
    grant: &MemberGrant<'_>,
) -> RelayResult<PermissionRequest> {
    let (_, origin) = relying_party(issuer)?;
    let lifetime = grant.template.lifetime_seconds;
    let policy = grant
        .template
        .template_policy()?
        .grant_policy(grant.requested_at, lifetime)?;
    let detail = GrantDetail {
        signer: operator_for(&grant.member.credential()?)?,
        policy,
        chains: Vec::new(),
        // The policy's last valid second is before the request's expiry.
        expires_at: grant.requested_at + lifetime + 1,
        // The member's profile hash names its device.
        device_id: grant
            .member
            .profile_hash
            .trim_start_matches("0x")
            .to_owned(),
    };
    compose(
        &detail,
        &Composition {
            request_id: grant.request_id,
            client_id: PORTAL_CLIENT_ID,
            redirect_origin: &origin,
            requested_at: grant.requested_at,
            account_address: &grant.account.address,
            account: &grant.account.account_profile()?,
        },
    )
}

pub fn prepared(request: &PermissionRequest, account: &str) -> RelayResult<PreparedGrant> {
    let signing = grant_signing_request(request, &request.policy, account)?;
    Ok(PreparedGrant {
        permission_request: request.to_json(),
        request_hash: format!("{:#x}", request.hash()),
        approved_policy: request.policy.to_json(),
        signing_request: signing.to_json(),
    })
}

/// Verifies the root's approval of `request` for `account`; pure.
pub fn verify_member_approval(
    issuer: &str,
    request: &PermissionRequest,
    account: &AccountRecord,
    artifact: &str,
    decided_at: u64,
) -> RelayResult<()> {
    let (rp_id, origin) = relying_party(issuer)?;
    let verified = verify_grant_approval(
        request,
        &account.address,
        artifact,
        decided_at,
        &RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        },
    )?;
    if verified.decision.request_id != request.request_id {
        return Err(INVALID);
    }
    Ok(())
}

/// Writes the approved grant and the member's permission membership for it.
/// `artifact_ref` is the sealed approval artifact.
pub async fn record_member_grant(
    transaction: &mut dyn RelayTransaction,
    request: &PermissionRequest,
    account: &AccountRecord,
    member_id: &str,
    artifact_ref: &str,
    decided_at: u64,
) -> RelayResult<()> {
    let mut scope = request.to_json();
    if let Some(record) = scope.as_object_mut() {
        record.shift_remove("requestId");
    }
    let inserted = transaction
        .insert_authorization_request(&AuthorizationRequestRecord {
            version: AUTHORIZATION_REQUEST_RECORD_VERSION,
            request_id: request.request_id.clone(),
            client_id: PORTAL_CLIENT_ID.to_owned(),
            subject: account.account_id.clone(),
            owner_device_id: account.root_signer_id.clone(),
            owner_subject: account.root_signer_id.clone(),
            organization_audience: None,
            // The portal is its own client: it neither redirects nor redeems.
            redirect_uri: request.application.origin.clone(),
            code_challenge: PORTAL_CLIENT_ID.to_owned(),
            requested_scope: scope.to_string(),
            created_at: request.requested_at * 1_000,
            expires_at: request.expires_at * 1_000,
        })
        .await?
        && transaction
            .insert_authorization_decision(&AuthorizationDecisionRecord {
                version: AUTHORIZATION_DECISION_RECORD_VERSION,
                request_id: request.request_id.clone(),
                outcome: DecisionOutcome::Approved,
                decided_at,
                code_ref: None,
                code_expires_at: None,
            })
            .await?
        && transaction
            .insert_encrypted_artifact(&EncryptedArtifactRecord {
                version: ENCRYPTED_ARTIFACT_RECORD_VERSION,
                artifact_id: random_identifier(),
                request_id: request.request_id.clone(),
                client_id: PORTAL_CLIENT_ID.to_owned(),
                ciphertext_ref: artifact_ref.to_owned(),
                created_at: decided_at,
                claimed_at: None,
            })
            .await?;
    if !inserted {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    let joined = transaction
        .insert_account_signer(&AccountSignerRecord {
            version: ACCOUNT_SIGNER_RECORD_VERSION,
            account_id: account.account_id.clone(),
            signer_id: member_id.to_owned(),
            role: MembershipRole::Permission,
            request_id: Some(request.request_id.clone()),
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

/// `{template_id}`.
pub fn template_selection(body: &Map<String, Value>) -> RelayResult<&str> {
    exact_record(&Value::Object(body.clone()), &["template_id"], INVALID)?;
    canonical_identifier(body.get("template_id"), INVALID)
}

/// The account, its template, and the member, for the root assigning a grant
/// to an existing, active, non-root member.
async fn assignment(
    transaction: &mut dyn RelayTransaction,
    account_id: &str,
    member_id: &str,
    template_id: &str,
    session: &str,
) -> RelayResult<(AccountRecord, PolicyTemplateRecord, SignerRecord)> {
    let template = root_template(transaction, account_id, template_id, session).await?;
    let account = transaction
        .lock_account(account_id)
        .await?
        .ok_or(UNREADABLE)?;
    let memberships: Vec<AccountSignerRecord> = transaction
        .list_account_signers(account_id)
        .await?
        .into_iter()
        .map(|(_, membership)| membership)
        .filter(|membership| membership.signer_id == member_id)
        .collect();
    if memberships.is_empty() {
        return Err(RelayErrorCode::NotFound);
    }
    if memberships.iter().any(|m| m.role == MembershipRole::Root) {
        return Err(INVALID);
    }
    if !memberships.iter().any(AccountSignerRecord::is_active) {
        return Err(RelayErrorCode::MembershipSuspended);
    }
    let member = transaction
        .lock_signer(member_id)
        .await?
        .ok_or(UNREADABLE)?;
    Ok((account, template, member))
}

/// A fresh request for an existing member under a template; nothing persists.
pub async fn prepare_assignment(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    issuer: &str,
    account_id: &str,
    member_id: &str,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<PreparedGrant> {
    let template_id = template_selection(body)?;
    let now = relay_now(clock)? / 1_000;
    let mut transaction = store.begin().await?;
    let result = assignment(
        &mut *transaction,
        account_id,
        member_id,
        template_id,
        session,
    )
    .await;
    let (account, template, member) = settle(transaction, result).await?;
    let request = compose_member_request(
        issuer,
        &MemberGrant {
            request_id: &random_identifier(),
            requested_at: now,
            account: &account,
            member: &member,
            template: &template,
        },
    )?;
    prepared(&request, &account.address)
}

#[derive(Debug, Serialize)]
pub struct AssignedGrant {
    pub grant_id: String,
}

/// Records the root-approved assignment prepared above.
#[allow(clippy::too_many_arguments)]
pub async fn assign_grant(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    issuer: &str,
    account_id: &str,
    member_id: &str,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<AssignedGrant> {
    exact_record(
        &Value::Object(body.clone()),
        &["template_id", "request_id", "requested_at", "artifact"],
        INVALID,
    )?;
    let template_id = canonical_identifier(body.get("template_id"), INVALID)?;
    let request_id = canonical_identifier(body.get("request_id"), INVALID)?;
    let requested_at = timestamp(body.get("requested_at"), INVALID)?;
    let artifact = body
        .get("artifact")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let decided_at = relay_now(clock)?;
    let now = decided_at / 1_000;
    if requested_at > now || now - requested_at > PREPARE_TTL_SECONDS {
        return Err(RelayErrorCode::Expired);
    }
    let compose_at =
        |account: &AccountRecord, template: &PolicyTemplateRecord, member: &SignerRecord| {
            compose_member_request(
                issuer,
                &MemberGrant {
                    request_id,
                    requested_at,
                    account,
                    member,
                    template,
                },
            )
        };
    let mut transaction = store.begin().await?;
    let result = assignment(
        &mut *transaction,
        account_id,
        member_id,
        template_id,
        session,
    )
    .await;
    let (account, template, member) = settle(transaction, result).await?;
    let request = compose_at(&account, &template, &member)?;
    verify_member_approval(issuer, &request, &account, artifact, decided_at)?;
    let artifact_ref = seal_artifact(kms, artifact).await?;
    let mut transaction = store.begin().await?;
    let result = async {
        let (account, template, member) = assignment(
            &mut *transaction,
            account_id,
            member_id,
            template_id,
            session,
        )
        .await?;
        // The template may have changed since verification: recompose.
        if compose_at(&account, &template, &member)?.hash() != request.hash() {
            return Err(INVALID);
        }
        record_member_grant(
            &mut *transaction,
            &request,
            &account,
            member_id,
            &artifact_ref,
            decided_at,
        )
        .await
    }
    .await;
    settle(transaction, result).await?;
    Ok(AssignedGrant {
        grant_id: request_id.to_owned(),
    })
}

/// A portal grant's approval, for the account's root or the member it
/// admitted; its install approval is what the member's first operation uses.
pub async fn member_grant_view(
    store: &dyn RelayStore,
    kms: &dyn RelayKms,
    grant_id: &str,
    session: &str,
) -> RelayResult<GrantView> {
    let mut transaction = store.begin().await?;
    let result = async {
        let request = transaction
            .lock_authorization_request(grant_id)
            .await?
            .filter(|request| request.client_id == PORTAL_CLIENT_ID)
            .ok_or(RelayErrorCode::NotFound)?;
        let account = transaction
            .lock_account(&request.subject)
            .await?
            .ok_or(UNREADABLE)?;
        let member = transaction
            .list_account_signers(&account.account_id)
            .await?
            .into_iter()
            .any(|(signer, membership)| {
                signer.signer_id == session && membership.request_id.as_deref() == Some(grant_id)
            });
        if session != account.root_signer_id && !member {
            return Err(RelayErrorCode::Forbidden);
        }
        read_grant(&mut *transaction, kms, grant_id).await
    }
    .await;
    settle(transaction, result).await
}
