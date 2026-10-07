//! Grant reference verification: one read-only projection of the relay's
//! durable authorization evidence into the protocol grant-reference contract.
//!
//! ```text
//! state and owner        no new state; the request, decision, sealed artifact,
//!                        and capability invalidation records own every fact
//! resource occupied?     nothing; verification is a pure read
//! retry positively safe? yes: no write exists
//! transitions            none
//! ```
//!
//! Decision order, fail closed:
//!
//! 1. absent grant, another client's grant, or unreadable/contradictory stored
//!    scope -> `unknown`;
//! 2. subject, client, or audience mismatch -> `denied` before any lifecycle fact;
//! 3. pending, rejected, revoked, expired -> `denied`;
//! 4. revision other than the single approved revision -> `denied`;
//! 5. reviewed call set digest differing from the permitted one -> `denied`;
//! 6. otherwise -> `authorized` with the immutable reference evidence.
//!
//! The sealed permission decision owns the approved policy. A missing or
//! unreadable artifact never falls back to `outcome=approved`.

use oaath_protocol::grant_policy::hash_captured_calls;
use oaath_protocol::grant_reference::{
    GRANT_REFERENCE_APPROVED_REVISION, GrantRefState, GrantVerificationDeniedCode as Denied,
    GrantVerificationResult, GrantVerificationUnknownCode as Unknown, OaathGrantRef,
    VerifyGrantRevisionInput, parse_verify_grant_revision_input,
};
use oaath_protocol::permission::{ApprovePermissionDecision, PermissionRequest};
use serde_json::Value;

use crate::authentication::RelayCaller;
use crate::authority::{retained_approval, stored_permission_request};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::kms::{RelayKms, open_artifact};
use crate::records::{AuthorizationDecisionRecord, AuthorizationRequestRecord, DecisionOutcome};
use crate::store::{RelayStore, RelayTransaction, settle};

/// The whole exact-captured body is the assertion; the protocol
/// grant-reference contract owns its capture.
pub async fn verify_grant_reference(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    caller: &RelayCaller,
    body: &Value,
) -> RelayResult<GrantVerificationResult> {
    let assertion =
        parse_verify_grant_revision_input(body).map_err(|_| RelayErrorCode::RequestInvalid)?;
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = verify(&mut *transaction, kms, caller, &assertion, now).await;
    settle(transaction, result).await
}

async fn verify(
    transaction: &mut dyn RelayTransaction,
    kms: &dyn RelayKms,
    caller: &RelayCaller,
    assertion: &VerifyGrantRevisionInput,
    now: u64,
) -> RelayResult<GrantVerificationResult> {
    use GrantVerificationResult::{Denied as Deny, Unknown as Absent};
    // Another client's Grant reads as unknown: not an existence oracle.
    let Some(request) = transaction
        .lock_authorization_request(&assertion.grant_id)
        .await?
        .filter(|request| request.client_id == caller.client_id)
    else {
        return Ok(Absent(Unknown::Unknown));
    };
    // The stored scope must be the exact permission request this Grant was
    // created from, and its application binding must name the creating client.
    let Some(permission) = stored_permission_request(&request.requested_scope, &request.request_id)
        .filter(|permission| permission.application.client_id == request.client_id)
    else {
        return Ok(Absent(Unknown::Unreadable));
    };
    // Binding assertions deny before any lifecycle fact is revealed.
    if assertion.subject != request.subject {
        return Ok(Deny(Denied::SubjectMismatch));
    }
    if assertion.client_id != request.client_id {
        return Ok(Deny(Denied::ClientMismatch));
    }
    if request.organization_audience.as_deref() != Some(assertion.organization_audience.as_str()) {
        return Ok(Deny(Denied::AudienceMismatch));
    }
    let Some(decision) = transaction
        .lock_authorization_decision(&assertion.grant_id)
        .await?
    else {
        return Ok(Deny(Denied::Pending));
    };
    if decision.outcome != DecisionOutcome::Approved {
        return Ok(Deny(Denied::Rejected));
    }
    if transaction
        .lock_capability_invalidation(&assertion.grant_id)
        .await?
        .is_some()
    {
        return Ok(Deny(Denied::Revoked));
    }
    // The sealed artifact is the authoritative approval; request policy is
    // only its upper bound.
    let Some(approval) = read_approval(transaction, kms, &request, &decision, &permission).await
    else {
        return Ok(Absent(Unknown::Unreadable));
    };
    let policy = &approval.approved_policy;
    // The policy's inclusive expiry is the strict fail-closed bound. Protocol
    // time is whole seconds.
    match policy.valid_until {
        Some(valid_until) if now / 1_000 <= valid_until => {}
        _ => return Ok(Deny(Denied::Expired)),
    }
    if assertion.revision != GRANT_REFERENCE_APPROVED_REVISION {
        return Ok(Deny(Denied::RevisionMismatch));
    }
    if assertion.required_calls_digest != hash_captured_calls(&policy.calls) {
        return Ok(Deny(Denied::CallsMismatch));
    }
    Ok(GrantVerificationResult::Authorized(OaathGrantRef {
        grant_id: request.request_id,
        revision: GRANT_REFERENCE_APPROVED_REVISION,
        subject: request.subject,
        client_id: request.client_id,
        organization_audience: assertion.organization_audience.clone(),
        state: GrantRefState::Active,
        policy_digest: format!("0x{}", hex::encode(policy.hash())),
    }))
}

/// The retained sealed approval, read without releasing it. Any failure here,
/// including an unavailable store or KMS, reads as unreadable evidence.
async fn read_approval(
    transaction: &mut dyn RelayTransaction,
    kms: &dyn RelayKms,
    request: &AuthorizationRequestRecord,
    decision: &AuthorizationDecisionRecord,
    permission: &PermissionRequest,
) -> Option<ApprovePermissionDecision> {
    let artifact = transaction
        .lock_encrypted_artifact_by_request_id(&request.request_id)
        .await
        .ok()??;
    if artifact.request_id != request.request_id
        || artifact.client_id != request.client_id
        || artifact.created_at != decision.decided_at
    {
        return None;
    }
    let plaintext = open_artifact(kms, &artifact.ciphertext_ref).await.ok()?;
    retained_approval(&plaintext, permission, decision.decided_at)
}
