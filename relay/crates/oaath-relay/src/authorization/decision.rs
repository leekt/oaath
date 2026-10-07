//! Authoritative approve/reject transition.
//!
//! ```text
//! state and owner        the decision record owns "decided"; the request record
//!                        never mutates
//! persisted evidence     the immutable requestedScope is reclassified from the
//!                        durable request before every approval attempt
//! resource occupied?     a refused approval occupies nothing and performs no KMS
//!                        sealing; a rejection occupies only its decision row
//! retry positively safe? refused approval is read-only; a terminal outcome is
//!                        rejected by this owner
//! transitions            undecided -> approved | rejected, once
//! terminal               both outcomes; a second decide fails relay_already_decided
//! crash/reload           the decision, the code, and the sealed artifact commit in
//!                        one transaction on the row-locked request, so a crash
//!                        leaves the request undecided and nothing released
//! cleanup owner          the relay transaction; refused approvals allocate nothing
//! ```
//!
//! The approving subject is recovered from the stored request and compared
//! against the authenticated owner. No wire field names the subject.

use serde::Serialize;

use super::challenge::{random_identifier, sha256_base64url};
use super::request::fetch_authorization_request;
use crate::authentication::RelayCaller;
use crate::authority::approve_scope;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::kms::{RelayKms, seal_artifact};
use crate::records::{
    AUTHORIZATION_CODE_RECORD_VERSION, AUTHORIZATION_DECISION_RECORD_VERSION,
    AuthorizationCodeRecord, AuthorizationDecisionRecord, DecisionOutcome,
    ENCRYPTED_ARTIFACT_RECORD_VERSION, EncryptedArtifactRecord,
};
use crate::store::{RelayStore, RelayTransaction, settle};

pub enum DecisionCommand {
    /// The owner supplies a request-bound approval artifact; the client claims it once.
    Approved {
        artifact: String,
    },
    Rejected,
}

#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum SubmittedDecision {
    #[serde(rename_all = "camelCase")]
    Approved {
        decided_at: u64,
        /// Released exactly once, here. Only its SHA-256 is stored.
        code: String,
        artifact_id: String,
        redirect_uri: String,
        code_expires_at: u64,
    },
    #[serde(rename_all = "camelCase")]
    Rejected { decided_at: u64 },
}

pub struct DecisionPorts<'a> {
    pub store: &'a dyn RelayStore,
    pub clock: &'a dyn RelayClock,
    pub kms: &'a dyn RelayKms,
}

struct Released {
    code: String,
    code_hash: String,
    artifact_id: String,
    ciphertext_ref: String,
}

pub async fn submit_authorization_decision(
    ports: DecisionPorts<'_>,
    caller: &RelayCaller,
    request_id: &str,
    command: DecisionCommand,
    code_ttl_ms: u64,
) -> RelayResult<SubmittedDecision> {
    let decided_at = relay_now(ports.clock)?;

    // Approval is the artifact-creating transition, so it is admitted only for
    // an exact scope this server currently permits to release. Refusal happens
    // before KMS sealing or any durable decision/code/artifact.
    let mut released = None;
    let mut code_ref = None;
    if let DecisionCommand::Approved { artifact } = &command {
        let state =
            fetch_authorization_request(ports.store, ports.clock, caller, request_id).await?;
        if state.decision.is_some() {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        if state.expired {
            return Err(RelayErrorCode::Expired);
        }
        let approved = approve_scope(
            &state.requested_scope,
            &state.request_id,
            artifact,
            decided_at,
        )?;
        // Seal before the transaction: the store only ever receives references,
        // and an uncommitted decision leaves nothing but unreferenced ciphertexts.
        let code = random_identifier();
        let artifact_id = random_identifier();
        let ciphertext_ref = seal_artifact(ports.kms, &approved).await?;
        code_ref = Some(seal_artifact(ports.kms, &code).await?);
        released = Some(Released {
            code_hash: sha256_base64url(&code),
            code,
            artifact_id,
            ciphertext_ref,
        });
    }
    let decision = AuthorizationDecisionRecord {
        version: AUTHORIZATION_DECISION_RECORD_VERSION,
        request_id: request_id.to_owned(),
        outcome: match command {
            DecisionCommand::Approved { .. } => DecisionOutcome::Approved,
            DecisionCommand::Rejected => DecisionOutcome::Rejected,
        },
        decided_at,
        code_expires_at: code_ref.as_ref().map(|_| decided_at + code_ttl_ms),
        code_ref,
    };

    let mut transaction = ports.store.begin().await?;
    let result = decide(
        &mut *transaction,
        caller,
        &decision,
        released.as_ref(),
        code_ttl_ms,
    )
    .await;
    let redirect_uri = settle(transaction, result).await?;

    Ok(match released {
        Some(released) => SubmittedDecision::Approved {
            decided_at,
            code: released.code,
            artifact_id: released.artifact_id,
            redirect_uri,
            code_expires_at: decided_at + code_ttl_ms,
        },
        None => SubmittedDecision::Rejected { decided_at },
    })
}

async fn decide(
    transaction: &mut dyn RelayTransaction,
    caller: &RelayCaller,
    decision: &AuthorizationDecisionRecord,
    released: Option<&Released>,
    code_ttl_ms: u64,
) -> RelayResult<String> {
    let decided_at = decision.decided_at;
    // The request snapshots its approving subject independently of its requester.
    let request = transaction
        .lock_authorization_request(&decision.request_id)
        .await?
        .filter(|request| request.owner_subject == caller.subject)
        .ok_or(RelayErrorCode::NotFound)?;
    if transaction
        .lock_authorization_decision(&decision.request_id)
        .await?
        .is_some()
    {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    if decided_at >= request.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    if !transaction.insert_authorization_decision(decision).await? {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    if let Some(released) = released {
        let inserted = transaction
            .insert_authorization_code(&AuthorizationCodeRecord {
                version: AUTHORIZATION_CODE_RECORD_VERSION,
                code_hash: released.code_hash.clone(),
                request_id: request.request_id.clone(),
                client_id: request.client_id.clone(),
                redirect_uri: request.redirect_uri.clone(),
                code_challenge: request.code_challenge.clone(),
                artifact_id: released.artifact_id.clone(),
                created_at: decided_at,
                expires_at: decided_at + code_ttl_ms,
                consumed_at: None,
            })
            .await?
            && transaction
                .insert_encrypted_artifact(&EncryptedArtifactRecord {
                    version: ENCRYPTED_ARTIFACT_RECORD_VERSION,
                    artifact_id: released.artifact_id.clone(),
                    request_id: request.request_id.clone(),
                    client_id: request.client_id.clone(),
                    ciphertext_ref: released.ciphertext_ref.clone(),
                    created_at: decided_at,
                    claimed_at: None,
                })
                .await?;
        if !inserted {
            return Err(RelayErrorCode::Internal);
        }
    }
    Ok(request.redirect_uri)
}
