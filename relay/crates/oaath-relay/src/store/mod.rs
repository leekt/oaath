//! Durable relay transaction contract.
//!
//! ```text
//! state and owner        authorization request (immutable), decision (terminal),
//!                        code (one-shot), encrypted artifact (one-shot),
//!                        capability invalidation (immutable)
//! persisted evidence     one row per record, one current schema version
//! resource occupied?     yes: a decision row occupies its request; a consumed
//!                        code and a claimed artifact are terminal
//! retry positively safe? recover committed evidence before any new transition
//! transitions            request -> decision(approved|rejected|withdrawn) once;
//!                        code: issued -> consumed once;
//!                        artifact: sealed -> claimed once
//! crash/reload           every transition is decided inside one transaction on a
//!                        row locked for update; a crash leaves the prior state
//! cleanup owner          the caller rolls back; the store releases its handle
//! ```
//!
//! Every `lock_*` read acquires an exclusive row lock for the life of the
//! transaction (`SELECT ... FOR UPDATE` semantics). Every one-shot writer
//! additionally guards on the terminal column being null and reports whether
//! *this* call performed the transition. Revocation and owner-inbox reads are
//! later-stage additions to this contract. The signer/account registry state
//! model lives in `registry.rs`, the portal session model in `session.rs`, and
//! the link request model in `link.rs`.

pub mod memory;
pub mod postgres;

use async_trait::async_trait;

use crate::error::RelayResult;
use crate::link::{LinkOutcome, LinkRequestRecord};
use crate::oauth::records::{AccessTokenRecord, OAuthClientRecord, ParRecord};
use crate::records::{
    AuthorizationCodeRecord, AuthorizationDecisionRecord, AuthorizationRequestRecord,
    CapabilityInvalidationRecord, EncryptedArtifactRecord,
};
use crate::registry::{AccountRecord, AccountSignerRecord, MembershipStatus, SignerRecord};
use crate::session::{PortalChallengeRecord, PortalSessionRecord};

#[async_trait]
pub trait RelayTransaction: Send {
    async fn lock_authorization_request(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<AuthorizationRequestRecord>>;
    /// `false` when the identifier already exists.
    async fn insert_authorization_request(
        &mut self,
        record: &AuthorizationRequestRecord,
    ) -> RelayResult<bool>;

    async fn lock_authorization_decision(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<AuthorizationDecisionRecord>>;
    /// `false` when the request was already decided.
    async fn insert_authorization_decision(
        &mut self,
        record: &AuthorizationDecisionRecord,
    ) -> RelayResult<bool>;

    async fn lock_authorization_code(
        &mut self,
        code_hash: &str,
    ) -> RelayResult<Option<AuthorizationCodeRecord>>;
    async fn insert_authorization_code(
        &mut self,
        record: &AuthorizationCodeRecord,
    ) -> RelayResult<bool>;
    /// `true` only when this call set `consumed_at`.
    async fn consume_authorization_code(
        &mut self,
        code_hash: &str,
        consumed_at: u64,
    ) -> RelayResult<bool>;

    async fn lock_capability_invalidation(
        &mut self,
        grant_id: &str,
    ) -> RelayResult<Option<CapabilityInvalidationRecord>>;
    /// `false` when the Grant's capability is already invalidated.
    async fn insert_capability_invalidation(
        &mut self,
        record: &CapabilityInvalidationRecord,
    ) -> RelayResult<bool>;

    async fn lock_encrypted_artifact(
        &mut self,
        artifact_id: &str,
    ) -> RelayResult<Option<EncryptedArtifactRecord>>;
    /// Internal authority lookup; returns retained evidence even after claim.
    async fn lock_encrypted_artifact_by_request_id(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<EncryptedArtifactRecord>>;
    async fn insert_encrypted_artifact(
        &mut self,
        record: &EncryptedArtifactRecord,
    ) -> RelayResult<bool>;
    /// `true` only when this call set `claimed_at`.
    async fn claim_encrypted_artifact(
        &mut self,
        artifact_id: &str,
        claimed_at: u64,
    ) -> RelayResult<bool>;

    async fn lock_signer(&mut self, signer_id: &str) -> RelayResult<Option<SignerRecord>>;
    async fn lock_signer_by_profile_hash(
        &mut self,
        profile_hash: &str,
    ) -> RelayResult<Option<SignerRecord>>;
    /// WebAuthn signers whose profile names this `authenticatorIdHash`, in
    /// registration order.
    async fn list_signers_by_authenticator(
        &mut self,
        authenticator_id_hash: &str,
    ) -> RelayResult<Vec<SignerRecord>>;
    /// `false` when the identifier or the profile hash already exists.
    async fn insert_signer(&mut self, record: &SignerRecord) -> RelayResult<bool>;
    /// Every account the signer belongs to, with its membership, ordered by
    /// account creation time then account identifier.
    async fn list_signer_accounts(
        &mut self,
        signer_id: &str,
    ) -> RelayResult<Vec<(AccountRecord, AccountSignerRecord)>>;
    /// `false` when the identifier, the address, or the root signer's index
    /// is taken, or the root signer is unknown.
    async fn insert_account(&mut self, record: &AccountRecord) -> RelayResult<bool>;
    /// `false` for an unknown account or signer, a second root, or a repeated
    /// (account, signer, request) row.
    async fn insert_account_signer(&mut self, record: &AccountSignerRecord) -> RelayResult<bool>;

    async fn lock_account(&mut self, account_id: &str) -> RelayResult<Option<AccountRecord>>;
    /// The account at this lowercase address.
    async fn lock_account_by_address(
        &mut self,
        address: &str,
    ) -> RelayResult<Option<AccountRecord>>;
    /// Every membership of the account with its signer: the root first, then
    /// in join order.
    async fn list_account_signers(
        &mut self,
        account_id: &str,
    ) -> RelayResult<Vec<(SignerRecord, AccountSignerRecord)>>;
    /// Deletes the signer's permission memberships of the account; a root
    /// membership is never deleted. `true` only when this call deleted one.
    async fn delete_account_signers(
        &mut self,
        account_id: &str,
        signer_id: &str,
    ) -> RelayResult<bool>;

    /// Moves the signer's permission memberships of the account to `status`
    /// at `at`; a root membership never moves. `true` only when this call
    /// moved at least one.
    async fn set_account_signer_status(
        &mut self,
        account_id: &str,
        signer_id: &str,
        status: MembershipStatus,
        at: u64,
    ) -> RelayResult<bool>;

    async fn lock_link_request(&mut self, link_id: &str) -> RelayResult<Option<LinkRequestRecord>>;
    /// `false` when the identifier exists or the account or signer is unknown.
    async fn insert_link_request(&mut self, record: &LinkRequestRecord) -> RelayResult<bool>;
    /// `true` only when this call decided the undecided link.
    async fn decide_link_request(
        &mut self,
        link_id: &str,
        outcome: LinkOutcome,
        approval_signature: Option<&str>,
        decided_at: u64,
    ) -> RelayResult<bool>;
    /// `true` only when this call set `removed_at` on the approved link.
    async fn remove_link_request(&mut self, link_id: &str, removed_at: u64) -> RelayResult<bool>;

    async fn lock_oauth_client(
        &mut self,
        client_id: &str,
    ) -> RelayResult<Option<OAuthClientRecord>>;
    /// `false` when the client identifier already exists.
    async fn insert_oauth_client(&mut self, record: &OAuthClientRecord) -> RelayResult<bool>;
    async fn lock_par(&mut self, par_id: &str) -> RelayResult<Option<ParRecord>>;
    /// `false` when the identifier exists or the client is unknown.
    async fn insert_par(&mut self, record: &ParRecord) -> RelayResult<bool>;

    async fn lock_access_token(
        &mut self,
        token_hash: &str,
    ) -> RelayResult<Option<AccessTokenRecord>>;
    /// `false` when the hash exists or the client or request is unknown.
    async fn insert_access_token(&mut self, record: &AccessTokenRecord) -> RelayResult<bool>;
    /// `true` only when this call set `revoked_at`.
    async fn revoke_access_token(&mut self, token_hash: &str, revoked_at: u64)
    -> RelayResult<bool>;

    async fn lock_portal_challenge(
        &mut self,
        nonce: &str,
    ) -> RelayResult<Option<PortalChallengeRecord>>;
    /// `false` when the nonce already exists.
    async fn insert_portal_challenge(
        &mut self,
        record: &PortalChallengeRecord,
    ) -> RelayResult<bool>;
    /// `true` only when this call set `consumed_at`.
    async fn consume_portal_challenge(
        &mut self,
        nonce: &str,
        consumed_at: u64,
    ) -> RelayResult<bool>;

    async fn lock_portal_session(
        &mut self,
        token_hash: &str,
    ) -> RelayResult<Option<PortalSessionRecord>>;
    /// `false` when the hash exists or the signer is unknown.
    async fn insert_portal_session(&mut self, record: &PortalSessionRecord) -> RelayResult<bool>;
    /// `true` only when this call set `signed_out_at`.
    async fn end_portal_session(
        &mut self,
        token_hash: &str,
        signed_out_at: u64,
    ) -> RelayResult<bool>;

    /// `relay_state_ambiguous` when the outcome cannot be proven.
    async fn commit(self: Box<Self>) -> RelayResult<()>;
    /// Never fails; rollback failure is a suppressed diagnostic.
    async fn rollback(self: Box<Self>);
}

#[async_trait]
pub trait RelayStore: Send + Sync {
    async fn begin(&self) -> RelayResult<Box<dyn RelayTransaction>>;
    async fn close(&self) -> RelayResult<()>;
}

/// Settles one transition: the body's success commits, its failure rolls back
/// and the canonical failure is preserved.
pub async fn settle<Value>(
    transaction: Box<dyn RelayTransaction>,
    result: RelayResult<Value>,
) -> RelayResult<Value> {
    match result {
        Ok(value) => {
            transaction.commit().await?;
            Ok(value)
        }
        Err(code) => {
            transaction.rollback().await;
            Err(code)
        }
    }
}
