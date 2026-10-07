//! In-memory relay store implementing the same transaction contract as
//! PostgreSQL. It lives only as long as the process: use it for local
//! development and tests, never for a deployment that must survive a restart.
//!
//! One process-wide writer lock stands in for row locks. It is strictly
//! stronger than `SELECT ... FOR UPDATE`, so one-shot semantics are identical.
//! Rows are kept as JSON and re-validated on every read, exactly as the SQL
//! store validates rows.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::{RelayStore, RelayTransaction};
use crate::account_import::AccountImportRecord;
use crate::error::{RelayErrorCode, RelayResult};
use crate::link::{LinkOutcome, LinkRequestRecord};
use crate::oauth::records::{AccessTokenRecord, OAuthClientRecord, ParRecord};
use crate::policy::PolicyTemplateRecord;
use crate::records::{
    AuthorizationCodeRecord, AuthorizationDecisionRecord, AuthorizationRequestRecord,
    CapabilityInvalidationRecord, EncryptedArtifactRecord, to_value,
};
use crate::registry::{
    AccountRecord, AccountSignerRecord, MembershipRole, MembershipStatus, SignerRecord,
};
use crate::session::{PortalChallengeRecord, PortalSessionRecord};

#[derive(Clone, Default)]
struct Tables {
    requests: HashMap<String, Value>,
    decisions: HashMap<String, Value>,
    codes: HashMap<String, Value>,
    artifacts: HashMap<String, Value>,
    invalidations: HashMap<String, Value>,
    signers: HashMap<String, Value>,
    accounts: HashMap<String, Value>,
    memberships: Vec<Value>,
    oauth_clients: HashMap<String, Value>,
    pars: HashMap<String, Value>,
    access_tokens: HashMap<String, Value>,
    portal_challenges: HashMap<String, Value>,
    portal_sessions: HashMap<String, Value>,
    link_requests: HashMap<String, Value>,
    policy_templates: HashMap<String, Value>,
    account_imports: HashMap<String, Value>,
}

#[derive(Default)]
pub struct MemoryRelayStore {
    committed: Arc<Mutex<Tables>>,
    closed: AtomicBool,
}

impl MemoryRelayStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RelayStore for MemoryRelayStore {
    async fn begin(&self) -> RelayResult<Box<dyn RelayTransaction>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(RelayErrorCode::StoreUnavailable);
        }
        let guard = self.committed.clone().lock_owned().await;
        let staged = guard.clone();
        Ok(Box::new(MemoryTransaction { guard, staged }))
    }

    async fn close(&self) -> RelayResult<()> {
        self.closed.store(true, Ordering::SeqCst);
        *self.committed.lock().await = Tables::default();
        Ok(())
    }
}

struct MemoryTransaction {
    guard: OwnedMutexGuard<Tables>,
    staged: Tables,
}

fn insert(table: &mut HashMap<String, Value>, key: &str, record: Value) -> bool {
    if table.contains_key(key) {
        return false;
    }
    table.insert(key.to_owned(), record);
    true
}

fn read<Record>(
    table: &HashMap<String, Value>,
    key: &str,
    parse: fn(&Value) -> RelayResult<Record>,
) -> RelayResult<Option<Record>> {
    table.get(key).map(parse).transpose()
}

fn artifact_by_request(
    tables: &Tables,
    request_id: &str,
) -> RelayResult<Option<EncryptedArtifactRecord>> {
    let mut found = None;
    for value in tables.artifacts.values() {
        let record = EncryptedArtifactRecord::parse(value)?;
        if record.request_id != request_id {
            continue;
        }
        if found.is_some() {
            return Err(RelayErrorCode::RecordUnreadable);
        }
        found = Some(record);
    }
    Ok(found)
}

#[async_trait]
impl RelayTransaction for MemoryTransaction {
    async fn lock_authorization_request(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<AuthorizationRequestRecord>> {
        read(
            &self.staged.requests,
            request_id,
            AuthorizationRequestRecord::parse,
        )
    }

    async fn insert_authorization_request(
        &mut self,
        record: &AuthorizationRequestRecord,
    ) -> RelayResult<bool> {
        Ok(insert(
            &mut self.staged.requests,
            &record.request_id,
            to_value(record),
        ))
    }

    async fn lock_authorization_decision(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<AuthorizationDecisionRecord>> {
        read(
            &self.staged.decisions,
            request_id,
            AuthorizationDecisionRecord::parse,
        )
    }

    async fn insert_authorization_decision(
        &mut self,
        record: &AuthorizationDecisionRecord,
    ) -> RelayResult<bool> {
        Ok(insert(
            &mut self.staged.decisions,
            &record.request_id,
            to_value(record),
        ))
    }

    async fn lock_authorization_code(
        &mut self,
        code_hash: &str,
    ) -> RelayResult<Option<AuthorizationCodeRecord>> {
        read(
            &self.staged.codes,
            code_hash,
            AuthorizationCodeRecord::parse,
        )
    }

    async fn insert_authorization_code(
        &mut self,
        record: &AuthorizationCodeRecord,
    ) -> RelayResult<bool> {
        // The SQL schema also keeps request_id and artifact_id unique.
        let duplicate = self.staged.codes.values().any(|stored| {
            stored["requestId"] == json!(record.request_id)
                || stored["artifactId"] == json!(record.artifact_id)
        });
        Ok(!duplicate && insert(&mut self.staged.codes, &record.code_hash, to_value(record)))
    }

    async fn consume_authorization_code(
        &mut self,
        code_hash: &str,
        consumed_at: u64,
    ) -> RelayResult<bool> {
        let Some(mut record) = read(
            &self.staged.codes,
            code_hash,
            AuthorizationCodeRecord::parse,
        )?
        else {
            return Ok(false);
        };
        if record.consumed_at.is_some() {
            return Ok(false);
        }
        record.consumed_at = Some(consumed_at);
        self.staged
            .codes
            .insert(code_hash.to_owned(), to_value(&record));
        Ok(true)
    }

    async fn lock_capability_invalidation(
        &mut self,
        grant_id: &str,
    ) -> RelayResult<Option<CapabilityInvalidationRecord>> {
        read(
            &self.staged.invalidations,
            grant_id,
            CapabilityInvalidationRecord::parse,
        )
    }

    async fn insert_capability_invalidation(
        &mut self,
        record: &CapabilityInvalidationRecord,
    ) -> RelayResult<bool> {
        Ok(insert(
            &mut self.staged.invalidations,
            &record.grant_id,
            to_value(record),
        ))
    }

    async fn lock_encrypted_artifact(
        &mut self,
        artifact_id: &str,
    ) -> RelayResult<Option<EncryptedArtifactRecord>> {
        read(
            &self.staged.artifacts,
            artifact_id,
            EncryptedArtifactRecord::parse,
        )
    }

    async fn lock_encrypted_artifact_by_request_id(
        &mut self,
        request_id: &str,
    ) -> RelayResult<Option<EncryptedArtifactRecord>> {
        artifact_by_request(&self.staged, request_id)
    }

    async fn insert_encrypted_artifact(
        &mut self,
        record: &EncryptedArtifactRecord,
    ) -> RelayResult<bool> {
        if artifact_by_request(&self.staged, &record.request_id)?.is_some() {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.artifacts,
            &record.artifact_id,
            to_value(record),
        ))
    }

    async fn claim_encrypted_artifact(
        &mut self,
        artifact_id: &str,
        claimed_at: u64,
    ) -> RelayResult<bool> {
        let Some(mut record) = read(
            &self.staged.artifacts,
            artifact_id,
            EncryptedArtifactRecord::parse,
        )?
        else {
            return Ok(false);
        };
        if record.claimed_at.is_some() {
            return Ok(false);
        }
        record.claimed_at = Some(claimed_at);
        self.staged
            .artifacts
            .insert(artifact_id.to_owned(), to_value(&record));
        Ok(true)
    }

    async fn lock_signer(&mut self, signer_id: &str) -> RelayResult<Option<SignerRecord>> {
        read(&self.staged.signers, signer_id, SignerRecord::parse)
    }

    async fn lock_signer_by_profile_hash(
        &mut self,
        profile_hash: &str,
    ) -> RelayResult<Option<SignerRecord>> {
        let mut found = None;
        for value in self.staged.signers.values() {
            let record = SignerRecord::parse(value)?;
            if record.profile_hash == profile_hash {
                found = Some(record);
            }
        }
        Ok(found)
    }

    async fn list_signers_by_authenticator(
        &mut self,
        authenticator_id_hash: &str,
    ) -> RelayResult<Vec<SignerRecord>> {
        let mut signers = Vec::new();
        for value in self.staged.signers.values() {
            let record = SignerRecord::parse(value)?;
            if record.authenticator_id_hash()?.as_deref() == Some(authenticator_id_hash) {
                signers.push(record);
            }
        }
        signers.sort_by(|a, b| (a.created_at, &a.signer_id).cmp(&(b.created_at, &b.signer_id)));
        Ok(signers)
    }

    async fn insert_signer(&mut self, record: &SignerRecord) -> RelayResult<bool> {
        if self
            .lock_signer_by_profile_hash(&record.profile_hash)
            .await?
            .is_some()
        {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.signers,
            &record.signer_id,
            to_value(record),
        ))
    }

    async fn list_signer_accounts(
        &mut self,
        signer_id: &str,
    ) -> RelayResult<Vec<(AccountRecord, AccountSignerRecord)>> {
        let mut accounts = Vec::new();
        for value in &self.staged.memberships {
            let membership = AccountSignerRecord::parse(value)?;
            if membership.signer_id != signer_id {
                continue;
            }
            let account = read(
                &self.staged.accounts,
                &membership.account_id,
                AccountRecord::parse,
            )?
            .ok_or(RelayErrorCode::RecordUnreadable)?;
            accounts.push((account, membership));
        }
        accounts.sort_by(|(a, _), (b, _)| {
            (a.created_at, &a.account_id).cmp(&(b.created_at, &b.account_id))
        });
        Ok(accounts)
    }

    async fn insert_account(&mut self, record: &AccountRecord) -> RelayResult<bool> {
        if !self.staged.signers.contains_key(&record.root_signer_id) {
            return Ok(false);
        }
        for value in self.staged.accounts.values() {
            let stored = AccountRecord::parse(value)?;
            if stored.address == record.address
                || (stored.root_signer_id == record.root_signer_id
                    && ((stored.account_index.is_some()
                        && stored.account_index == record.account_index)
                        || (stored.creation_key.is_some()
                            && stored.creation_key == record.creation_key)))
            {
                return Ok(false);
            }
        }
        Ok(insert(
            &mut self.staged.accounts,
            &record.account_id,
            to_value(record),
        ))
    }

    async fn insert_account_signer(&mut self, record: &AccountSignerRecord) -> RelayResult<bool> {
        if !self.staged.accounts.contains_key(&record.account_id)
            || !self.staged.signers.contains_key(&record.signer_id)
        {
            return Ok(false);
        }
        for value in &self.staged.memberships {
            let stored = AccountSignerRecord::parse(value)?;
            if stored.account_id != record.account_id {
                continue;
            }
            let second_root =
                stored.role == MembershipRole::Root && record.role == MembershipRole::Root;
            let repeated = stored.signer_id == record.signer_id
                && stored.role == MembershipRole::Permission
                && stored.request_id == record.request_id
                && stored.link_id == record.link_id;
            if second_root || repeated {
                return Ok(false);
            }
        }
        self.staged.memberships.push(to_value(record));
        Ok(true)
    }

    async fn lock_account(&mut self, account_id: &str) -> RelayResult<Option<AccountRecord>> {
        read(&self.staged.accounts, account_id, AccountRecord::parse)
    }

    async fn lock_account_by_creation_key(
        &mut self,
        root_signer_id: &str,
        creation_key: &str,
    ) -> RelayResult<Option<AccountRecord>> {
        for value in self.staged.accounts.values() {
            let account = AccountRecord::parse(value)?;
            if account.root_signer_id == root_signer_id
                && account.creation_key.as_deref() == Some(creation_key)
            {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    async fn lock_account_by_address(
        &mut self,
        address: &str,
    ) -> RelayResult<Option<AccountRecord>> {
        for value in self.staged.accounts.values() {
            let account = AccountRecord::parse(value)?;
            if account.address == address {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    async fn list_account_signers(
        &mut self,
        account_id: &str,
    ) -> RelayResult<Vec<(SignerRecord, AccountSignerRecord)>> {
        let mut signers = Vec::new();
        for value in &self.staged.memberships {
            let membership = AccountSignerRecord::parse(value)?;
            if membership.account_id != account_id {
                continue;
            }
            let signer = read(
                &self.staged.signers,
                &membership.signer_id,
                SignerRecord::parse,
            )?
            .ok_or(RelayErrorCode::RecordUnreadable)?;
            signers.push((signer, membership));
        }
        signers.sort_by_key(|(signer, membership)| {
            (
                membership.role != MembershipRole::Root,
                membership.created_at,
                signer.signer_id.clone(),
            )
        });
        Ok(signers)
    }

    async fn delete_account_signers(
        &mut self,
        account_id: &str,
        signer_id: &str,
    ) -> RelayResult<bool> {
        let mut kept = Vec::new();
        let mut deleted = false;
        for value in &self.staged.memberships {
            let stored = AccountSignerRecord::parse(value)?;
            if stored.account_id == account_id
                && stored.signer_id == signer_id
                && stored.role == MembershipRole::Permission
            {
                deleted = true;
            } else {
                kept.push(value.clone());
            }
        }
        self.staged.memberships = kept;
        Ok(deleted)
    }

    async fn set_account_signer_status(
        &mut self,
        account_id: &str,
        signer_id: &str,
        status: MembershipStatus,
        at: u64,
    ) -> RelayResult<bool> {
        let mut moved = false;
        for value in &mut self.staged.memberships {
            let mut stored = AccountSignerRecord::parse(value)?;
            if stored.account_id != account_id
                || stored.signer_id != signer_id
                || stored.role != MembershipRole::Permission
                || stored.status == status
            {
                continue;
            }
            match status {
                MembershipStatus::Suspended => stored.suspended_at = Some(at),
                MembershipStatus::Active => stored.restored_at = Some(at),
            }
            stored.status = status;
            *value = to_value(&stored);
            moved = true;
        }
        Ok(moved)
    }

    async fn insert_account_import(&mut self, record: &AccountImportRecord) -> RelayResult<bool> {
        if !self.staged.accounts.contains_key(&record.account_id) {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.account_imports,
            &record.account_id,
            to_value(record),
        ))
    }

    async fn lock_account_import(
        &mut self,
        account_id: &str,
    ) -> RelayResult<Option<AccountImportRecord>> {
        read(
            &self.staged.account_imports,
            account_id,
            AccountImportRecord::parse,
        )
    }

    async fn lock_link_request(&mut self, link_id: &str) -> RelayResult<Option<LinkRequestRecord>> {
        read(
            &self.staged.link_requests,
            link_id,
            LinkRequestRecord::parse,
        )
    }

    async fn insert_link_request(&mut self, record: &LinkRequestRecord) -> RelayResult<bool> {
        if !self.staged.accounts.contains_key(&record.account_id)
            || !self.staged.signers.contains_key(&record.signer_id)
        {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.link_requests,
            &record.link_id,
            to_value(record),
        ))
    }

    async fn decide_link_request(
        &mut self,
        link_id: &str,
        outcome: LinkOutcome,
        approval_signature: Option<&str>,
        grant_id: Option<&str>,
        decided_at: u64,
    ) -> RelayResult<bool> {
        let Some(mut record) = self.lock_link_request(link_id).await? else {
            return Ok(false);
        };
        if record.outcome.is_some() {
            return Ok(false);
        }
        record.outcome = Some(outcome);
        record.decided_at = Some(decided_at);
        record.approval_signature = approval_signature.map(str::to_owned);
        record.grant_id = grant_id.map(str::to_owned);
        // The record parser owns the outcome/signature invariant.
        let value = to_value(&record);
        LinkRequestRecord::parse(&value)?;
        self.staged.link_requests.insert(link_id.to_owned(), value);
        Ok(true)
    }

    async fn list_policy_templates(
        &mut self,
        account_id: &str,
    ) -> RelayResult<Vec<PolicyTemplateRecord>> {
        let mut templates = Vec::new();
        for value in self.staged.policy_templates.values() {
            let template = PolicyTemplateRecord::parse(value)?;
            if template.account_id == account_id {
                templates.push(template);
            }
        }
        templates
            .sort_by(|a, b| (a.created_at, &a.template_id).cmp(&(b.created_at, &b.template_id)));
        Ok(templates)
    }

    async fn lock_policy_template(
        &mut self,
        template_id: &str,
    ) -> RelayResult<Option<PolicyTemplateRecord>> {
        read(
            &self.staged.policy_templates,
            template_id,
            PolicyTemplateRecord::parse,
        )
    }

    async fn insert_policy_template(&mut self, record: &PolicyTemplateRecord) -> RelayResult<bool> {
        if !self.staged.accounts.contains_key(&record.account_id) {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.policy_templates,
            &record.template_id,
            to_value(record),
        ))
    }

    async fn update_policy_template(&mut self, record: &PolicyTemplateRecord) -> RelayResult<bool> {
        let Some(stored) = self.lock_policy_template(&record.template_id).await? else {
            return Ok(false);
        };
        if stored.account_id != record.account_id {
            return Ok(false);
        }
        self.staged
            .policy_templates
            .insert(record.template_id.clone(), to_value(record));
        Ok(true)
    }

    async fn delete_policy_template(&mut self, template_id: &str) -> RelayResult<bool> {
        Ok(self.staged.policy_templates.remove(template_id).is_some())
    }

    async fn remove_link_request(&mut self, link_id: &str, removed_at: u64) -> RelayResult<bool> {
        let Some(mut record) = self.lock_link_request(link_id).await? else {
            return Ok(false);
        };
        if record.outcome != Some(LinkOutcome::Approved) || record.removed_at.is_some() {
            return Ok(false);
        }
        record.removed_at = Some(removed_at);
        self.staged
            .link_requests
            .insert(link_id.to_owned(), to_value(&record));
        Ok(true)
    }

    async fn lock_oauth_client(
        &mut self,
        client_id: &str,
    ) -> RelayResult<Option<OAuthClientRecord>> {
        read(
            &self.staged.oauth_clients,
            client_id,
            OAuthClientRecord::parse,
        )
    }

    async fn insert_oauth_client(&mut self, record: &OAuthClientRecord) -> RelayResult<bool> {
        Ok(insert(
            &mut self.staged.oauth_clients,
            &record.client_id,
            to_value(record),
        ))
    }

    async fn lock_par(&mut self, par_id: &str) -> RelayResult<Option<ParRecord>> {
        read(&self.staged.pars, par_id, ParRecord::parse)
    }

    async fn insert_par(&mut self, record: &ParRecord) -> RelayResult<bool> {
        if !self.staged.oauth_clients.contains_key(&record.client_id) {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.pars,
            &record.par_id,
            to_value(record),
        ))
    }

    async fn lock_access_token(
        &mut self,
        token_hash: &str,
    ) -> RelayResult<Option<AccessTokenRecord>> {
        read(
            &self.staged.access_tokens,
            token_hash,
            AccessTokenRecord::parse,
        )
    }

    async fn insert_access_token(&mut self, record: &AccessTokenRecord) -> RelayResult<bool> {
        if !self.staged.oauth_clients.contains_key(&record.client_id)
            || !self.staged.requests.contains_key(&record.request_id)
        {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.access_tokens,
            &record.token_hash,
            to_value(record),
        ))
    }

    async fn revoke_access_token(
        &mut self,
        token_hash: &str,
        revoked_at: u64,
    ) -> RelayResult<bool> {
        let Some(mut record) = read(
            &self.staged.access_tokens,
            token_hash,
            AccessTokenRecord::parse,
        )?
        else {
            return Ok(false);
        };
        if record.revoked_at.is_some() {
            return Ok(false);
        }
        record.revoked_at = Some(revoked_at);
        self.staged
            .access_tokens
            .insert(token_hash.to_owned(), to_value(&record));
        Ok(true)
    }

    async fn lock_portal_challenge(
        &mut self,
        nonce: &str,
    ) -> RelayResult<Option<PortalChallengeRecord>> {
        read(
            &self.staged.portal_challenges,
            nonce,
            PortalChallengeRecord::parse,
        )
    }

    async fn insert_portal_challenge(
        &mut self,
        record: &PortalChallengeRecord,
    ) -> RelayResult<bool> {
        Ok(insert(
            &mut self.staged.portal_challenges,
            &record.nonce,
            to_value(record),
        ))
    }

    async fn consume_portal_challenge(
        &mut self,
        nonce: &str,
        consumed_at: u64,
    ) -> RelayResult<bool> {
        let Some(mut record) = self.lock_portal_challenge(nonce).await? else {
            return Ok(false);
        };
        if record.consumed_at.is_some() {
            return Ok(false);
        }
        record.consumed_at = Some(consumed_at);
        self.staged
            .portal_challenges
            .insert(nonce.to_owned(), to_value(&record));
        Ok(true)
    }

    async fn lock_portal_session(
        &mut self,
        token_hash: &str,
    ) -> RelayResult<Option<PortalSessionRecord>> {
        read(
            &self.staged.portal_sessions,
            token_hash,
            PortalSessionRecord::parse,
        )
    }

    async fn insert_portal_session(&mut self, record: &PortalSessionRecord) -> RelayResult<bool> {
        if !self.staged.signers.contains_key(&record.signer_id) {
            return Ok(false);
        }
        Ok(insert(
            &mut self.staged.portal_sessions,
            &record.token_hash,
            to_value(record),
        ))
    }

    async fn end_portal_session(
        &mut self,
        token_hash: &str,
        signed_out_at: u64,
    ) -> RelayResult<bool> {
        let Some(mut record) = self.lock_portal_session(token_hash).await? else {
            return Ok(false);
        };
        if record.signed_out_at.is_some() {
            return Ok(false);
        }
        record.signed_out_at = Some(signed_out_at);
        self.staged
            .portal_sessions
            .insert(token_hash.to_owned(), to_value(&record));
        Ok(true)
    }

    async fn commit(self: Box<Self>) -> RelayResult<()> {
        let MemoryTransaction { mut guard, staged } = *self;
        *guard = staged;
        Ok(())
    }

    async fn rollback(self: Box<Self>) {}
}
