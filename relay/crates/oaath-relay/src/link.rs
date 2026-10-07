//! Adding a signer to an existing account: a link request from the new
//! signer, one root signature over an OAAth membership approval, and the
//! root's removal of a member.
//!
//! ```text
//! POST   /portal/links                          {signer_id, account, label} -> {link_id, expires_at}
//! GET    /portal/links/{id}                                                 -> link view
//! POST   /portal/links/{id}/approve             {signature}                 -> link view
//! POST   /portal/links/{id}/reject              {}                          -> link view
//! GET    /portal/accounts/{id}/members                                      -> {members: [...]}
//! DELETE /portal/accounts/{id}/members/{signer}                             -> {removed: n}
//! ```
//!
//! ```text
//! state and owner      link: pending -> approved | rejected (once, by the
//!                      account's root) | expired (by time, never written);
//!                      approved -> removed (once, by the root)
//! persisted evidence   oaath_link_request_v1 with the root's approval
//!                      signature; the typed data is rebuilt from the record
//! resource occupied?   a decided link never decides again; an approved link
//!                      owns one permission membership until it is removed
//! retry safe?          approve, reject and remove each decide in one
//!                      transaction on the locked link; a lost reply is read
//!                      back with GET, never re-signed
//! forbidden            an approver who is not the account's root; a decided,
//!                      removed or expired link; a signature by another key or
//!                      over other data; a link for a signer that is already a
//!                      member; removing the root
//! crash/reload         every transition commits with its membership change
//! cleanup owner        expiry; the root's removal. A removed grant member's
//!                      capability is invalidated by the existing owner
//!                      (`authorization/invalidation.rs`) in the same
//!                      transaction; on-chain revocation stays separate
//! ```
//!
//! A link admits the signer as a login-only member: it can sign in as the
//! account and holds no on-chain authority. The root approves exactly this
//! EIP-712 message, which binds the account, the new signer's
//! owner-credential profile hash, the role, the link's lifetime, and the link
//! id as a single-use nonce:
//!
//! ```text
//! domain  { name: "OAAth", version: "1" }
//! MembershipApproval(address account,bytes32 signerProfileHash,string role,
//!                    uint64 issuedAt,uint64 expiresAt,string nonce)
//! ```
//!
//! The root signs it like a grant's install digest (`grant/signature.rs`): an
//! ECDSA root over the EIP-712 digest (`eth_signTypedData_v4`), a P-256 root
//! over the digest, and a WebAuthn root asserting with challenge = digest for
//! the issuer's rpId and origin.

use alloy_primitives::{Address, B256};
use alloy_sol_types::{Eip712Domain, SolStruct, eip712_domain, sol};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::authentication::{RelayCaller, RelayCallerRole};
use crate::authorization::challenge::random_identifier;
use crate::authorization::invalidation::invalidate;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::signature::{RelyingParty, verify_root_signature};
use crate::kms::RelayKms;
use crate::oauth::grant::{granted_capability, relying_party};
use crate::records::{bounded_text, canonical_identifier, canonical_str, exact_record, timestamp};
use crate::registry::{
    ACCOUNT_SIGNER_RECORD_VERSION, AccountRecord, AccountSignerRecord, MembershipRole,
};
use crate::store::{RelayStore, RelayTransaction, settle};

pub const LINK_REQUEST_RECORD_VERSION: &str = "oaath.link-request-record/v1";
pub const LINK_TTL_MS: u64 = 3_600_000;
/// The role a link admits a signer with.
pub const LINK_ROLE: &str = "permission";
const MAX_LABEL: usize = 64;
/// A WebAuthn assertion envelope stays well inside this many hex digits.
const MAX_SIGNATURE_HEX: usize = 16_384;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;
const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

sol! {
    /// The OAAth membership approval an account's root signs.
    struct MembershipApproval {
        address account;
        bytes32 signerProfileHash;
        string role;
        uint64 issuedAt;
        uint64 expiresAt;
        string nonce;
    }
}

const DOMAIN: Eip712Domain = eip712_domain! { name: "OAAth", version: "1", };

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkOutcome {
    Approved,
    Rejected,
}

/// One request to add `signer_id` to `account_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkRequestRecord {
    pub version: &'static str,
    pub link_id: String,
    pub account_id: String,
    pub signer_id: String,
    /// The requester's own name for the new signer, shown to the root.
    pub label: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub outcome: Option<LinkOutcome>,
    pub decided_at: Option<u64>,
    /// The root's signature over the membership approval; set exactly when
    /// the outcome is `approved`.
    pub approval_signature: Option<String>,
    /// Set once, by the root's removal of an approved member.
    pub removed_at: Option<u64>,
}

fn nullable_timestamp(value: Option<&Value>) -> RelayResult<Option<u64>> {
    match value {
        Some(Value::Null) => Ok(None),
        other => timestamp(other, UNREADABLE).map(Some),
    }
}

fn signature_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x")?;
    if digits.is_empty()
        || digits.len() > MAX_SIGNATURE_HEX
        || digits.bytes().any(|b| b.is_ascii_uppercase())
    {
        return None;
    }
    hex::decode(digits).ok()
}

impl LinkRequestRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "linkId",
                "accountId",
                "signerId",
                "label",
                "createdAt",
                "expiresAt",
                "outcome",
                "decidedAt",
                "approvalSignature",
                "removedAt",
            ],
            UNREADABLE,
        )?;
        if r.get("version").and_then(Value::as_str) != Some(LINK_REQUEST_RECORD_VERSION) {
            return Err(UNREADABLE);
        }
        let outcome = match r.get("outcome") {
            Some(Value::Null) => None,
            Some(Value::String(text)) if text == "approved" => Some(LinkOutcome::Approved),
            Some(Value::String(text)) if text == "rejected" => Some(LinkOutcome::Rejected),
            _ => return Err(UNREADABLE),
        };
        let approval_signature = match r.get("approvalSignature") {
            Some(Value::Null) => None,
            Some(Value::String(text)) if signature_hex(text).is_some() => Some(text.clone()),
            _ => return Err(UNREADABLE),
        };
        let record = Self {
            version: LINK_REQUEST_RECORD_VERSION,
            link_id: canonical_identifier(r.get("linkId"), UNREADABLE)?.to_owned(),
            account_id: canonical_identifier(r.get("accountId"), UNREADABLE)?.to_owned(),
            signer_id: canonical_identifier(r.get("signerId"), UNREADABLE)?.to_owned(),
            label: bounded_text(r.get("label"), MAX_LABEL, UNREADABLE)?.to_owned(),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            expires_at: timestamp(r.get("expiresAt"), UNREADABLE)?,
            outcome,
            decided_at: nullable_timestamp(r.get("decidedAt"))?,
            approval_signature,
            removed_at: nullable_timestamp(r.get("removedAt"))?,
        };
        let approved = record.outcome == Some(LinkOutcome::Approved);
        if record.expires_at <= record.created_at
            || record.outcome.is_some() != record.decided_at.is_some()
            || approved != record.approval_signature.is_some()
            || (record.removed_at.is_some() && !approved)
        {
            return Err(UNREADABLE);
        }
        Ok(record)
    }

    /// `pending`, `approved`, `rejected`, `expired`, or `removed` at `now`.
    pub fn status(&self, now: u64) -> &'static str {
        match (self.outcome, self.removed_at) {
            (_, Some(_)) => "removed",
            (Some(LinkOutcome::Approved), None) => "approved",
            (Some(LinkOutcome::Rejected), None) => "rejected",
            (None, None) if now >= self.expires_at => "expired",
            (None, None) => "pending",
        }
    }
}

/// The membership approval for `link`, adding `signer_profile_hash` to
/// `account`.
pub fn membership_approval(
    link: &LinkRequestRecord,
    account: &AccountRecord,
    signer_profile_hash: &str,
) -> RelayResult<MembershipApproval> {
    Ok(MembershipApproval {
        account: account.address.parse::<Address>().map_err(|_| UNREADABLE)?,
        signerProfileHash: signer_profile_hash
            .parse::<B256>()
            .map_err(|_| UNREADABLE)?,
        role: LINK_ROLE.to_owned(),
        issuedAt: link.created_at / 1_000,
        expiresAt: link.expires_at / 1_000,
        nonce: link.link_id.clone(),
    })
}

/// The `eth_signTypedData_v4` payload and its EIP-712 digest.
pub fn typed_data(approval: &MembershipApproval) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
            ],
            "MembershipApproval": [
                { "name": "account", "type": "address" },
                { "name": "signerProfileHash", "type": "bytes32" },
                { "name": "role", "type": "string" },
                { "name": "issuedAt", "type": "uint64" },
                { "name": "expiresAt", "type": "uint64" },
                { "name": "nonce", "type": "string" },
            ],
        },
        "primaryType": "MembershipApproval",
        "domain": { "name": "OAAth", "version": "1" },
        "message": {
            "account": format!("{:#x}", approval.account),
            "signerProfileHash": format!("{:#x}", approval.signerProfileHash),
            "role": approval.role,
            "issuedAt": approval.issuedAt,
            "expiresAt": approval.expiresAt,
            "nonce": approval.nonce,
        },
    })
}

pub fn approval_digest(approval: &MembershipApproval) -> B256 {
    approval.eip712_signing_hash(&DOMAIN)
}

#[derive(Debug, Serialize)]
pub struct CreatedLink {
    pub link_id: String,
    /// Unix seconds.
    pub expires_at: u64,
}

/// The new signer (`session`) asks to join the account at `account`.
pub async fn create_link(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<CreatedLink> {
    exact_record(
        &Value::Object(body.clone()),
        &["signer_id", "account", "label"],
        INVALID,
    )?;
    let signer_id = canonical_identifier(body.get("signer_id"), INVALID)?;
    if signer_id != session {
        return Err(RelayErrorCode::Forbidden);
    }
    let address = body
        .get("account")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<Address>().ok())
        .ok_or(INVALID)?;
    let label = bounded_text(body.get("label"), MAX_LABEL, INVALID)?.trim();
    if label.is_empty() {
        return Err(INVALID);
    }
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let account = transaction
            .lock_account_by_address(&format!("{address:#x}"))
            .await?
            .ok_or(RelayErrorCode::NotFound)?;
        if is_member(&mut *transaction, signer_id, &account.account_id).await? {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        let link = LinkRequestRecord {
            version: LINK_REQUEST_RECORD_VERSION,
            link_id: random_identifier(),
            account_id: account.account_id,
            signer_id: signer_id.to_owned(),
            label: label.to_owned(),
            created_at: now,
            expires_at: now + LINK_TTL_MS,
            outcome: None,
            decided_at: None,
            approval_signature: None,
            removed_at: None,
        };
        if !transaction.insert_link_request(&link).await? {
            return Err(RelayErrorCode::Internal);
        }
        Ok(link)
    }
    .await;
    let link = settle(transaction, result).await?;
    Ok(CreatedLink {
        link_id: link.link_id,
        expires_at: link.expires_at / 1_000,
    })
}

async fn is_member(
    transaction: &mut dyn RelayTransaction,
    signer_id: &str,
    account_id: &str,
) -> RelayResult<bool> {
    Ok(transaction
        .list_signer_accounts(signer_id)
        .await?
        .iter()
        .any(|(account, _)| account.account_id == account_id))
}

#[derive(Debug, Serialize)]
pub struct LinkSigner {
    pub signer_id: String,
    pub kind: &'static str,
    pub profile: Value,
    pub profile_hash: String,
}

#[derive(Debug, Serialize)]
pub struct LinkView {
    pub link_id: String,
    /// `pending`, `approved`, `rejected`, `expired`, or `removed`.
    pub status: &'static str,
    pub account_id: String,
    pub address: String,
    pub signer: LinkSigner,
    pub label: String,
    pub role: &'static str,
    /// Unix seconds.
    pub expires_at: u64,
    /// What the root signs: the `eth_signTypedData_v4` payload and its digest.
    pub typed_data: Value,
    pub digest: String,
}

struct Locked {
    link: LinkRequestRecord,
    account: AccountRecord,
    view: LinkView,
}

/// Locks the link and its account. Only the requesting signer and the
/// account's root may see it.
async fn locked(
    transaction: &mut dyn RelayTransaction,
    link_id: &str,
    session: &str,
    now: u64,
) -> RelayResult<Locked> {
    let link = transaction
        .lock_link_request(link_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let account = transaction
        .lock_account(&link.account_id)
        .await?
        .ok_or(UNREADABLE)?;
    if session != link.signer_id && session != account.root_signer_id {
        return Err(RelayErrorCode::Forbidden);
    }
    let signer = transaction
        .lock_signer(&link.signer_id)
        .await?
        .ok_or(UNREADABLE)?;
    let credential = signer.credential()?;
    let approval = membership_approval(&link, &account, &signer.profile_hash)?;
    let view = LinkView {
        link_id: link.link_id.clone(),
        status: link.status(now),
        account_id: account.account_id.clone(),
        address: account.address.clone(),
        signer: LinkSigner {
            signer_id: signer.signer_id,
            kind: credential.kind(),
            profile: credential.to_json(),
            profile_hash: signer.profile_hash,
        },
        label: link.label.clone(),
        role: LINK_ROLE,
        expires_at: link.expires_at / 1_000,
        typed_data: typed_data(&approval),
        digest: format!("{:#x}", approval_digest(&approval)),
    };
    Ok(Locked {
        link,
        account,
        view,
    })
}

pub async fn read_link(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    link_id: &str,
    session: &str,
) -> RelayResult<LinkView> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = locked(&mut *transaction, link_id, session, now).await;
    Ok(settle(transaction, result).await?.view)
}

/// The account's root decides a pending, unexpired link: an approval must be
/// its signature over the link's membership approval.
pub async fn decide_link(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    issuer: &str,
    link_id: &str,
    body: &Map<String, Value>,
    session: &str,
    outcome: LinkOutcome,
) -> RelayResult<LinkView> {
    let signature = match outcome {
        LinkOutcome::Approved => {
            exact_record(&Value::Object(body.clone()), &["signature"], INVALID)?;
            let text = body
                .get("signature")
                .and_then(Value::as_str)
                .ok_or(INVALID)?;
            Some((text.to_owned(), signature_hex(text).ok_or(INVALID)?))
        }
        LinkOutcome::Rejected => {
            exact_record(&Value::Object(body.clone()), &[], INVALID)?;
            None
        }
    };
    let (rp_id, origin) = relying_party(issuer)?;
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let Locked {
            link,
            account,
            mut view,
        } = locked(&mut *transaction, link_id, session, now).await?;
        if session != account.root_signer_id {
            return Err(RelayErrorCode::Forbidden);
        }
        if link.outcome.is_some() {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        if now >= link.expires_at {
            return Err(RelayErrorCode::Expired);
        }
        if let Some((_, bytes)) = &signature {
            let root = transaction
                .lock_signer(&account.root_signer_id)
                .await?
                .ok_or(UNREADABLE)?;
            let digest: B256 = view.digest.parse().map_err(|_| RelayErrorCode::Internal)?;
            let relying_party = RelyingParty {
                rp_id: &rp_id,
                origin: &origin,
            };
            if !verify_root_signature(&root.credential()?, digest, bytes, &relying_party) {
                return Err(RelayErrorCode::Forbidden);
            }
            if is_member(&mut *transaction, &link.signer_id, &account.account_id).await? {
                return Err(RelayErrorCode::AlreadyDecided);
            }
            let joined = transaction
                .insert_account_signer(&AccountSignerRecord {
                    version: ACCOUNT_SIGNER_RECORD_VERSION,
                    account_id: account.account_id.clone(),
                    signer_id: link.signer_id.clone(),
                    role: MembershipRole::Permission,
                    request_id: None,
                    link_id: Some(link.link_id.clone()),
                    created_at: now,
                })
                .await?;
            if !joined {
                return Err(RelayErrorCode::Internal);
            }
        }
        let decided = transaction
            .decide_link_request(
                &link.link_id,
                outcome,
                signature.as_ref().map(|(text, _)| text.as_str()),
                now,
            )
            .await?;
        if !decided {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        view.status = match outcome {
            LinkOutcome::Approved => "approved",
            LinkOutcome::Rejected => "rejected",
        };
        Ok(view)
    }
    .await;
    settle(transaction, result).await
}

#[derive(Debug, Serialize)]
pub struct Member {
    pub signer_id: String,
    pub kind: &'static str,
    pub profile: Value,
    pub role: MembershipRole,
    /// The link that admitted a login-only member, with its label.
    pub link_id: Option<String>,
    pub label: Option<String>,
    /// The grant that admitted a policy-bound member.
    pub grant_id: Option<String>,
    /// Unix seconds.
    pub joined_at: u64,
}

#[derive(Debug, Serialize)]
pub struct Members {
    pub members: Vec<Member>,
}

async fn root_account(
    transaction: &mut dyn RelayTransaction,
    account_id: &str,
    session: &str,
) -> RelayResult<AccountRecord> {
    let account = transaction
        .lock_account(account_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    if account.root_signer_id != session {
        return Err(RelayErrorCode::Forbidden);
    }
    Ok(account)
}

/// Every signer of the account, for its root.
pub async fn list_members(
    store: &dyn RelayStore,
    account_id: &str,
    session: &str,
) -> RelayResult<Members> {
    let mut transaction = store.begin().await?;
    let result = async {
        root_account(&mut *transaction, account_id, session).await?;
        let mut members = Vec::new();
        for (signer, membership) in transaction.list_account_signers(account_id).await? {
            let label = match &membership.link_id {
                Some(link_id) => Some(
                    transaction
                        .lock_link_request(link_id)
                        .await?
                        .ok_or(UNREADABLE)?
                        .label,
                ),
                None => None,
            };
            let credential = signer.credential()?;
            members.push(Member {
                signer_id: signer.signer_id,
                kind: credential.kind(),
                profile: credential.to_json(),
                role: membership.role,
                link_id: membership.link_id,
                label,
                grant_id: membership.request_id,
                joined_at: membership.created_at / 1_000,
            });
        }
        Ok(Members { members })
    }
    .await;
    settle(transaction, result).await
}

#[derive(Debug, Serialize)]
pub struct RemovedMember {
    /// Memberships removed: one per link or grant that admitted the signer.
    pub removed: usize,
}

/// The root removes a member: each link it joined through is marked removed,
/// each grant's capability is invalidated, and the memberships are deleted,
/// in one transaction. Nothing happens on-chain.
pub async fn remove_member(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    account_id: &str,
    signer_id: &str,
    session: &str,
) -> RelayResult<RemovedMember> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        root_account(&mut *transaction, account_id, session).await?;
        let memberships: Vec<AccountSignerRecord> = transaction
            .list_account_signers(account_id)
            .await?
            .into_iter()
            .map(|(_, membership)| membership)
            .filter(|membership| membership.signer_id == signer_id)
            .collect();
        if memberships.is_empty() {
            return Err(RelayErrorCode::NotFound);
        }
        if memberships
            .iter()
            .any(|membership| membership.role == MembershipRole::Root)
        {
            return Err(INVALID);
        }
        for membership in &memberships {
            if let Some(link_id) = &membership.link_id
                && !transaction.remove_link_request(link_id, now).await?
            {
                return Err(UNREADABLE);
            }
            if let Some(grant_id) = &membership.request_id
                && let Some((client_id, capability_hash)) =
                    granted_capability(&mut *transaction, kms, grant_id).await?
            {
                let caller = RelayCaller {
                    role: RelayCallerRole::Client,
                    client_id: client_id.clone(),
                    subject: client_id,
                    redirect_uris: Vec::new(),
                    organization_audience: None,
                };
                invalidate(
                    &mut *transaction,
                    clock,
                    &caller,
                    grant_id,
                    &capability_hash,
                )
                .await?;
            }
        }
        if !transaction
            .delete_account_signers(account_id, signer_id)
            .await?
        {
            return Err(UNREADABLE);
        }
        Ok(RemovedMember {
            removed: memberships.len(),
        })
    }
    .await;
    settle(transaction, result).await
}

/// A path segment naming a link or signer.
pub fn identifier_segment(segment: Option<&str>) -> RelayResult<&str> {
    canonical_str(segment.unwrap_or_default(), INVALID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_the_membership_approval_as_eip_712() {
        let approval = MembershipApproval {
            account: "0x00000000000000000000000000000000000000aa"
                .parse()
                .unwrap(),
            signerProfileHash: B256::repeat_byte(0x11),
            role: LINK_ROLE.to_owned(),
            issuedAt: 1_700_000_000,
            expiresAt: 1_700_003_600,
            nonce: "link-1".to_owned(),
        };
        // Pinned against viem's hashTypedData over typed_data(&approval).
        assert_eq!(
            format!("{:#x}", approval_digest(&approval)),
            "0xcbf4b3c065f0db08b9d5f25feb449f6e17501f2eb140718903bdf231679283d6"
        );
    }
}
