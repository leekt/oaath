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
//! POST   /portal/accounts/{id}/members/{signer}/suspend|restore  {}         -> {signer_id, status}
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
//! members              the root suspends a member (active -> suspended, its
//!                      grants invalidated in the same transaction) and
//!                      restores it (suspended -> active, grants stay
//!                      invalidated); each move once; never the root
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
use oaath_protocol::permission::PermissionRequest;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::authentication::{RelayCaller, RelayCallerRole};
use crate::authorization::challenge::random_identifier;
use crate::authorization::invalidation::invalidate;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::signature::{RelyingParty, verify_root_signature};
use crate::kms::{RelayKms, seal_artifact};
use crate::member_grant::{
    MemberGrant, compose_member_request, prepared, record_member_grant, template_selection,
    verify_member_approval,
};
use crate::oauth::PreparedGrant;
use crate::oauth::grant::{granted_capability, relying_party};
use crate::oauth::pending::retire_member_requests;
use crate::policy::root_template;
use crate::records::{bounded_text, canonical_identifier, canonical_str, exact_record, timestamp};
use crate::registry::{
    ACCOUNT_SIGNER_RECORD_VERSION, AccountRecord, AccountSignerRecord, MembershipRole,
    MembershipStatus,
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

pub(crate) const DOMAIN: Eip712Domain = eip712_domain! { name: "OAAth", version: "1", };

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
    /// An approval's evidence, exactly one of: the root's signature over the
    /// membership approval (login only), or the grant whose enable the root
    /// signed (named by the link id; `member_grant.rs`).
    pub approval_signature: Option<String>,
    pub grant_id: Option<String>,
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
                "grantId",
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
            grant_id: match r.get("grantId") {
                Some(Value::Null) => None,
                other => Some(canonical_identifier(other, UNREADABLE)?.to_owned()),
            },
            removed_at: nullable_timestamp(r.get("removedAt"))?,
        };
        let approved = record.outcome == Some(LinkOutcome::Approved);
        if record.expires_at <= record.created_at
            || record.outcome.is_some() != record.decided_at.is_some()
            || usize::from(approved)
                != usize::from(record.approval_signature.is_some())
                    + usize::from(record.grant_id.is_some())
            || record
                .grant_id
                .as_ref()
                .is_some_and(|id| *id != record.link_id)
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
            grant_id: None,
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
    /// The member's grant, when the root approved with a policy template.
    pub grant_id: Option<String>,
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
        grant_id: link.grant_id.clone(),
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
#[allow(clippy::too_many_arguments)]
pub async fn decide_link(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    issuer: &str,
    link_id: &str,
    body: &Map<String, Value>,
    session: &str,
    outcome: LinkOutcome,
) -> RelayResult<LinkView> {
    let approval = match outcome {
        LinkOutcome::Approved if body.contains_key("signature") => {
            exact_record(&Value::Object(body.clone()), &["signature"], INVALID)?;
            let text = body
                .get("signature")
                .and_then(Value::as_str)
                .ok_or(INVALID)?;
            Some(LinkApproval::Membership(
                text.to_owned(),
                signature_hex(text).ok_or(INVALID)?,
            ))
        }
        LinkOutcome::Approved => {
            exact_record(
                &Value::Object(body.clone()),
                &["template_id", "artifact"],
                INVALID,
            )?;
            Some(LinkApproval::Grant {
                template_id: canonical_identifier(body.get("template_id"), INVALID)?.to_owned(),
                artifact: body
                    .get("artifact")
                    .and_then(Value::as_str)
                    .ok_or(INVALID)?
                    .to_owned(),
            })
        }
        LinkOutcome::Rejected => {
            exact_record(&Value::Object(body.clone()), &[], INVALID)?;
            None
        }
    };
    let (rp_id, origin) = relying_party(issuer)?;
    let now = relay_now(clock)?;
    // A policy approval is verified, and its artifact sealed, before the write.
    let sealed = match &approval {
        Some(LinkApproval::Grant {
            template_id,
            artifact,
        }) => {
            let mut transaction = store.begin().await?;
            let result = link_grant_request(
                &mut *transaction,
                issuer,
                link_id,
                template_id,
                session,
                now,
            )
            .await;
            let (request, account) = settle(transaction, result).await?;
            verify_member_approval(issuer, &request, &account, artifact, now)?;
            Some((request, seal_artifact(kms, artifact).await?))
        }
        _ => None,
    };
    let mut transaction = store.begin().await?;
    let result = async {
        let Locked {
            link,
            account,
            mut view,
        } = pending_for_root(&mut *transaction, link_id, session, now).await?;
        match &approval {
            None => {}
            Some(LinkApproval::Membership(_, bytes)) => {
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
            }
            Some(LinkApproval::Grant { template_id, .. }) => {
                let (request, artifact_ref) = sealed.as_ref().ok_or(RelayErrorCode::Internal)?;
                // The template may have changed since verification: recompose.
                let (recomposed, _) = link_grant_request(
                    &mut *transaction,
                    issuer,
                    link_id,
                    template_id,
                    session,
                    now,
                )
                .await?;
                if recomposed.hash() != request.hash() {
                    return Err(INVALID);
                }
                if is_member(&mut *transaction, &link.signer_id, &account.account_id).await? {
                    return Err(RelayErrorCode::AlreadyDecided);
                }
                record_member_grant(
                    &mut *transaction,
                    request,
                    &account,
                    &link.signer_id,
                    artifact_ref,
                    now,
                )
                .await?;
            }
        }
        if approval.is_some() {
            if approval_is_membership(&approval)
                && is_member(&mut *transaction, &link.signer_id, &account.account_id).await?
            {
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
                    status: MembershipStatus::Active,
                    suspended_at: None,
                    restored_at: None,
                })
                .await?;
            if !joined {
                return Err(RelayErrorCode::Internal);
            }
        }
        let (signature, grant_id) = match &approval {
            Some(LinkApproval::Membership(text, _)) => (Some(text.as_str()), None),
            Some(LinkApproval::Grant { .. }) => (None, Some(link.link_id.as_str())),
            None => (None, None),
        };
        let decided = transaction
            .decide_link_request(&link.link_id, outcome, signature, grant_id, now)
            .await?;
        if !decided {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        view.status = match outcome {
            LinkOutcome::Approved => "approved",
            LinkOutcome::Rejected => "rejected",
        };
        view.grant_id = grant_id.map(str::to_owned);
        Ok(view)
    }
    .await;
    settle(transaction, result).await
}

/// How the root approves a link: the membership approval (login only), or
/// a template's grant whose enable is the root's one signature.
enum LinkApproval {
    Membership(String, Vec<u8>),
    Grant {
        template_id: String,
        artifact: String,
    },
}

fn approval_is_membership(approval: &Option<LinkApproval>) -> bool {
    matches!(approval, Some(LinkApproval::Membership(..)))
}

/// The link, locked for its account's root while still pending.
async fn pending_for_root(
    transaction: &mut dyn RelayTransaction,
    link_id: &str,
    session: &str,
    now: u64,
) -> RelayResult<Locked> {
    let locked = locked(transaction, link_id, session, now).await?;
    if session != locked.account.root_signer_id {
        return Err(RelayErrorCode::Forbidden);
    }
    if locked.link.outcome.is_some() {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    if now >= locked.link.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    Ok(locked)
}

/// The grant request a template approval of this link signs: the link's id
/// and creation time, the new signer, and the template.
async fn link_grant_request(
    transaction: &mut dyn RelayTransaction,
    issuer: &str,
    link_id: &str,
    template_id: &str,
    session: &str,
    now: u64,
) -> RelayResult<(PermissionRequest, AccountRecord)> {
    let Locked { link, account, .. } = pending_for_root(transaction, link_id, session, now).await?;
    let template = root_template(transaction, &account.account_id, template_id, session).await?;
    let member = transaction
        .lock_signer(&link.signer_id)
        .await?
        .ok_or(UNREADABLE)?;
    let request = compose_member_request(
        issuer,
        &MemberGrant {
            request_id: &link.link_id,
            requested_at: link.created_at / 1_000,
            account: &account,
            member: &member,
            template: &template,
        },
    )?;
    Ok((request, account))
}

/// What the root signs to approve this link with `{template_id}`.
pub async fn prepare_link_grant(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    issuer: &str,
    link_id: &str,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<PreparedGrant> {
    let template_id = template_selection(body)?;
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = link_grant_request(
        &mut *transaction,
        issuer,
        link_id,
        template_id,
        session,
        now,
    )
    .await;
    let (request, account) = settle(transaction, result).await?;
    prepared(&request, &account.address)
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
    pub status: MembershipStatus,
    /// Unix seconds of the latest suspension, if any.
    pub suspended_at: Option<u64>,
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
                status: membership.status,
                suspended_at: membership.suspended_at.map(|at| at / 1_000),
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
        let memberships = member_rows(&mut *transaction, account_id, signer_id, session).await?;
        for membership in &memberships {
            if let Some(link_id) = &membership.link_id
                && !transaction.remove_link_request(link_id, now).await?
            {
                return Err(UNREADABLE);
            }
        }
        retire_grants(
            &mut *transaction,
            clock,
            kms,
            account_id,
            signer_id,
            &memberships,
            now,
        )
        .await?;
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

/// The signer's memberships of the root's account; never the root's own.
async fn member_rows(
    transaction: &mut dyn RelayTransaction,
    account_id: &str,
    signer_id: &str,
    session: &str,
) -> RelayResult<Vec<AccountSignerRecord>> {
    root_account(transaction, account_id, session).await?;
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
    Ok(memberships)
}

/// Invalidates every live grant that admitted these memberships or that the
/// member asked the root for, and rejects its undecided requests, through
/// the existing capability-invalidation owner, in the caller's transaction.
async fn retire_grants(
    transaction: &mut dyn RelayTransaction,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    account_id: &str,
    signer_id: &str,
    memberships: &[AccountSignerRecord],
    now: u64,
) -> RelayResult<()> {
    let mut grant_ids: Vec<String> = memberships
        .iter()
        .filter_map(|membership| membership.request_id.clone())
        .collect();
    grant_ids.extend(retire_member_requests(&mut *transaction, account_id, signer_id, now).await?);
    grant_ids.sort();
    grant_ids.dedup();
    for grant_id in &grant_ids {
        if let Some((client_id, capability_hash)) =
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
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct MemberStanding {
    pub signer_id: String,
    pub status: MembershipStatus,
}

/// The root suspends a member (it can no longer sign in as the account, and
/// its grants on the account are invalidated) or restores it (it can sign in
/// again; invalidated grants stay invalidated). Each move happens once.
pub async fn set_member_status(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    account_id: &str,
    signer_id: &str,
    session: &str,
    status: MembershipStatus,
) -> RelayResult<MemberStanding> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let memberships = member_rows(&mut *transaction, account_id, signer_id, session).await?;
        if status == MembershipStatus::Suspended {
            retire_grants(
                &mut *transaction,
                clock,
                kms,
                account_id,
                signer_id,
                &memberships,
                now,
            )
            .await?;
        }
        if !transaction
            .set_account_signer_status(account_id, signer_id, status, now)
            .await?
        {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        Ok(MemberStanding {
            signer_id: signer_id.to_owned(),
            status,
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
