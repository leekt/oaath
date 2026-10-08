//! On-chain revocation of an invalidated grant: the account root signs one
//! owner operation that uninstalls the grant's Kernel v4 permission, or, when
//! it was never installed, consumes the enable's install nonce so the held
//! enable can never install it. The relay submits it through its configured
//! bundler, or hands it to the dapp when the dapp's client registered
//! `revocation_delivery: "dapp"` (the root may still submit from OAAth).
//!
//! ```text
//! GET  /portal/grants/{id}/revocation           root: status (observes once)
//! POST /portal/grants/{id}/revocation/prepare   root: {estimation_signature}
//! POST /portal/grants/{id}/revocation/sign      root: {signature}
//! GET  /oauth/grants/{id}/revocation            public: the stored status, and
//!                                               the signed operation for a dapp
//! ```
//!
//! ```text
//! state and owner      RevocationRecord (this module), one per grant on 421614:
//!                      reserved (bundler budget spent, no request) -> prepared
//!                      (exact request) -> signed -> submitted (relay) or
//!                      delivered (dapp) -> included -> finalized; rejected and
//!                      failed are terminal. Re-preparing replaces an unsigned
//!                      request only.
//! persisted evidence   oaath_revocation_v1: the request and its UserOperation
//!                      hash, the root signature, the submission time, every
//!                      bundler request spent, the receipt's transaction and
//!                      block
//! resource occupied?   the root validator's revocation lane on the account
//! retry positively     never for submission: the submission time is written
//! safe?                before the one eth_sendUserOperation, so a timeout,
//!                      crash or unreadable answer leaves `submitted`, which
//!                      only observes by UserOperation hash
//! allowed transitions  prepare only while unsigned and installed on chain;
//!                      sign once, by the account's root, over the exact
//!                      request; observe only after submission or delivery
//! crash/reload         every transition is one compare-and-swap on the record's
//!                      revision; reload reads the record and observes
//! cleanup owner        none: an off-chain invalidation already stopped the
//!                      grant; this removes its on-chain authority
//! ```
//!
//! A permission that is neither installed nor installable (its install
//! nonce is already consumed) needs nothing submitted. Every bundler request spends one unit of
//! `MAX_BUNDLER_REQUESTS`, recorded before the request leaves.

use alloy_primitives::{Address, U256};
use oaath_protocol::capture::parse_json;
use oaath_protocol::identity::KernelAccountProfile;
use oaath_protocol::kernel_revocation::{
    kernel_install_nonce_invalidation_call, kernel_permission_uninstall_calls,
};
use oaath_protocol::owner_operation::{
    OwnerOperationRequest, OwnerUserOperation, SignedOwnerOperation,
    compose_owner_operation_request, kernel_factory_deployment, parse_owner_operation_request,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::bundler::{Bundler, BundlerFailure};
use crate::chain::{
    ChainReader, PermissionState, PermissionTarget, finalized_permission, permission_state,
};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::signature::{RelyingParty, verify_root_signature};
use crate::kms::RelayKms;
use crate::oauth::grant::{read_grant, relying_party};
use crate::records::{canonical_identifier, exact_record, timestamp};
use crate::store::{RelayStore, RelayTransaction, settle};

pub const REVOCATION_RECORD_VERSION: &str = "oaath.revocation-record/v1";
pub const REVOCATION_CHAIN_ID: u64 = 421_614;
/// The root validator's standard-mode EntryPoint lane revocations use.
pub const REVOCATION_LANE: u16 = 1;
/// Bundler requests one revocation may ever spend: preparations, the one
/// submission, and receipt polls together.
pub const MAX_BUNDLER_REQUESTS: u64 = 32;
const ENTRY_POINT_V09: &str = "0x433709009b8330fda32311df1c2afa402ed8d009";
/// A WebAuthn assertion envelope is the largest root signature.
const MAX_SIGNATURE_HEX: usize = 2 + 2 * 8 * 1024;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;
const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;
const UNAVAILABLE: RelayErrorCode = RelayErrorCode::ChainUnavailable;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RevocationDelivery {
    /// The relay submits through its bundler (the default).
    Relay,
    /// The dapp receives the signed operation and submits it itself.
    Dapp,
}

impl RevocationDelivery {
    pub fn parse(value: Option<&Value>) -> Option<Self> {
        match value.and_then(Value::as_str) {
            Some("relay") => Some(Self::Relay),
            Some("dapp") => Some(Self::Dapp),
            _ => None,
        }
    }
}

/// What the root's one owner operation does on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RevocationAction {
    /// Uninstalls the installed permission: its policies, then its signer.
    Uninstall,
    /// Consumes the unused enable's install nonce (`setNonce`), so the
    /// retained enable signature can never install the permission; an
    /// undeployed account is deployed first.
    Invalidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RevocationOutcome {
    /// The bundler refused the submission.
    Rejected,
    /// A receipt: the operation executed.
    Included,
    /// A receipt: the operation reverted.
    Failed,
    /// Included at or below the finalized block, and absent there.
    Finalized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRecord {
    pub version: &'static str,
    pub grant_id: String,
    pub delivery: RevocationDelivery,
    pub action: RevocationAction,
    /// The exact unsigned request (JSON text); none while only reserved.
    pub request: Option<String>,
    pub signature: Option<String>,
    pub signed_at: Option<u64>,
    /// Whether the relay submits: always for relay delivery; for dapp
    /// delivery, the root's choice when it signs. Never set before signing.
    pub relay_submits: bool,
    /// Written before the one submission attempt; never cleared.
    pub submitted_at: Option<u64>,
    pub outcome: Option<RevocationOutcome>,
    pub transaction_hash: Option<String>,
    pub block_number: Option<u64>,
    pub bundler_requests: u64,
    pub revision: u64,
    pub updated_at: u64,
}

fn nullable<T>(
    value: Option<&Value>,
    read: impl FnOnce(&Value) -> RelayResult<T>,
) -> RelayResult<Option<T>> {
    match value {
        Some(Value::Null) => Ok(None),
        Some(value) => read(value).map(Some),
        None => Err(UNREADABLE),
    }
}

fn text(value: &Value) -> RelayResult<String> {
    value.as_str().map(str::to_owned).ok_or(UNREADABLE)
}

impl RevocationRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "grantId",
                "delivery",
                "action",
                "request",
                "signature",
                "signedAt",
                "relaySubmits",
                "submittedAt",
                "outcome",
                "transactionHash",
                "blockNumber",
                "bundlerRequests",
                "revision",
                "updatedAt",
            ],
            UNREADABLE,
        )?;
        if r.get("version").and_then(Value::as_str) != Some(REVOCATION_RECORD_VERSION) {
            return Err(UNREADABLE);
        }
        let outcome = nullable(r.get("outcome"), |value| match value.as_str() {
            Some("rejected") => Ok(RevocationOutcome::Rejected),
            Some("included") => Ok(RevocationOutcome::Included),
            Some("failed") => Ok(RevocationOutcome::Failed),
            Some("finalized") => Ok(RevocationOutcome::Finalized),
            _ => Err(UNREADABLE),
        })?;
        let record = Self {
            version: REVOCATION_RECORD_VERSION,
            grant_id: canonical_identifier(r.get("grantId"), UNREADABLE)?.to_owned(),
            delivery: RevocationDelivery::parse(r.get("delivery")).ok_or(UNREADABLE)?,
            action: match r.get("action").and_then(Value::as_str) {
                Some("uninstall") => RevocationAction::Uninstall,
                Some("invalidate") => RevocationAction::Invalidate,
                _ => return Err(UNREADABLE),
            },
            request: nullable(r.get("request"), text)?,
            signature: nullable(r.get("signature"), text)?,
            signed_at: nullable(r.get("signedAt"), |v| timestamp(Some(v), UNREADABLE))?,
            relay_submits: r
                .get("relaySubmits")
                .and_then(Value::as_bool)
                .ok_or(UNREADABLE)?,
            submitted_at: nullable(r.get("submittedAt"), |v| timestamp(Some(v), UNREADABLE))?,
            outcome,
            transaction_hash: nullable(r.get("transactionHash"), text)?,
            block_number: nullable(r.get("blockNumber"), |v| timestamp(Some(v), UNREADABLE))?,
            bundler_requests: timestamp(r.get("bundlerRequests"), UNREADABLE)?,
            revision: timestamp(r.get("revision"), UNREADABLE)?,
            updated_at: timestamp(r.get("updatedAt"), UNREADABLE)?,
        };
        // A signature names a request; a submission or delivery outcome a signature;
        // the relay submits relay deliveries always and dapp deliveries by choice.
        let consistent = (record.signature.is_none() || record.request.is_some())
            && (record.signature.is_some() == record.signed_at.is_some())
            && (!record.relay_submits || record.signature.is_some())
            && (record.signature.is_none()
                || record.delivery == RevocationDelivery::Dapp
                || record.relay_submits)
            && (record.submitted_at.is_none() || record.relay_submits)
            && (record.outcome.is_none() || record.signature.is_some())
            && (record.transaction_hash.is_some() == record.block_number.is_some())
            && record.revision >= 1
            && record.bundler_requests <= MAX_BUNDLER_REQUESTS;
        if !consistent {
            return Err(UNREADABLE);
        }
        if let Some(request) = &record.request {
            parse_owner_operation_request(&parse_json(request).map_err(|_| UNREADABLE)?)
                .map_err(|_| UNREADABLE)?;
        }
        Ok(record)
    }

    fn request(&self) -> RelayResult<Option<OwnerOperationRequest>> {
        self.request
            .as_deref()
            .map(|text| {
                parse_owner_operation_request(&parse_json(text).map_err(|_| UNREADABLE)?)
                    .map_err(|_| UNREADABLE)
            })
            .transpose()
    }

    /// The status the stored evidence alone supports.
    fn stored_status(&self) -> &'static str {
        match (self.outcome, self.submitted_at, &self.signature) {
            (Some(RevocationOutcome::Finalized), ..) => "finalized",
            (Some(RevocationOutcome::Included), ..) => "included",
            (Some(RevocationOutcome::Failed | RevocationOutcome::Rejected), ..) => "failed",
            (None, Some(_), _) => "submitted",
            (None, None, Some(_)) => "delivered",
            (None, None, None) => "pending_signature",
        }
    }

    /// Whether a receipt may still arrive for the signed operation.
    fn observable(&self) -> bool {
        self.outcome.is_none()
            && (self.submitted_at.is_some()
                || (self.signature.is_some() && self.delivery == RevocationDelivery::Dapp))
    }

    fn next(&self, now: u64) -> Self {
        Self {
            revision: self.revision + 1,
            updated_at: now,
            ..self.clone()
        }
    }
}

/// What the root and the portal see.
#[derive(Debug, Serialize)]
pub struct RevocationView {
    pub grant_id: String,
    /// `not_installed`, `pending_signature`, `submitted`, `delivered`,
    /// `included`, `finalized`, or `failed`.
    pub status: &'static str,
    pub delivery: RevocationDelivery,
    /// What the root's operation does, or none when nothing is needed on chain.
    pub action: Option<RevocationAction>,
    /// The grant's enable install nonce, which an invalidation consumes.
    pub install_nonce: String,
    /// Whether OAAth submits the signed uninstall (always for relay delivery;
    /// the root's choice for dapp delivery, once signed).
    pub relay_submits: bool,
    /// The grant's install packages: what the uninstall removes.
    pub packages: Value,
    /// The unsigned request the root signs, while one is prepared.
    pub request: Option<Value>,
    pub user_operation_hash: Option<String>,
    pub transaction_hash: Option<String>,
}

/// The dapp's view: the stored status and, for dapp delivery, what to submit.
#[derive(Debug, Serialize)]
pub struct DappRevocationView {
    pub grant_id: String,
    pub status: &'static str,
    pub signed_operation: Option<Value>,
}

/// The configured chain and bundler a revocation reads and submits through.
pub struct RevocationPorts<'a> {
    pub chain: Option<&'a ChainReader>,
    pub bundler: Option<&'a Bundler>,
}

/// One invalidated grant on the root's account.
struct Revocable {
    account: KernelAccountProfile,
    owner_validator: Option<String>,
    install_nonce: U256,
    target: PermissionTarget,
    packages: Value,
    delivery: RevocationDelivery,
}

async fn revocable(
    transaction: &mut dyn RelayTransaction,
    kms: &dyn RelayKms,
    grant_id: &str,
    session: Option<&str>,
) -> RelayResult<Revocable> {
    let request = transaction
        .lock_authorization_request(grant_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let account = transaction
        .lock_account(&request.subject)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    if session.is_some_and(|session| session != account.root_signer_id) {
        return Err(RelayErrorCode::Forbidden);
    }
    let view = read_grant(transaction, kms, grant_id).await?;
    if view.status != "invalidated" {
        return Err(INVALID);
    }
    let enable = view.enable.ok_or(UNREADABLE)?;
    let packages = enable.get("packages").cloned().ok_or(UNREADABLE)?;
    let signer = packages
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|entry| entry.get("moduleType").and_then(Value::as_u64) == Some(6))
        })
        .ok_or(UNREADABLE)?;
    let module = signer
        .get("module")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<Address>().ok())
        .ok_or(UNREADABLE)?;
    let permission_id: [u8; 4] = signer
        .get("moduleData")
        .and_then(Value::as_str)
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| hex::decode(digits.get(..8)?).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(UNREADABLE)?;
    let address = account.address.parse::<Address>().map_err(|_| UNREADABLE)?;
    if enable.get("account").and_then(Value::as_str) != Some(account.address.as_str()) {
        return Err(UNREADABLE);
    }
    let install_nonce = enable
        .get("installNonce")
        .and_then(Value::as_str)
        .and_then(|text| U256::from_str_radix(text, 10).ok())
        .ok_or(UNREADABLE)?;
    let delivery = match transaction.lock_oauth_client(&request.client_id).await? {
        Some(client) => client.revocation_delivery,
        None => RevocationDelivery::Relay,
    };
    Ok(Revocable {
        account: account.account_profile()?,
        owner_validator: account.owner_validator.clone(),
        install_nonce,
        target: PermissionTarget {
            account: address,
            signer: module,
            permission_id,
        },
        packages,
        delivery,
    })
}

fn view(
    grant_id: &str,
    revocable: &Revocable,
    record: Option<&RevocationRecord>,
    status: &'static str,
    action: Option<RevocationAction>,
) -> RelayResult<RevocationView> {
    let request = match record {
        Some(record) => record.request()?,
        None => None,
    };
    Ok(RevocationView {
        grant_id: grant_id.to_owned(),
        status,
        delivery: revocable.delivery,
        action: record.map(|record| record.action).or(action),
        install_nonce: revocable.install_nonce.to_string(),
        relay_submits: revocable.delivery == RevocationDelivery::Relay
            || record.is_some_and(|record| record.relay_submits),
        packages: revocable.packages.clone(),
        user_operation_hash: request.as_ref().map(|r| r.user_operation_hash.clone()),
        request: request
            .filter(|_| record.is_some_and(|r| r.signature.is_none()))
            .map(|r| r.to_json()),
        transaction_hash: record.and_then(|r| r.transaction_hash.clone()),
    })
}

/// Saves one transition; another writer's transition first is a conflict.
async fn save(store: &dyn RelayStore, record: &RevocationRecord) -> RelayResult<()> {
    let mut transaction = store.begin().await?;
    let result = transaction
        .save_revocation(record)
        .await
        .and_then(|saved| saved.then_some(()).ok_or(RelayErrorCode::AlreadyDecided));
    settle(transaction, result).await
}

async fn load(
    store: &dyn RelayStore,
    kms: &dyn RelayKms,
    grant_id: &str,
    session: Option<&str>,
) -> RelayResult<(Revocable, Option<RevocationRecord>)> {
    let mut transaction = store.begin().await?;
    let result = async {
        let revocable = revocable(&mut *transaction, kms, grant_id, session).await?;
        let record = transaction.lock_revocation(grant_id).await?;
        Ok((revocable, record))
    }
    .await;
    settle(transaction, result).await
}

/// Spends `count` bundler requests on the record before they leave.
fn spend(record: &RevocationRecord, count: u64, now: u64) -> RelayResult<RevocationRecord> {
    if record.bundler_requests + count > MAX_BUNDLER_REQUESTS {
        return Err(RelayErrorCode::RequestBudgetExhausted);
    }
    let mut next = record.next(now);
    next.bundler_requests += count;
    Ok(next)
}

fn quantity(decimal: &str) -> RelayResult<String> {
    let value = alloy_primitives::U256::from_str_radix(decimal, 10).map_err(|_| UNREADABLE)?;
    Ok(format!("{value:#x}"))
}

fn decimal(value: Option<&Value>) -> RelayResult<String> {
    let digits = value
        .and_then(Value::as_str)
        .and_then(|text| text.strip_prefix("0x"))
        .filter(|digits| !digits.is_empty() && digits.len() <= 32)
        .ok_or(UNAVAILABLE)?;
    let value = u128::from_str_radix(digits, 16).map_err(|_| UNAVAILABLE)?;
    Ok(value.to_string())
}

/// The EntryPoint 0.9 RPC form of an operation with `signature`.
fn wire(op: &OwnerUserOperation, signature: &str) -> RelayResult<Value> {
    let mut wire = json!({
        "sender": op.sender,
        "nonce": quantity(&op.nonce)?,
        "callData": op.call_data,
        "callGasLimit": quantity(&op.call_gas_limit)?,
        "verificationGasLimit": quantity(&op.verification_gas_limit)?,
        "preVerificationGas": quantity(&op.pre_verification_gas)?,
        "maxFeePerGas": quantity(&op.max_fee_per_gas)?,
        "maxPriorityFeePerGas": quantity(&op.max_priority_fee_per_gas)?,
        "signature": signature,
    });
    if let Some(factory) = &op.factory {
        wire["factory"] = json!(factory.address);
        wire["factoryData"] = json!(factory.data);
    }
    Ok(wire)
}

fn signature_hex(value: Option<&Value>) -> RelayResult<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| text.len() <= MAX_SIGNATURE_HEX && text.len() > 2)
        .and_then(|text| text.strip_prefix("0x"))
        .filter(|digits| {
            digits.len() % 2 == 0
                && digits
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
        .map(|digits| format!("0x{digits}"))
        .ok_or(INVALID)
}

/// `GET /portal/grants/{id}/revocation`: the root's status. A submitted or
/// delivered operation is observed once (one receipt request), and an
/// included one is checked against the finalized block.
pub async fn revocation_status(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    ports: &RevocationPorts<'_>,
    grant_id: &str,
    session: &str,
) -> RelayResult<RevocationView> {
    let now = relay_now(clock)?;
    let (revocable, record) = load(store, kms, grant_id, Some(session)).await?;
    let Some(mut record) = record else {
        let chain = ports.chain.ok_or(UNAVAILABLE)?;
        let state = chain_state(chain, &revocable).await?;
        let status = if state.installed {
            "pending_signature"
        } else {
            "not_installed"
        };
        let action = required_action(&state, revocable.install_nonce)?;
        return view(grant_id, &revocable, None, status, action);
    };
    if record.observable() {
        record = observe(store, ports, &record, now).await?;
    }
    if record.outcome == Some(RevocationOutcome::Included)
        && let (Some(chain), Some(block)) = (ports.chain, record.block_number)
        && let Ok((finalized, installed)) = finalized_permission(chain, &revocable.target).await
        && finalized >= block
        && !installed
    {
        let mut next = record.next(now);
        next.outcome = Some(RevocationOutcome::Finalized);
        save(store, &next).await?;
        record = next;
    }
    view(
        grant_id,
        &revocable,
        Some(&record),
        record.stored_status(),
        None,
    )
}

/// What the chain state requires: uninstall an installed permission;
/// invalidate an enable that can still install it (an undeployed account, or a
/// stored install nonce not past the enable's); nothing once it is consumed.
fn required_action(
    state: &PermissionState,
    install_nonce: U256,
) -> RelayResult<Option<RevocationAction>> {
    if state.installed {
        return Ok(Some(RevocationAction::Uninstall));
    }
    let Some(stored) = state.install_nonce else {
        return Ok(Some(RevocationAction::Invalidate));
    };
    // Kernel answers its own key: another one is contradictory.
    if stored >> 64 != install_nonce >> 64 {
        return Err(UNAVAILABLE);
    }
    Ok((stored <= install_nonce).then_some(RevocationAction::Invalidate))
}

async fn chain_state(chain: &ChainReader, revocable: &Revocable) -> RelayResult<PermissionState> {
    permission_state(
        chain,
        &revocable.target,
        entry_point(),
        REVOCATION_LANE,
        revocable.install_nonce >> 64,
    )
    .await
}

fn entry_point() -> Address {
    ENTRY_POINT_V09.parse().expect("pinned EntryPoint")
}

/// One receipt request, spent before it leaves. No receipt yet, or an
/// unusable answer, changes nothing but the spend.
async fn observe(
    store: &dyn RelayStore,
    ports: &RevocationPorts<'_>,
    record: &RevocationRecord,
    now: u64,
) -> RelayResult<RevocationRecord> {
    let Some(bundler) = ports.bundler else {
        return Ok(record.clone());
    };
    let Ok(spent) = spend(record, 1, now) else {
        return Ok(record.clone());
    };
    save(store, &spent).await?;
    let request = spent.request()?.ok_or(UNREADABLE)?;
    let Ok(receipt) = bundler
        .call(
            "eth_getUserOperationReceipt",
            json!([request.user_operation_hash]),
        )
        .await
    else {
        return Ok(spent);
    };
    if receipt.is_null() {
        return Ok(spent);
    }
    let matches = receipt.get("userOpHash").and_then(Value::as_str)
        == Some(request.user_operation_hash.as_str())
        && receipt
            .get("sender")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .as_deref()
            == Some(request.user_operation.sender.as_str());
    let success = receipt.get("success").and_then(Value::as_bool);
    let inner = receipt.get("receipt");
    let transaction_hash = inner
        .and_then(|inner| inner.get("transactionHash"))
        .and_then(Value::as_str)
        .filter(|hash| crate::records::is_lowercase_hash(hash));
    let block_number = inner
        .and_then(|inner| inner.get("blockNumber"))
        .and_then(Value::as_str)
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok());
    let (Some(success), Some(transaction_hash), Some(block_number), true) =
        (success, transaction_hash, block_number, matches)
    else {
        return Ok(spent);
    };
    let mut next = spent.next(now);
    next.outcome = Some(if success {
        RevocationOutcome::Included
    } else {
        RevocationOutcome::Failed
    });
    next.transaction_hash = Some(transaction_hash.to_owned());
    next.block_number = Some(block_number);
    save(store, &next).await?;
    Ok(next)
}

/// `POST /portal/grants/{id}/revocation/prepare {estimation_signature}`: the
/// exact uninstall the root signs, priced and estimated by the bundler. The
/// estimation signature is a placeholder of the root's kind and authorizes
/// nothing.
pub async fn prepare_revocation(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    ports: &RevocationPorts<'_>,
    grant_id: &str,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<RevocationView> {
    exact_record(
        &Value::Object(body.clone()),
        &["estimation_signature"],
        INVALID,
    )?;
    let estimation = signature_hex(body.get("estimation_signature"))?;
    let now = relay_now(clock)?;
    let chain = ports.chain.ok_or(UNAVAILABLE)?;
    let bundler = ports.bundler.ok_or(UNAVAILABLE)?;
    let (revocable, record) = load(store, kms, grant_id, Some(session)).await?;
    if record
        .as_ref()
        .is_some_and(|record| record.signature.is_some())
    {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    let state = chain_state(chain, &revocable).await?;
    let Some(action) = required_action(&state, revocable.install_nonce)? else {
        return view(grant_id, &revocable, None, "not_installed", None);
    };
    let account = format!("{:#x}", revocable.target.account);
    let calls = match action {
        RevocationAction::Uninstall => kernel_permission_uninstall_calls(&json!({
            "account": account,
            "packages": revocable.packages,
        })),
        RevocationAction::Invalidate => kernel_install_nonce_invalidation_call(&json!({
            "account": account,
            "installNonce": revocable.install_nonce.to_string(),
        }))
        .map(|call| vec![call]),
    }
    .map_err(|_| UNREADABLE)?;
    // Only a derived account can be undeployed; the operation deploys it first.
    let factory = match (&revocable.account, state.deployed) {
        (_, true) => None,
        (KernelAccountProfile::Derived(profile), false) => Some(
            kernel_factory_deployment(profile, revocable.owner_validator.as_deref())
                .map_err(|_| UNREADABLE)?,
        ),
        (KernelAccountProfile::Existing(_), false) => return Err(UNREADABLE),
    };

    // The two bundler requests below are spent before they leave.
    let reserved = match &record {
        Some(record) => {
            let mut reserved = spend(record, 2, now)?;
            reserved.action = action;
            reserved
        }
        None => RevocationRecord {
            version: REVOCATION_RECORD_VERSION,
            grant_id: grant_id.to_owned(),
            delivery: revocable.delivery,
            action,
            request: None,
            signature: None,
            signed_at: None,
            relay_submits: false,
            submitted_at: None,
            outcome: None,
            transaction_hash: None,
            block_number: None,
            bundler_requests: 2,
            revision: 1,
            updated_at: now,
        },
    };
    save(store, &reserved).await?;

    let prices = bundler
        .call("pimlico_getUserOperationGasPrice", json!([]))
        .await
        .map_err(|_| UNAVAILABLE)?;
    let fast = prices.get("fast").ok_or(UNAVAILABLE)?;
    let mut op = OwnerUserOperation {
        sender: format!("{:#x}", revocable.target.account),
        nonce: state.nonce.to_string(),
        call_data: String::new(),
        call_gas_limit: "0".to_owned(),
        verification_gas_limit: "0".to_owned(),
        pre_verification_gas: "0".to_owned(),
        max_fee_per_gas: decimal(fast.get("maxFeePerGas"))?,
        max_priority_fee_per_gas: decimal(fast.get("maxPriorityFeePerGas"))?,
        factory,
        paymaster: None,
    };
    let draft = compose_owner_operation_request(
        revocable.account.clone(),
        REVOCATION_CHAIN_ID,
        calls.clone(),
        op.clone(),
    )
    .map_err(|_| UNREADABLE)?;
    let estimate = bundler
        .call(
            "eth_estimateUserOperationGas",
            json!([wire(&draft.user_operation, &estimation)?, ENTRY_POINT_V09]),
        )
        .await
        .map_err(|_| UNAVAILABLE)?;
    op.call_gas_limit = decimal(estimate.get("callGasLimit"))?;
    op.verification_gas_limit = decimal(estimate.get("verificationGasLimit"))?;
    op.pre_verification_gas = decimal(estimate.get("preVerificationGas"))?;
    let request =
        compose_owner_operation_request(revocable.account.clone(), REVOCATION_CHAIN_ID, calls, op)
            .map_err(|_| UNAVAILABLE)?;

    let mut prepared = reserved.next(now);
    prepared.request = Some(request.to_json().to_string());
    save(store, &prepared).await?;
    view(
        grant_id,
        &revocable,
        Some(&prepared),
        "pending_signature",
        None,
    )
}

/// `POST /portal/grants/{id}/revocation/sign {signature, submit_from_oaath?}`:
/// the root's one signature over the prepared request. With relay delivery, or
/// with dapp delivery and `submit_from_oaath: true`, the submission is
/// recorded, then sent once; nothing ever sends it again. A dapp can still
/// read the signed operation; the account nonce lets only one copy land.
#[allow(clippy::too_many_arguments)]
pub async fn sign_revocation(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    ports: &RevocationPorts<'_>,
    issuer: &str,
    grant_id: &str,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<RevocationView> {
    let submit_from_oaath = match body.get("submit_from_oaath") {
        None => false,
        Some(Value::Bool(choice)) => *choice,
        Some(_) => return Err(INVALID),
    };
    let keys: &[&str] = if body.contains_key("submit_from_oaath") {
        &["signature", "submit_from_oaath"]
    } else {
        &["signature"]
    };
    exact_record(&Value::Object(body.clone()), keys, INVALID)?;
    let signature = signature_hex(body.get("signature"))?;
    let now = relay_now(clock)?;
    let (revocable, record) = load(store, kms, grant_id, Some(session)).await?;
    let record = record.ok_or(INVALID)?;
    if record.signature.is_some() {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    let request = record.request()?.ok_or(INVALID)?;
    let (rp_id, origin) = relying_party(issuer)?;
    let bytes = hex::decode(&signature[2..]).map_err(|_| INVALID)?;
    if !verify_root_signature(
        request.owner_credential(),
        request.digest(),
        &bytes,
        &RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        },
    ) {
        return Err(INVALID);
    }
    let relay = record.delivery == RevocationDelivery::Relay || submit_from_oaath;
    let bundler = if relay {
        Some(ports.bundler.ok_or(UNAVAILABLE)?)
    } else {
        None
    };
    let mut signed = if relay {
        spend(&record, 1, now)?
    } else {
        record.next(now)
    };
    signed.signature = Some(signature.clone());
    signed.signed_at = Some(now);
    signed.relay_submits = relay;
    if relay {
        signed.submitted_at = Some(now);
    }
    save(store, &signed).await?;

    if let Some(bundler) = bundler {
        match bundler
            .call(
                "eth_sendUserOperation",
                json!([wire(&request.user_operation, &signature)?, ENTRY_POINT_V09]),
            )
            .await
        {
            Err(BundlerFailure::Rejected) => {
                let mut rejected = signed.next(now);
                rejected.outcome = Some(RevocationOutcome::Rejected);
                save(store, &rejected).await?;
                signed = rejected;
            }
            // Accepted, or unknown: either way only observation follows.
            Ok(_) | Err(BundlerFailure::Unavailable) => {}
        }
    }
    view(
        grant_id,
        &revocable,
        Some(&signed),
        signed.stored_status(),
        None,
    )
}

/// `GET /oauth/grants/{id}/revocation` (by the grant's bearer token or operator
/// proof): the stored status, read without
/// spending any chain or bundler budget. A dapp that registered
/// `revocation_delivery: "dapp"` reads its root-signed uninstall here; it can
/// only remove the grant's own permission.
pub async fn dapp_revocation(
    store: &dyn RelayStore,
    kms: &dyn RelayKms,
    grant_id: &str,
) -> RelayResult<DappRevocationView> {
    let (revocable, record) = load(store, kms, grant_id, None).await?;
    let status = record
        .as_ref()
        .map_or("pending_signature", RevocationRecord::stored_status);
    let signed_operation = match (&record, revocable.delivery) {
        (Some(record), RevocationDelivery::Dapp) => match (record.request()?, &record.signature) {
            (Some(request), Some(signature)) => Some(
                SignedOwnerOperation {
                    request,
                    signature: signature.clone(),
                }
                .to_json(),
            ),
            _ => None,
        },
        _ => None,
    };
    Ok(DappRevocationView {
        grant_id: grant_id.to_owned(),
        status,
        signed_operation,
    })
}
