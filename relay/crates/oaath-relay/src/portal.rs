//! Portal signer and account endpoints.
//!
//! ```text
//! POST /portal/signers                 {profile}         -> {signer_id}
//! GET  /portal/signers/{id}/accounts                     -> {accounts: [...]}
//! GET  /portal/signers/by-credential/{credentialId}      -> {signer_id, kind, profile}
//! POST /portal/accounts                {root_signer_id}  -> {account_id, address, profile}
//! ```
//!
//! The portal is unauthenticated: registering a signer or deriving an account
//! grants no authority, because only a root signature can approve anything.
//! The routes are same-origin only, so another site cannot drive them from a
//! visitor's browser.

use alloy_primitives::keccak256;
use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oaath_protocol::identity::{
    KernelAccountProfile, KernelDerivedAccountProfile, KernelFactoryRoute, OwnerCredentialProfile,
    parse_owner_credential_profile,
};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::authorization::challenge::random_identifier;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::records::canonical_str;
use crate::registry::{
    ACCOUNT_RECORD_VERSION, ACCOUNT_SIGNER_RECORD_VERSION, AccountRecord, AccountSignerRecord,
    MembershipRole, SIGNER_RECORD_VERSION, SignerRecord, derive_account_address, hex_hash,
    owner_validator_for,
};
use crate::store::{RelayStore, RelayTransaction, settle};

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;

/// Refuses a request a browser marked as coming from another site. Requests
/// without `sec-fetch-site` come from non-browser clients, which carry no
/// visitor's ambient authority.
pub fn assert_same_origin(headers: &HeaderMap) -> RelayResult<()> {
    match headers.get("sec-fetch-site").map(|value| value.as_bytes()) {
        None | Some(b"same-origin") | Some(b"none") => Ok(()),
        Some(_) => Err(RelayErrorCode::Forbidden),
    }
}

#[derive(Debug, Serialize)]
pub struct RegisteredSigner {
    pub signer_id: String,
}

/// Registers one owner-credential profile, idempotently: the same profile
/// always answers the same signer.
pub async fn register_signer(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    body: &Map<String, Value>,
) -> RelayResult<RegisteredSigner> {
    if body.len() != 1 {
        return Err(INVALID);
    }
    let credential =
        parse_owner_credential_profile(body.get("profile").ok_or(INVALID)?).map_err(|_| INVALID)?;
    let record = signer_record(&credential, relay_now(clock)?);
    let mut transaction = store.begin().await?;
    let result = register(&mut *transaction, &record).await;
    let signer_id = settle(transaction, result).await?;
    Ok(RegisteredSigner { signer_id })
}

/// A new signer record for one credential.
pub fn signer_record(credential: &OwnerCredentialProfile, now: u64) -> SignerRecord {
    SignerRecord {
        version: SIGNER_RECORD_VERSION,
        signer_id: random_identifier(),
        profile_hash: hex_hash(credential.hash()),
        profile: credential.to_json().to_string(),
        created_at: now,
    }
}

/// The signer for this profile hash, registering it if absent.
pub async fn register(
    transaction: &mut dyn RelayTransaction,
    record: &SignerRecord,
) -> RelayResult<String> {
    if let Some(existing) = transaction
        .lock_signer_by_profile_hash(&record.profile_hash)
        .await?
    {
        return Ok(existing.signer_id);
    }
    if transaction.insert_signer(record).await? {
        return Ok(record.signer_id.clone());
    }
    // A concurrent registration of the same profile won; answer its signer.
    transaction
        .lock_signer_by_profile_hash(&record.profile_hash)
        .await?
        .map(|existing| existing.signer_id)
        .ok_or(RelayErrorCode::Internal)
}

#[derive(Debug, Serialize)]
pub struct IdentifiedSigner {
    pub signer_id: String,
    pub kind: &'static str,
    pub profile: Value,
}

/// WebAuthn allows credential IDs of up to 1023 bytes.
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// Recognises a passkey registered from another browser by its credential ID
/// (base64url, as `navigator.credentials.get()` returns it). Identification
/// only: nothing is verified, and a match grants no authority. The match is
/// the profile's own `authenticatorIdHash = keccak256(credentialId)`, so no
/// separate credential fact is stored. More than one match (a profile copying
/// another's authenticator) is ambiguous and reads as absent.
pub async fn signer_by_credential(
    store: &dyn RelayStore,
    credential_id: &str,
) -> RelayResult<IdentifiedSigner> {
    if !credential_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(INVALID);
    }
    let raw = URL_SAFE_NO_PAD.decode(credential_id).map_err(|_| INVALID)?;
    if raw.is_empty() || raw.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(INVALID);
    }
    let authenticator_id_hash = hex_hash(keccak256(&raw));
    let mut transaction = store.begin().await?;
    let result = transaction
        .list_signers_by_authenticator(&authenticator_id_hash)
        .await;
    let mut signers = settle(transaction, result).await?;
    if signers.len() != 1 {
        return Err(RelayErrorCode::NotFound);
    }
    let signer = signers.remove(0);
    let credential = signer.credential()?;
    Ok(IdentifiedSigner {
        signer_id: signer.signer_id,
        kind: credential.kind(),
        profile: credential.to_json(),
    })
}

#[derive(Debug, Serialize)]
pub struct SignerAccount {
    pub account_id: String,
    pub address: String,
    pub role: MembershipRole,
    pub profile: Value,
}

#[derive(Debug, Serialize)]
pub struct SignerAccounts {
    pub accounts: Vec<SignerAccount>,
}

fn account_profile_json(account: &AccountRecord) -> RelayResult<Value> {
    Ok(account.account_profile()?.to_json())
}

pub async fn signer_accounts(
    store: &dyn RelayStore,
    signer_id: &str,
) -> RelayResult<SignerAccounts> {
    let mut transaction = store.begin().await?;
    let result = list(&mut *transaction, signer_id).await;
    let memberships = settle(transaction, result).await?;
    let accounts = memberships
        .iter()
        .map(|(account, membership)| {
            Ok(SignerAccount {
                account_id: account.account_id.clone(),
                address: account.address.clone(),
                role: membership.role,
                profile: account_profile_json(account)?,
            })
        })
        .collect::<RelayResult<_>>()?;
    Ok(SignerAccounts { accounts })
}

async fn list(
    transaction: &mut dyn RelayTransaction,
    signer_id: &str,
) -> RelayResult<Vec<(AccountRecord, AccountSignerRecord)>> {
    if transaction.lock_signer(signer_id).await?.is_none() {
        return Err(RelayErrorCode::NotFound);
    }
    transaction.list_signer_accounts(signer_id).await
}

#[derive(Debug, Serialize)]
pub struct CreatedAccount {
    pub account_id: String,
    pub address: String,
    pub profile: Value,
}

/// Derives the root signer's next counterfactual account (the smallest unused
/// index) and records it with its root membership in one transaction.
pub async fn create_account(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    body: &Map<String, Value>,
) -> RelayResult<CreatedAccount> {
    if body.len() != 1 {
        return Err(INVALID);
    }
    let root_signer_id = body
        .get("root_signer_id")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    canonical_str(root_signer_id, INVALID)?;
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = create(&mut *transaction, root_signer_id, now).await;
    let account = settle(transaction, result).await?;
    Ok(CreatedAccount {
        profile: account_profile_json(&account)?,
        account_id: account.account_id,
        address: account.address,
    })
}

async fn create(
    transaction: &mut dyn RelayTransaction,
    root_signer_id: &str,
    now: u64,
) -> RelayResult<AccountRecord> {
    // The signer row lock serializes index allocation for this root.
    let signer = transaction
        .lock_signer(root_signer_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let used: Vec<u64> = transaction
        .list_signer_accounts(root_signer_id)
        .await?
        .into_iter()
        .filter(|(account, _)| account.root_signer_id == root_signer_id)
        .map(|(account, _)| account.account_index)
        .collect();
    let account_index = (0..)
        .find(|index| !used.contains(index))
        .ok_or(RelayErrorCode::Internal)?;
    let owner_credential = signer.credential()?;
    let owner_validator = owner_validator_for(&owner_credential);
    let profile = KernelAccountProfile::Derived(KernelDerivedAccountProfile {
        account_index: account_index.to_string(),
        factory_route: KernelFactoryRoute::KernelFactory,
        owner_credential,
    });
    let account = AccountRecord {
        version: ACCOUNT_RECORD_VERSION,
        account_id: random_identifier(),
        address: derive_account_address(&profile, owner_validator.as_deref())
            .ok_or(RelayErrorCode::Internal)?,
        root_signer_id: root_signer_id.to_owned(),
        account_index,
        owner_validator,
        profile: profile.to_json().to_string(),
        created_at: now,
    };
    let root = AccountSignerRecord {
        version: ACCOUNT_SIGNER_RECORD_VERSION,
        account_id: account.account_id.clone(),
        signer_id: root_signer_id.to_owned(),
        role: MembershipRole::Root,
        request_id: None,
        created_at: now,
    };
    if !transaction.insert_account(&account).await?
        || !transaction.insert_account_signer(&root).await?
    {
        return Err(RelayErrorCode::Internal);
    }
    Ok(account)
}
