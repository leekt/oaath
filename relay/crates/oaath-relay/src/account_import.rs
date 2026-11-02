//! Importing an existing Kernel v4 account, or a Kernel 0.3.3 account with an
//! ECDSA root, on its root's signed statement. The relay reads no chain.
//!
//! ```text
//! POST /portal/accounts/import
//!   {root_signer_id, address, kernel_version, inventory_fingerprint, issued_at,
//!    nonce, signature}
//!   -> {account_id, address, profile}
//! ```
//!
//! ```text
//! state and owner      none -> imported account + root membership + import
//!                      evidence, one transaction; an import is immutable
//! persisted evidence   oaath_account_v1 (the protocol existing-account
//!                      profile at the signed Kernel version, no factory index)
//!                      and oaath_account_import_v1 (the acknowledged
//!                      fingerprint, the statement's time and nonce, and the
//!                      root's signature)
//! resource occupied?   the address: an account is registered once, derived
//!                      or imported
//! retry safe?          a repeated import of the same address is refused
//! forbidden            another signer's session; a signature by another key
//!                      or over another account, owner, version, fingerprint,
//!                      time or nonce; a statement older than five minutes or
//!                      from the future; a Kernel 0.3.3 account whose root is
//!                      not an ECDSA owner
//! ```
//!
//! The root signs one EIP-712 statement under the OAAth domain (as the
//! membership approval in `link.rs`), verified like every root signature
//! (`grant/signature.rs`):
//!
//! ```text
//! AccountImport(address account, string kernelVersion, bytes32 ownerProfileHash,
//!               bytes32 inventoryFingerprint, uint64 issuedAt, string nonce)
//! ```
//!
//! The signature proves control of the key, not that the key is the account's
//! root on chain. That is enforced where it matters: every grant installs only
//! through the root's own Kernel signature, which the account verifies on
//! chain, so a non-root's approvals install nothing. A signer can still
//! register an address it does not own first; the real root is then refused
//! as `relay_already_decided`. The portal reads the account before the root
//! signs and the root acknowledges that reading by its fingerprint.

use alloy_primitives::{Address, B256};
use alloy_sol_types::{SolStruct, sol};
use oaath_protocol::identity::{
    KernelAccountProfile, KernelExistingAccountProfile, KernelExistingAccountVersion,
    OwnerCredentialProfile,
};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::authorization::challenge::random_identifier;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::signature::{RelyingParty, verify_root_signature};
use crate::link::DOMAIN;
use crate::oauth::grant::relying_party;
use crate::records::{canonical_identifier, exact_record, timestamp};
use crate::registry::{
    ACCOUNT_RECORD_VERSION, ACCOUNT_SIGNER_RECORD_VERSION, AccountRecord, AccountSignerRecord,
    MembershipRole, MembershipStatus, owner_validator_for,
};
use crate::store::{RelayStore, settle};

pub const ACCOUNT_IMPORT_RECORD_VERSION: &str = "oaath.account-import-record/v1";
/// How old an import statement may be when it arrives.
pub const STATEMENT_TTL_SECONDS: u64 = 300;
const MAX_SIGNATURE_HEX: usize = 16_384;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;
const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

sol! {
    /// The statement an account's root signs to import it.
    struct AccountImport {
        address account;
        string kernelVersion;
        bytes32 ownerProfileHash;
        bytes32 inventoryFingerprint;
        uint64 issuedAt;
        string nonce;
    }
}

pub fn import_digest(statement: &AccountImport) -> B256 {
    statement.eip712_signing_hash(&DOMAIN)
}

/// The evidence an import keeps: what the root acknowledged and signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountImportRecord {
    pub version: &'static str,
    pub account_id: String,
    /// The portal's inventory fingerprint the root acknowledged.
    pub inventory_fingerprint: String,
    /// Unix seconds, as signed.
    pub issued_at: u64,
    pub nonce: String,
    pub signature: String,
    pub created_at: u64,
}

fn bytes32(text: &str) -> Option<B256> {
    let digits = text.strip_prefix("0x")?;
    (digits.len() == 64
        && digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| text.parse().ok())
    .flatten()
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

impl AccountImportRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "accountId",
                "inventoryFingerprint",
                "issuedAt",
                "nonce",
                "signature",
                "createdAt",
            ],
            UNREADABLE,
        )?;
        if r.get("version").and_then(Value::as_str) != Some(ACCOUNT_IMPORT_RECORD_VERSION) {
            return Err(UNREADABLE);
        }
        let text = |key| r.get(key).and_then(Value::as_str).ok_or(UNREADABLE);
        let fingerprint = text("inventoryFingerprint")?;
        let signature = text("signature")?;
        if bytes32(fingerprint).is_none() || signature_hex(signature).is_none() {
            return Err(UNREADABLE);
        }
        Ok(Self {
            version: ACCOUNT_IMPORT_RECORD_VERSION,
            account_id: canonical_identifier(r.get("accountId"), UNREADABLE)?.to_owned(),
            inventory_fingerprint: fingerprint.to_owned(),
            issued_at: timestamp(r.get("issuedAt"), UNREADABLE)?,
            nonce: canonical_identifier(r.get("nonce"), UNREADABLE)?.to_owned(),
            signature: signature.to_owned(),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ImportedAccount {
    pub account_id: String,
    pub address: String,
    pub profile: Value,
}

/// Records the root-signed import of an existing Kernel account.
pub async fn import_account(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    issuer: &str,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<ImportedAccount> {
    exact_record(
        &Value::Object(body.clone()),
        &[
            "root_signer_id",
            "address",
            "kernel_version",
            "inventory_fingerprint",
            "issued_at",
            "nonce",
            "signature",
        ],
        INVALID,
    )?;
    let root_signer_id = canonical_identifier(body.get("root_signer_id"), INVALID)?;
    if root_signer_id != session {
        return Err(RelayErrorCode::Forbidden);
    }
    let address = body
        .get("address")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<Address>().ok())
        .ok_or(INVALID)?;
    let kernel_version = match body.get("kernel_version").and_then(Value::as_str) {
        Some("0.4.0") => KernelExistingAccountVersion::V0_4_0,
        Some("0.3.3") => KernelExistingAccountVersion::V0_3_3,
        _ => return Err(INVALID),
    };
    let fingerprint_text = body
        .get("inventory_fingerprint")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let fingerprint = bytes32(fingerprint_text).ok_or(INVALID)?;
    let issued_at = timestamp(body.get("issued_at"), INVALID)?;
    let nonce = canonical_identifier(body.get("nonce"), INVALID)?;
    let signature_text = body
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let signature = signature_hex(signature_text).ok_or(INVALID)?;
    let now = relay_now(clock)?;
    let seconds = now / 1_000;
    if issued_at > seconds || seconds - issued_at > STATEMENT_TTL_SECONDS {
        return Err(RelayErrorCode::Expired);
    }
    let (rp_id, origin) = relying_party(issuer)?;
    let account_address = format!("{address:#x}");
    // The statement and the free address are checked first; the chain is read
    // outside any transaction; the write re-checks the address under its guard.
    let mut transaction = store.begin().await?;
    let result = async {
        let signer = transaction
            .lock_signer(root_signer_id)
            .await?
            .ok_or(RelayErrorCode::NotFound)?;
        let owner = signer.credential()?;
        let statement = AccountImport {
            account: address,
            kernelVersion: kernel_version.as_str().to_owned(),
            ownerProfileHash: signer.profile_hash.parse().map_err(|_| UNREADABLE)?,
            inventoryFingerprint: fingerprint,
            issuedAt: issued_at,
            nonce: nonce.to_owned(),
        };
        let relying_party = RelyingParty {
            rp_id: &rp_id,
            origin: &origin,
        };
        if !verify_root_signature(
            &owner,
            import_digest(&statement),
            &signature,
            &relying_party,
        ) {
            return Err(RelayErrorCode::Forbidden);
        }
        if transaction
            .lock_account_by_address(&account_address)
            .await?
            .is_some()
        {
            return Err(RelayErrorCode::AlreadyDecided);
        }
        Ok(owner)
    }
    .await;
    let owner = settle(transaction, result).await?;
    // Kernel 0.3.3's root is its ECDSA validator.
    if kernel_version == KernelExistingAccountVersion::V0_3_3
        && !matches!(owner, OwnerCredentialProfile::Ecdsa { .. })
    {
        return Err(RelayErrorCode::Forbidden);
    }

    let mut transaction = store.begin().await?;
    let result = async {
        let profile = KernelAccountProfile::Existing(KernelExistingAccountProfile {
            kernel_version,
            address: account_address.clone(),
            owner_credential: owner.clone(),
        });
        let account = AccountRecord {
            version: ACCOUNT_RECORD_VERSION,
            account_id: random_identifier(),
            address: account_address.clone(),
            root_signer_id: root_signer_id.to_owned(),
            account_index: None,
            creation_key: None,
            owner_validator: owner_validator_for(&owner),
            profile: profile.to_json().to_string(),
            created_at: now,
        };
        let inserted = transaction.insert_account(&account).await?
            && transaction
                .insert_account_signer(&AccountSignerRecord {
                    version: ACCOUNT_SIGNER_RECORD_VERSION,
                    account_id: account.account_id.clone(),
                    signer_id: root_signer_id.to_owned(),
                    role: MembershipRole::Root,
                    request_id: None,
                    link_id: None,
                    created_at: now,
                    status: MembershipStatus::Active,
                    suspended_at: None,
                    restored_at: None,
                })
                .await?
            && transaction
                .insert_account_import(&AccountImportRecord {
                    version: ACCOUNT_IMPORT_RECORD_VERSION,
                    account_id: account.account_id.clone(),
                    inventory_fingerprint: fingerprint_text.to_owned(),
                    issued_at,
                    nonce: nonce.to_owned(),
                    signature: signature_text.to_owned(),
                    created_at: now,
                })
                .await?;
        if !inserted {
            // The address was registered concurrently.
            return Err(RelayErrorCode::AlreadyDecided);
        }
        Ok(ImportedAccount {
            profile: profile.to_json(),
            account_id: account.account_id,
            address: account.address,
        })
    }
    .await;
    settle(transaction, result).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_the_import_statement_as_eip_712() {
        let statement = AccountImport {
            account: "0x00000000000000000000000000000000000000aa"
                .parse()
                .unwrap(),
            kernelVersion: "0.4.0".to_owned(),
            ownerProfileHash: B256::repeat_byte(0x11),
            inventoryFingerprint: B256::repeat_byte(0x22),
            issuedAt: 1_700_000_000,
            nonce: "import-1".to_owned(),
        };
        // Pinned against cetane's hashTypedData over the same typed data.
        assert_eq!(
            format!("{:#x}", import_digest(&statement)),
            "0x251942d2c0007601749d5aa298e8d5a155a8ef94b96a10cd42d7ce61f5929ec0"
        );
    }
}
