//! Signer, account, and membership records.
//!
//! ```text
//! state and owner        signer (immutable, unique on its owner-credential
//!                        profile hash); account (immutable, one root signer and
//!                        index); membership (immutable index row)
//! persisted evidence     oaath_signer_v1, oaath_account_v1, oaath_account_signer_v1
//! resource occupied?     one root per account; (root signer, index) and address
//!                        are unique
//! retry positively safe? signer registration is idempotent on the profile hash;
//!                        account creation allocates the next index, so a retry
//!                        after an unproven commit may create a second account
//! transitions            none -> signer; none -> account + root membership in one
//!                        transaction; a permission membership arrives with a
//!                        verified grant decision or a root-approved link
//!                        (`link.rs`); the root removes a permission membership
//! forbidden              a second root; a root carrying a grant or a link; a
//!                        permission membership with neither or both; a
//!                        membership on an unknown account or signer
//! crash/reload           every write commits in one transaction
//! ```
//!
//! Durable storage is a trust boundary: every read re-captures the stored
//! profile through the protocol and checks it against the stored identity.

use oaath_protocol::capture::parse_json;
use oaath_protocol::identity::{
    KernelAccountProfile, KernelFactoryRoute, OwnerCredentialProfile, parse_kernel_account_profile,
    parse_owner_credential_profile,
};
use oaath_protocol::kernel_account::derive_kernel_v4_account_address;
use serde::Serialize;
use serde_json::Value;

use crate::error::{RelayErrorCode, RelayResult};
use crate::records::{canonical_identifier, exact_record, timestamp};

pub const SIGNER_RECORD_VERSION: &str = "oaath.signer-record/v1";
pub const ACCOUNT_RECORD_VERSION: &str = "oaath.account-record/v1";
pub const ACCOUNT_SIGNER_RECORD_VERSION: &str = "oaath.account-signer-record/v2";

const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

/// The ECDSA root validator the SDK runtime binds for Kernel v4 (`ECDSA_VALIDATOR`
/// in `packages/sdk/src/kernel/deployment/v33.ts`), recorded on each new ECDSA
/// account. P-256 and WebAuthn roots use the validators the protocol pins.
pub const ECDSA_ROOT_VALIDATOR: &str = "0x845adb2c711129d4f3966735ed98a9f09fc4ce57";

/// The root validator an account binds for its owner credential: the SDK's
/// ECDSA validator, or none where the protocol pins it.
pub fn owner_validator_for(owner: &OwnerCredentialProfile) -> Option<String> {
    match owner {
        OwnerCredentialProfile::Ecdsa { .. } => Some(ECDSA_ROOT_VALIDATOR.to_owned()),
        OwnerCredentialProfile::P256 { .. } | OwnerCredentialProfile::WebAuthn { .. } => None,
    }
}

/// The offline counterfactual address of a factory-derived account whose
/// single policy-free root is the profile's owner credential.
pub fn derive_account_address(
    profile: &KernelAccountProfile,
    owner_validator: Option<&str>,
) -> Option<String> {
    let KernelAccountProfile::Derived(profile) = profile else {
        return None;
    };
    derive_kernel_v4_account_address(profile, owner_validator).ok()
}

fn version(value: Option<&Value>, expected: &str) -> RelayResult<()> {
    match value {
        Some(Value::String(text)) if text == expected => Ok(()),
        _ => Err(UNREADABLE),
    }
}

fn identifier(value: Option<&Value>) -> RelayResult<String> {
    canonical_identifier(value, UNREADABLE).map(str::to_owned)
}

fn text(value: Option<&Value>) -> RelayResult<&str> {
    value.and_then(Value::as_str).ok_or(UNREADABLE)
}

/// The lowercase `0x` hex form of a 32-byte hash.
pub fn hex_hash(hash: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(hash))
}

/// One credential, identified by its protocol owner-credential profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerRecord {
    pub version: &'static str,
    pub signer_id: String,
    /// `hashOwnerCredentialProfile`; unique per signer.
    pub profile_hash: String,
    /// Canonical JSON of the owner-credential profile.
    pub profile: String,
    pub created_at: u64,
}

impl SignerRecord {
    /// A WebAuthn signer's `authenticatorIdHash` (keccak256 of its credential
    /// ID), the key a passkey is recognised by in another browser.
    pub fn authenticator_id_hash(&self) -> RelayResult<Option<String>> {
        Ok(match self.credential()? {
            OwnerCredentialProfile::WebAuthn {
                authenticator_id_hash,
                ..
            } => Some(authenticator_id_hash),
            _ => None,
        })
    }

    pub fn credential(&self) -> RelayResult<OwnerCredentialProfile> {
        let value = parse_json(&self.profile).map_err(|_| UNREADABLE)?;
        parse_owner_credential_profile(&value).map_err(|_| UNREADABLE)
    }

    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &["version", "signerId", "profileHash", "profile", "createdAt"],
            UNREADABLE,
        )?;
        version(r.get("version"), SIGNER_RECORD_VERSION)?;
        let record = Self {
            version: SIGNER_RECORD_VERSION,
            signer_id: identifier(r.get("signerId"))?,
            profile_hash: text(r.get("profileHash"))?.to_owned(),
            profile: text(r.get("profile"))?.to_owned(),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
        };
        // The stored profile must be the canonical form behind the stored hash.
        let credential = record.credential()?;
        let canonical = credential.to_json().to_string();
        if record.profile != canonical || record.profile_hash != hex_hash(credential.hash()) {
            return Err(UNREADABLE);
        }
        Ok(record)
    }
}

/// One factory-derived Kernel 0.4.0 account whose single policy-free root is
/// its root signer's credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRecord {
    pub version: &'static str,
    pub account_id: String,
    /// Lowercase counterfactual address.
    pub address: String,
    pub root_signer_id: String,
    pub account_index: u64,
    /// The ECDSA root validator the address binds (the bootstrap
    /// `ownerValidator`), or none for a protocol-pinned validator.
    pub owner_validator: Option<String>,
    /// Canonical JSON of the protocol `KernelDerivedAccountProfile`.
    pub profile: String,
    pub created_at: u64,
}

impl AccountRecord {
    pub fn account_profile(&self) -> RelayResult<KernelAccountProfile> {
        let value = parse_json(&self.profile).map_err(|_| UNREADABLE)?;
        parse_kernel_account_profile(&value).map_err(|_| UNREADABLE)
    }

    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "accountId",
                "address",
                "rootSignerId",
                "accountIndex",
                "ownerValidator",
                "profile",
                "createdAt",
            ],
            UNREADABLE,
        )?;
        version(r.get("version"), ACCOUNT_RECORD_VERSION)?;
        let record = Self {
            version: ACCOUNT_RECORD_VERSION,
            account_id: identifier(r.get("accountId"))?,
            address: text(r.get("address"))?.to_owned(),
            root_signer_id: identifier(r.get("rootSignerId"))?,
            account_index: timestamp(r.get("accountIndex"), UNREADABLE)?,
            owner_validator: match r.get("ownerValidator") {
                Some(Value::Null) => None,
                other => Some(text(other)?.to_owned()),
            },
            profile: text(r.get("profile"))?.to_owned(),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
        };
        // Only a canonical factory-derived profile at the stored index and
        // its derived address.
        let account = record.account_profile()?;
        let canonical = account.to_json().to_string();
        let KernelAccountProfile::Derived(profile) = &account else {
            return Err(UNREADABLE);
        };
        if profile.factory_route != KernelFactoryRoute::KernelFactory
            || profile.account_index != record.account_index.to_string()
            || record.profile != canonical
            || owner_validator_for(&profile.owner_credential) != record.owner_validator
            || derive_account_address(&account, record.owner_validator.as_deref()).as_deref()
                != Some(record.address.as_str())
        {
            return Err(UNREADABLE);
        }
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MembershipRole {
    /// The account's single policy-free root validator.
    Root,
    /// A signer the root admitted: login-only through a link approval, or
    /// policy-bound through a root-signed enable.
    Permission,
}

impl MembershipRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Permission => "permission",
        }
    }
}

/// One account ↔ signer index row. A root carries no evidence; a permission
/// membership points at exactly one approval: the grant (`request_id`) or the
/// link (`link_id`) its root signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSignerRecord {
    pub version: &'static str,
    pub account_id: String,
    pub signer_id: String,
    pub role: MembershipRole,
    pub request_id: Option<String>,
    pub link_id: Option<String>,
    pub created_at: u64,
}

impl AccountSignerRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "accountId",
                "signerId",
                "role",
                "requestId",
                "linkId",
                "createdAt",
            ],
            UNREADABLE,
        )?;
        version(r.get("version"), ACCOUNT_SIGNER_RECORD_VERSION)?;
        let role = match r.get("role").and_then(Value::as_str) {
            Some("root") => MembershipRole::Root,
            Some("permission") => MembershipRole::Permission,
            _ => return Err(UNREADABLE),
        };
        let optional = |key| match r.get(key) {
            Some(Value::Null) => Ok(None),
            other => identifier(other).map(Some),
        };
        let request_id = optional("requestId")?;
        let link_id = optional("linkId")?;
        let evidence = usize::from(request_id.is_some()) + usize::from(link_id.is_some());
        if evidence != usize::from(role == MembershipRole::Permission) {
            return Err(UNREADABLE);
        }
        Ok(Self {
            version: ACCOUNT_SIGNER_RECORD_VERSION,
            account_id: identifier(r.get("accountId"))?,
            signer_id: identifier(r.get("signerId"))?,
            role,
            request_id,
            link_id,
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
        })
    }
}
