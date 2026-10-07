//! Owner, operator, and Kernel account identity profiles (`identity-profile.ts`).

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolValue;
use serde_json::{Value, json};

use crate::capture::{
    Record, ZERO_ADDRESS, capture_record, decimal_uint256, exact_record, field, has_exact_keys,
    hex_bytes, lower_hash,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure, fail};

pub const OWNER_CREDENTIAL_PROFILE_VERSION: &str = "oaath.owner-credential-profile/v1";
pub const OPERATOR_CREDENTIAL_PROFILE_VERSION: &str = "oaath.operator-credential-profile/v1";
pub const KERNEL_ACCOUNT_PROFILE_VERSION: &str = "oaath.kernel-account-profile/v1";
pub const KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION: &str =
    "oaath.kernel-existing-account-profile/v3";
const OWNER_CREDENTIAL_PROFILE_HASH_DOMAIN: &str = "@oaath/protocol:owner-credential-profile";
const OPERATOR_PROFILE_HASH_DOMAIN: &str = "@oaath/protocol:operator-credential-profile";
const KERNEL_PROFILE_HASH_DOMAIN: &str = "@oaath/protocol:kernel-account-profile";

/// Owner credential public material. Hex fields are canonical lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerCredentialProfile {
    Ecdsa {
        address: String,
    },
    P256 {
        public_key: String,
    },
    WebAuthn {
        public_key: String,
        authenticator_id_hash: String,
    },
}

/// Operator (session) credential public material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorCredentialProfile {
    Ecdsa {
        address: String,
    },
    WebAuthn {
        public_key: String,
        authenticator_id_hash: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFactoryRoute {
    KernelFactory,
    MetaFactory,
}

impl KernelFactoryRoute {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelFactory => "kernel_factory",
            Self::MetaFactory => "meta_factory",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelExistingAccountVersion {
    V0_3_3,
    V0_4_0,
}

impl KernelExistingAccountVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V0_3_3 => "0.3.3",
            Self::V0_4_0 => "0.4.0",
        }
    }

    /// The EntryPoint version each Kernel deployment pins.
    pub const fn entry_point_version(self) -> &'static str {
        match self {
            Self::V0_3_3 => "0.7",
            Self::V0_4_0 => "0.9",
        }
    }
}

/// A Kernel 0.4.0 account derived from its owner and index (EntryPoint 0.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelDerivedAccountProfile {
    pub account_index: String,
    pub factory_route: KernelFactoryRoute,
    pub owner_credential: OwnerCredentialProfile,
}

/// An existing account at its address. The owner is ECDSA, or P-256 on 0.4.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelExistingAccountProfile {
    pub kernel_version: KernelExistingAccountVersion,
    pub address: String,
    pub owner_credential: OwnerCredentialProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelAccountProfile {
    Derived(KernelDerivedAccountProfile),
    Existing(KernelExistingAccountProfile),
}

impl KernelAccountProfile {
    pub fn owner_credential(&self) -> &OwnerCredentialProfile {
        match self {
            Self::Derived(profile) => &profile.owner_credential,
            Self::Existing(profile) => &profile.owner_credential,
        }
    }

    pub fn is_existing(&self) -> bool {
        matches!(self, Self::Existing(_))
    }
}

/// `isAddress(value, { strict: true })`: lowercase or exact EIP-55, captured
/// lowercase and nonzero.
fn checksummed_address(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let digits = text.strip_prefix("0x")?;
    if digits.len() != 40 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let lowercase = text.to_ascii_lowercase();
    if text != lowercase && text != text.parse::<Address>().ok()?.to_checksum(None) {
        return None;
    }
    (lowercase != ZERO_ADDRESS).then_some(lowercase)
}

/// `^0x04[0-9a-f]{128}$` naming a point on P-256.
pub(crate) fn p256_public_key(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    if !text.starts_with("0x04") || !crate::capture::is_lower_hex(text, 65) {
        return None;
    }
    p256::PublicKey::from_sec1_bytes(&hex_bytes(text))
        .ok()
        .map(|_| text)
}

pub(crate) fn capture_owner_credential(
    value: &Value,
    code: ErrorCode,
) -> ProtocolResult<OwnerCredentialProfile> {
    let record = capture_record(value).or_fail(code)?;
    let kind = record.get("kind").and_then(Value::as_str);
    let keys: &[&str] = match kind {
        Some("ecdsa") => &["version", "kind", "address"],
        Some("p256") => &["version", "kind", "publicKey"],
        Some("webauthn") => &["version", "kind", "publicKey", "authenticatorIdHash"],
        _ => &["version", "kind"],
    };
    ensure(has_exact_keys(record, keys), code)?;
    ensure(
        field(record, "version") == OWNER_CREDENTIAL_PROFILE_VERSION,
        code,
    )?;
    match kind {
        Some("ecdsa") => Ok(OwnerCredentialProfile::Ecdsa {
            address: checksummed_address(field(record, "address")).or_fail(code)?,
        }),
        Some("p256") => Ok(OwnerCredentialProfile::P256 {
            public_key: p256_public_key(field(record, "publicKey"))
                .or_fail(code)?
                .to_owned(),
        }),
        Some("webauthn") => Ok(OwnerCredentialProfile::WebAuthn {
            public_key: p256_public_key(field(record, "publicKey"))
                .or_fail(code)?
                .to_owned(),
            authenticator_id_hash: lower_hash(field(record, "authenticatorIdHash"))
                .or_fail(code)?
                .to_owned(),
        }),
        _ => fail(code),
    }
}

pub(crate) fn capture_operator_credential(
    value: &Value,
    code: ErrorCode,
) -> ProtocolResult<OperatorCredentialProfile> {
    let record = capture_record(value).or_fail(code)?;
    let kind = record.get("kind").and_then(Value::as_str);
    let keys: &[&str] = match kind {
        Some("ecdsa") => &["version", "kind", "address"],
        Some("webauthn") => &["version", "kind", "publicKey", "authenticatorIdHash"],
        _ => &["version", "kind"],
    };
    ensure(has_exact_keys(record, keys), code)?;
    ensure(
        field(record, "version") == OPERATOR_CREDENTIAL_PROFILE_VERSION,
        code,
    )?;
    match kind {
        Some("ecdsa") => Ok(OperatorCredentialProfile::Ecdsa {
            address: checksummed_address(field(record, "address")).or_fail(code)?,
        }),
        Some("webauthn") => Ok(OperatorCredentialProfile::WebAuthn {
            public_key: p256_public_key(field(record, "publicKey"))
                .or_fail(code)?
                .to_owned(),
            authenticator_id_hash: lower_hash(field(record, "authenticatorIdHash"))
                .or_fail(code)?
                .to_owned(),
        }),
        _ => fail(code),
    }
}

pub(crate) fn capture_kernel_account(
    value: &Value,
    code: ErrorCode,
) -> ProtocolResult<KernelAccountProfile> {
    let record: &Record = capture_record(value).or_fail(code)?;
    let existing = record.get("version").and_then(Value::as_str)
        == Some(KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION);
    let keys: &[&str] = if existing {
        &[
            "version",
            "kind",
            "kernelVersion",
            "address",
            "entryPoint",
            "ownerCredential",
        ]
    } else {
        &[
            "version",
            "kind",
            "kernelVersion",
            "accountIndex",
            "factoryRoute",
            "entryPoint",
            "ownerCredential",
        ]
    };
    ensure(has_exact_keys(record, keys), code)?;
    let expected_version = if existing {
        KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION
    } else {
        KERNEL_ACCOUNT_PROFILE_VERSION
    };
    ensure(
        field(record, "version") == expected_version && field(record, "kind") == "kernel",
        code,
    )?;
    let kernel_version = match field(record, "kernelVersion").as_str() {
        Some("0.4.0") => KernelExistingAccountVersion::V0_4_0,
        Some("0.3.3") if existing => KernelExistingAccountVersion::V0_3_3,
        _ => return fail(code),
    };
    let factory_route = match field(record, "factoryRoute").as_str() {
        Some("kernel_factory") => Some(KernelFactoryRoute::KernelFactory),
        Some("meta_factory") => Some(KernelFactoryRoute::MetaFactory),
        _ => None,
    };
    ensure(existing || factory_route.is_some(), code)?;
    let entry_point = exact_record(field(record, "entryPoint"), &["version"]).or_fail(code)?;
    ensure(
        field(entry_point, "version") == kernel_version.entry_point_version(),
        code,
    )?;
    let owner_credential = capture_owner_credential(field(record, "ownerCredential"), code)?;
    if existing {
        // Only a root owner the account's validator exposes is provable onchain.
        ensure(
            match owner_credential {
                OwnerCredentialProfile::Ecdsa { .. } => true,
                OwnerCredentialProfile::P256 { .. } => {
                    kernel_version == KernelExistingAccountVersion::V0_4_0
                }
                OwnerCredentialProfile::WebAuthn { .. } => false,
            },
            code,
        )?;
        return Ok(KernelAccountProfile::Existing(
            KernelExistingAccountProfile {
                kernel_version,
                address: checksummed_address(field(record, "address")).or_fail(code)?,
                owner_credential,
            },
        ));
    }
    Ok(KernelAccountProfile::Derived(KernelDerivedAccountProfile {
        account_index: decimal_uint256(field(record, "accountIndex"))
            .or_fail(code)?
            .to_owned(),
        factory_route: factory_route.or_fail(code)?,
        owner_credential,
    }))
}

pub fn parse_owner_credential_profile(value: &Value) -> ProtocolResult<OwnerCredentialProfile> {
    capture_owner_credential(value, ErrorCode::OwnerCredentialProfileInvalid)
}

pub fn parse_operator_credential_profile(
    value: &Value,
) -> ProtocolResult<OperatorCredentialProfile> {
    capture_operator_credential(value, ErrorCode::OperatorCredentialProfileInvalid)
}

pub fn parse_kernel_account_profile(value: &Value) -> ProtocolResult<KernelAccountProfile> {
    capture_kernel_account(value, ErrorCode::KernelAccountProfileInvalid)
}

pub(crate) fn address_of(text: &str) -> Address {
    Address::from_slice(&hex_bytes(text))
}

pub(crate) fn b256_of(text: &str) -> B256 {
    B256::from_slice(&hex_bytes(text))
}

pub(crate) fn bytes_of(text: &str) -> Bytes {
    Bytes::from(hex_bytes(text))
}

pub(crate) fn hex_hash(hash: B256) -> String {
    format!("0x{}", hex::encode(hash))
}

impl OwnerCredentialProfile {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ecdsa { .. } => "ecdsa",
            Self::P256 { .. } => "p256",
            Self::WebAuthn { .. } => "webauthn",
        }
    }

    /// Stable owner-credential identity hash; it grants no authority by itself.
    pub fn hash(&self) -> B256 {
        let domain = OWNER_CREDENTIAL_PROFILE_HASH_DOMAIN.to_owned();
        let version = OWNER_CREDENTIAL_PROFILE_VERSION.to_owned();
        let kind = self.kind().to_owned();
        keccak256(match self {
            Self::Ecdsa { address } => {
                (domain, version, kind, address_of(address)).abi_encode_params()
            }
            Self::P256 { public_key } => {
                (domain, version, kind, bytes_of(public_key)).abi_encode_params()
            }
            Self::WebAuthn {
                public_key,
                authenticator_id_hash,
            } => (
                domain,
                version,
                kind,
                bytes_of(public_key),
                b256_of(authenticator_id_hash),
            )
                .abi_encode_params(),
        })
    }

    pub fn to_json(&self) -> Value {
        let version = OWNER_CREDENTIAL_PROFILE_VERSION;
        match self {
            Self::Ecdsa { address } => {
                json!({"version": version, "kind": "ecdsa", "address": address})
            }
            Self::P256 { public_key } => {
                json!({"version": version, "kind": "p256", "publicKey": public_key})
            }
            Self::WebAuthn {
                public_key,
                authenticator_id_hash,
            } => json!({
                "version": version,
                "kind": "webauthn",
                "publicKey": public_key,
                "authenticatorIdHash": authenticator_id_hash,
            }),
        }
    }
}

/// `hashOwnerCredentialProfile`: captures, then hashes.
pub fn hash_owner_credential_profile(value: &Value) -> ProtocolResult<String> {
    Ok(hex_hash(parse_owner_credential_profile(value)?.hash()))
}

impl OperatorCredentialProfile {
    pub(crate) fn hash(&self) -> B256 {
        let domain = OPERATOR_PROFILE_HASH_DOMAIN.to_owned();
        let version = OPERATOR_CREDENTIAL_PROFILE_VERSION.to_owned();
        keccak256(match self {
            Self::Ecdsa { address } => {
                (domain, version, "ecdsa".to_owned(), address_of(address)).abi_encode_params()
            }
            Self::WebAuthn {
                public_key,
                authenticator_id_hash,
            } => (
                domain,
                version,
                "webauthn".to_owned(),
                bytes_of(public_key),
                b256_of(authenticator_id_hash),
            )
                .abi_encode_params(),
        })
    }

    pub fn to_json(&self) -> Value {
        let version = OPERATOR_CREDENTIAL_PROFILE_VERSION;
        match self {
            Self::Ecdsa { address } => {
                json!({"version": version, "kind": "ecdsa", "address": address})
            }
            Self::WebAuthn {
                public_key,
                authenticator_id_hash,
            } => json!({
                "version": version,
                "kind": "webauthn",
                "publicKey": public_key,
                "authenticatorIdHash": authenticator_id_hash,
            }),
        }
    }
}

impl KernelAccountProfile {
    pub(crate) fn hash(&self) -> B256 {
        let domain = KERNEL_PROFILE_HASH_DOMAIN.to_owned();
        keccak256(match self {
            Self::Existing(profile) => (
                domain,
                KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION.to_owned(),
                "kernel".to_owned(),
                profile.kernel_version.as_str().to_owned(),
                address_of(&profile.address),
                profile.kernel_version.entry_point_version().to_owned(),
                profile.owner_credential.hash(),
            )
                .abi_encode_params(),
            Self::Derived(profile) => (
                domain,
                KERNEL_ACCOUNT_PROFILE_VERSION.to_owned(),
                "kernel".to_owned(),
                U256::from_str_radix(&profile.account_index, 10).expect("captured uint256"),
                "0.4.0".to_owned(),
                profile.factory_route.as_str().to_owned(),
                "0.9".to_owned(),
                profile.owner_credential.hash(),
            )
                .abi_encode_params(),
        })
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Existing(profile) => json!({
                "version": KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
                "kind": "kernel",
                "kernelVersion": profile.kernel_version.as_str(),
                "address": profile.address,
                "entryPoint": {"version": profile.kernel_version.entry_point_version()},
                "ownerCredential": profile.owner_credential.to_json(),
            }),
            Self::Derived(profile) => json!({
                "version": KERNEL_ACCOUNT_PROFILE_VERSION,
                "kind": "kernel",
                "accountIndex": profile.account_index,
                "kernelVersion": "0.4.0",
                "factoryRoute": profile.factory_route.as_str(),
                "entryPoint": {"version": "0.9"},
                "ownerCredential": profile.owner_credential.to_json(),
            }),
        }
    }
}
