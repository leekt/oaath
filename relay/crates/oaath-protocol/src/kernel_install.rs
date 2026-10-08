//! The exact Kernel v4 replayable-install signing profile
//! (`kernel-v4-replayable-install.ts`).

use alloy_primitives::B256;
use serde_json::{Value, json};

use crate::capture::{ZERO_ADDRESS, is_lower_hex_bytes, lower_address};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure, fail};
use crate::identity::OwnerCredentialProfile;
use crate::signing_request::{
    Eip712OwnerSigningRequest, Eip712SigningPurpose, OwnerSigningRequest,
    parse_owner_signing_request,
};

const CODE: ErrorCode = ErrorCode::SigningRequestInvalid;
const MAX_PACKAGES: usize = 256;
const MODULE_TYPES: [(&str, u8); 6] =
    [("1", 1), ("2", 2), ("3", 3), ("5", 5), ("6", 6), ("11", 11)];

/// One ERC-7579 install inside a Kernel enable package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelInstall {
    pub module_type: u8,
    pub module: String,
    pub module_data: String,
    pub internal_data: String,
}

/// An owner-signing request refined to the one exact Kernel 0.4.0 chainless
/// enable-replayable install whose signer, typed data, digest, and replay
/// nonce all describe the same install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelReplayableInstallOwnerSigningRequest {
    pub request: Eip712OwnerSigningRequest,
    pub nonce: String,
    pub packages: Vec<KernelInstall>,
}

impl KernelReplayableInstallOwnerSigningRequest {
    pub fn owner_credential(&self) -> &OwnerCredentialProfile {
        &self.request.signer.owner_credential
    }

    pub fn expected_digest(&self) -> &str {
        &self.request.expected_digest
    }

    /// `hashOwnerSigningRequest` of the underlying request.
    pub fn hash(&self) -> B256 {
        OwnerSigningRequest::Eip712(Box::new(self.request.clone()))
            .hash()
            .expect("a refined Kernel request hashes")
    }

    pub fn to_json(&self) -> Value {
        OwnerSigningRequest::Eip712(Box::new(self.request.clone())).to_json()
    }
}

fn capture_install(value: &Value) -> ProtocolResult<KernelInstall> {
    let record = value.as_object().or_fail(CODE)?;
    let module_type = record.get("moduleType").and_then(Value::as_str);
    let module_type = MODULE_TYPES
        .iter()
        .find(|(text, _)| Some(*text) == module_type)
        .map(|(_, module_type)| *module_type);
    let module = record
        .get("module")
        .and_then(lower_address)
        .filter(|text| *text != ZERO_ADDRESS);
    let bytes = |key: &str| {
        record
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| is_lower_hex_bytes(text))
            .map(str::to_owned)
    };
    Ok(KernelInstall {
        module_type: module_type.or_fail(CODE)?,
        module: module.or_fail(CODE)?.to_owned(),
        module_data: bytes("moduleData").or_fail(CODE)?,
        internal_data: bytes("internalData").or_fail(CODE)?,
    })
}

/// A type-5 policy opens a permission that type-6 signers close in order.
pub(crate) fn validate_package_sequence(packages: &[KernelInstall]) -> ProtocolResult<()> {
    ensure((1..=MAX_PACKAGES).contains(&packages.len()), CODE)?;
    let mut pending: Option<&str> = None;
    for install in packages {
        if install.module_type != 5 && install.module_type != 6 {
            continue;
        }
        ensure(install.internal_data.len() >= 10, CODE)?;
        let permission = &install.internal_data[..10];
        ensure(pending.is_none_or(|pending| pending == permission), CODE)?;
        ensure(install.module_type != 6 || pending.is_some(), CODE)?;
        pending = (install.module_type == 5).then_some(permission);
    }
    ensure(pending.is_none(), CODE)
}

/// The exact `InstallPackages` EIP-712 typed data a Kernel 0.4.0 replayable
/// install signs: chainless domain, the account as verifying contract.
pub fn kernel_v4_replayable_install_typed_data(
    account: &str,
    nonce: &str,
    packages: &[KernelInstall],
) -> Value {
    let packages: Vec<Value> = packages
        .iter()
        .map(|install| {
            json!({
                "moduleType": install.module_type.to_string(),
                "module": install.module,
                "moduleData": install.module_data,
                "internalData": install.internal_data,
            })
        })
        .collect();
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "InstallPackages": [
                {"name": "nonce", "type": "uint256"},
                {"name": "packages", "type": "Install[]"},
            ],
            "Install": [
                {"name": "moduleType", "type": "uint256"},
                {"name": "module", "type": "address"},
                {"name": "moduleData", "type": "bytes"},
                {"name": "internalData", "type": "bytes"},
            ],
        },
        "primaryType": "InstallPackages",
        "domain": {"name": "Kernel", "version": "0.4.0", "verifyingContract": account},
        "message": {"nonce": nonce, "packages": packages},
    })
}

pub fn parse_kernel_replayable_install_owner_signing_request(
    value: &Value,
) -> ProtocolResult<KernelReplayableInstallOwnerSigningRequest> {
    let OwnerSigningRequest::Eip712(request) = parse_owner_signing_request(value)? else {
        return fail(CODE);
    };
    ensure(
        request.purpose == Eip712SigningPurpose::KernelEnable && request.replay.deadline.is_none(),
        CODE,
    )?;
    let nonce = request.replay.nonce.clone().or_fail(CODE)?;
    let packages = request
        .typed_data
        .message
        .get("packages")
        .and_then(Value::as_array)
        .or_fail(CODE)?
        .iter()
        .map(capture_install)
        .collect::<ProtocolResult<Vec<_>>>()?;
    validate_package_sequence(&packages)?;
    ensure(
        request.typed_data.to_json()
            == kernel_v4_replayable_install_typed_data(&request.signer.account, &nonce, &packages),
        CODE,
    )?;
    let digest = crate::identity::hex_hash(request.typed_data.hash()?);
    ensure(request.expected_digest == digest, CODE)?;
    Ok(KernelReplayableInstallOwnerSigningRequest {
        request: *request,
        nonce,
        packages,
    })
}
