//! Closed Kernel v4 revocation calls (`kernel-v4-revocation.ts`). No
//! submission, authority decision, chain observation or finality lives here.

use alloy_primitives::aliases::U192;
use alloy_primitives::{Bytes, U256, keccak256};
use alloy_sol_types::SolValue;
use serde_json::Value;

use crate::capture::{ZERO_ADDRESS, exact_record, field, is_lower_hex_bytes, lower_address};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure};
use crate::identity::{address_of, bytes_of};
use crate::kernel_install::{KernelInstall, validate_package_sequence};
use crate::owner_operation::OwnerOperationCall;

const CODE: ErrorCode = ErrorCode::SigningRequestInvalid;
const MODULE_TYPES: [u8; 6] = [1, 2, 3, 5, 6, 11];

fn capture_install(value: &Value) -> ProtocolResult<KernelInstall> {
    let record = exact_record(
        value,
        &["moduleType", "module", "moduleData", "internalData"],
    )
    .or_fail(CODE)?;
    let module_type = field(record, "moduleType")
        .as_u64()
        .and_then(|number| u8::try_from(number).ok())
        .filter(|number| MODULE_TYPES.contains(number))
        .or_fail(CODE)?;
    let module = lower_address(field(record, "module"))
        .filter(|text| *text != ZERO_ADDRESS)
        .or_fail(CODE)?;
    let bytes = |key: &str| {
        field(record, key)
            .as_str()
            .filter(|text| is_lower_hex_bytes(text))
            .map(str::to_owned)
            .or_fail(CODE)
    };
    Ok(KernelInstall {
        module_type,
        module: module.to_owned(),
        module_data: bytes("moduleData")?,
        internal_data: bytes("internalData")?,
    })
}

/// An install approval's `packages`, as `parseKernelInstallPackages` captures them.
pub fn parse_kernel_install_packages(value: &Value) -> ProtocolResult<Vec<KernelInstall>> {
    let entries = value.as_array().or_fail(CODE)?;
    let packages = entries
        .iter()
        .map(capture_install)
        .collect::<ProtocolResult<Vec<_>>>()?;
    validate_package_sequence(&packages)?;
    Ok(packages)
}

/// `uninstallModule(uint256,address,bytes)` self-calls that remove one
/// permission: its policies in reverse install order, then its one signer.
/// Kernel requires that order; the install packages own the permission
/// identity and module data. Input: `{account, packages}`.
pub fn kernel_permission_uninstall_calls(value: &Value) -> ProtocolResult<Vec<OwnerOperationCall>> {
    let record = exact_record(value, &["account", "packages"]).or_fail(CODE)?;
    let account = lower_address(field(record, "account"))
        .filter(|text| *text != ZERO_ADDRESS)
        .or_fail(CODE)?
        .to_owned();
    let packages = parse_kernel_install_packages(field(record, "packages"))?;
    let policies: Vec<&KernelInstall> = packages.iter().filter(|p| p.module_type == 5).collect();
    let signers: Vec<&KernelInstall> = packages.iter().filter(|p| p.module_type == 6).collect();
    ensure(
        signers.len() == 1 && policies.len() + 1 == packages.len(),
        CODE,
    )?;
    ensure(packages.iter().all(|p| p.module_data.len() >= 66), CODE)?;
    let selector = &keccak256("uninstallModule(uint256,address,bytes)".as_bytes())[..4];
    Ok(policies
        .into_iter()
        .rev()
        .chain(signers)
        .map(|install| {
            let init = (
                bytes_of(&install.module_data[..66]),
                bytes_of(&install.internal_data),
            )
                .abi_encode_params();
            let mut data = selector.to_vec();
            data.extend(
                (
                    U256::from(install.module_type),
                    address_of(&install.module),
                    Bytes::from(init),
                )
                    .abi_encode_params(),
            );
            OwnerOperationCall {
                target: account.clone(),
                value: "0".to_owned(),
                data: format!("0x{}", hex::encode(data)),
            }
        })
        .collect())
}

/// An owner self-call that invalidates an unused install approval on one
/// chain: `setNonce(key, sequence + 1)` for the approval's install nonce
/// `key << 64 | sequence`. Kernel requires the stored sequence to increase, so
/// an approval already consumed or invalidated needs observation, not this.
/// Input: `{account, installNonce}`.
pub fn kernel_install_nonce_invalidation_call(value: &Value) -> ProtocolResult<OwnerOperationCall> {
    let record = exact_record(value, &["account", "installNonce"]).or_fail(CODE)?;
    let account = lower_address(field(record, "account"))
        .filter(|text| *text != ZERO_ADDRESS)
        .or_fail(CODE)?
        .to_owned();
    let nonce = field(record, "installNonce")
        .as_str()
        .filter(|text| crate::capture::is_canonical_decimal(text, 78))
        .and_then(|text| U256::from_str_radix(text, 10).ok())
        .or_fail(CODE)?;
    let max_u64 = U256::from(u64::MAX);
    let sequence = nonce & max_u64;
    ensure(sequence != max_u64, CODE)?;
    let key = U192::from(nonce >> 64);
    let selector = &keccak256("setNonce(uint192,uint64)".as_bytes())[..4];
    let mut data = selector.to_vec();
    data.extend((key, sequence + U256::from(1)).abi_encode_params());
    Ok(OwnerOperationCall {
        target: account,
        value: "0".to_owned(),
        data: format!("0x{}", hex::encode(data)),
    })
}
