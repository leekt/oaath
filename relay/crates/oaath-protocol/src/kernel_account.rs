//! Offline counterfactual address of a factory-derived Kernel 0.4.0 account
//! (EntryPoint 0.9), as `KernelFactory.getAddress(initialPackages, index)`
//! computes it. The SDK reads that view from the chain; every input is a
//! chain-independent CREATE2 constant, so no chain call is needed.

use alloy_primitives::{Address, B256, U256, keccak256};

use crate::capture::hex_bytes;
use crate::error::{ErrorCode, ProtocolResult, ensure, fail};
use crate::identity::{
    KernelDerivedAccountProfile, KernelFactoryRoute, OwnerCredentialProfile, address_of, b256_of,
};

/// `KernelFactory` for EntryPoint 0.9 (zero-salt CREATE2 deployment).
const KERNEL_V4_FACTORY: &str = "0x3d6d678742e276b6388fd06c1b8ecd19e2d64c2d";
/// The factory's `UUPS` implementation each account proxy delegates to.
const KERNEL_V4_UUPS_IMPLEMENTATION: &str = "0x6250926dd0309d9deaaeb4a2c413da5f3c4de37a";
/// The reviewed raw P-256 root validator.
const KERNEL_V4_P256_VALIDATOR: &str = "0x9906ab44ff795883c5a725687a2705be4118b0f3";
/// The reviewed WebAuthn root validator.
const KERNEL_V4_WEBAUTHN_VALIDATOR: &str = "0x6f781fff97b830daa2e11ee0ad6344aff7131ef2";

const CODE: ErrorCode = ErrorCode::KernelAccountDerivationInvalid;
const ROOT_VALIDATOR_MODULE_TYPE: u64 = 1;

/// The validator address a caller binds for an ECDSA root: lowercase or mixed
/// case hex (as the SDK's `getAddress` accepts), nonzero.
fn owner_validator(value: &str) -> ProtocolResult<Address> {
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 40 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let Some(digits) = digits else {
        return fail(CODE);
    };
    let validator = address_of(&format!("0x{}", digits.to_ascii_lowercase()));
    ensure(validator != Address::ZERO, CODE)?;
    Ok(validator)
}

/// The root validator and the public material it installs, byte-identical to
/// the SDK owner operator's package for the credential.
fn root_package(
    owner: &OwnerCredentialProfile,
    validator: Option<&str>,
) -> ProtocolResult<(Address, Vec<u8>)> {
    let point = |public_key: &str| hex_bytes(public_key)[1..].to_vec();
    match (owner, validator) {
        (OwnerCredentialProfile::Ecdsa { address }, Some(validator)) => {
            Ok((owner_validator(validator)?, hex_bytes(address)))
        }
        (OwnerCredentialProfile::P256 { public_key }, None) => {
            Ok((address_of(KERNEL_V4_P256_VALIDATOR), point(public_key)))
        }
        (
            OwnerCredentialProfile::WebAuthn {
                public_key,
                authenticator_id_hash,
            },
            None,
        ) => {
            let mut material = point(public_key);
            material.extend_from_slice(b256_of(authenticator_id_hash).as_slice());
            Ok((address_of(KERNEL_V4_WEBAUTHN_VALIDATOR), material))
        }
        _ => fail(CODE),
    }
}

/// `KernelFactory._calculateSalt` for one policy-free root validator package.
fn salt(index: U256, validator: Address, module_data: &[u8]) -> B256 {
    let mut package = U256::from(ROOT_VALIDATOR_MODULE_TYPE)
        .to_be_bytes::<32>()
        .to_vec();
    package.extend_from_slice(validator.into_word().as_slice());
    package.extend_from_slice(keccak256(module_data).as_slice());
    // The root package installs no selectors: its internalData is empty.
    package.extend_from_slice(keccak256([]).as_slice());
    let mut buffer = index.to_be_bytes::<32>().to_vec();
    buffer.extend_from_slice(keccak256(package).as_slice());
    keccak256(buffer)
}

/// Solady `LibClone.initCodeHashERC1967(implementation)`.
fn erc1967_init_code_hash(implementation: Address) -> B256 {
    let mut init_code = hex::decode("603d3d8160223d3973").expect("constant");
    init_code.extend_from_slice(implementation.as_slice());
    init_code.extend_from_slice(&hex::decode("6009").expect("constant"));
    init_code.extend_from_slice(
        &hex::decode("5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076")
            .expect("constant"),
    );
    init_code.extend_from_slice(
        &hex::decode("cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3")
            .expect("constant"),
    );
    keccak256(init_code)
}

/// The lowercase counterfactual address of a factory-derived Kernel 0.4.0
/// account whose single root is the profile's owner credential.
///
/// `owner_validator` is the deployment-bound ECDSA root validator (Kernel v4
/// pins none) and must be `None` for P-256 and WebAuthn, whose validators are
/// pinned. The meta-factory route is not derivable.
pub fn derive_kernel_v4_account_address(
    profile: &KernelDerivedAccountProfile,
    owner_validator: Option<&str>,
) -> ProtocolResult<String> {
    ensure(
        profile.factory_route == KernelFactoryRoute::KernelFactory,
        CODE,
    )?;
    let (validator, module_data) = root_package(&profile.owner_credential, owner_validator)?;
    let index = U256::from_str_radix(&profile.account_index, 10).expect("captured uint256");
    let address = address_of(KERNEL_V4_FACTORY).create2(
        salt(index, validator, &module_data),
        erc1967_init_code_hash(address_of(KERNEL_V4_UUPS_IMPLEMENTATION)),
    );
    Ok(format!("0x{}", hex::encode(address)))
}
