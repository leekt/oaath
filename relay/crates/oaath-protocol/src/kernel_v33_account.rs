//! A Kernel 0.3.3 account's offline deployment, as the SDK's
//! `deriveKernelV33Account` (`kernel/deployment/v33.ts`): the ECDSA root's
//! `initialize` data, ZeroDev's MetaFactory `deployWithFactory` call, and the
//! KernelFactory's CREATE2 address of the proxy.

use alloy_primitives::{Address, B256, Bytes, FixedBytes, keccak256};
use alloy_sol_types::{SolCall, sol};

/// ZeroDev's `metaFactoryAddress` (FactoryStaker).
pub const KERNEL_V33_META_FACTORY: &str = "0xd703aae79538628d27099b8c4f621be4ccd142d5";
/// The KernelFactory `deployWithFactory` forwards to.
pub const KERNEL_V33_FACTORY: &str = "0x2577507b78c2008ff367261cb6285d44ba5ef2e9";
/// The ECDSA validator every Kernel 0.3.3 root here uses.
pub const KERNEL_V33_ECDSA_VALIDATOR: &str = "0x845adb2c711129d4f3966735ed98a9f09fc4ce57";
/// Solady's ERC-1967 proxy creation-code hash for the Kernel 0.3.3 implementation.
const PROXY_INIT_CODE_HASH: &str =
    "0xc452397f1e7518f8cea0566ac057e243bb1643f6298aba8eec8cdee78ee3b3dd";

sol! {
    function initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig);
    function deployWithFactory(address factory, bytes createData, bytes32 salt);
}

fn address(text: &str) -> Address {
    text.parse().expect("pinned address")
}

/// `initialize(0x01 ‖ ECDSA validator, no hook, owner, 0x, [])`.
fn init_data(owner: Address) -> Vec<u8> {
    let mut root = [0u8; 21];
    root[0] = 0x01;
    root[1..].copy_from_slice(address(KERNEL_V33_ECDSA_VALIDATOR).as_slice());
    initializeCall {
        rootValidator: FixedBytes(root),
        hook: Address::ZERO,
        validatorData: Bytes::from(owner.to_vec()),
        hookData: Bytes::new(),
        initConfig: Vec::new(),
    }
    .abi_encode()
}

/// The CREATE2 address the KernelFactory deploys `init` at for `index`.
fn proxy_address(init: &[u8], index: B256) -> Address {
    let salt = keccak256([init, index.as_slice()].concat());
    let hash: B256 = PROXY_INIT_CODE_HASH.parse().expect("pinned hash");
    address(KERNEL_V33_FACTORY).create2(salt, hash)
}

/// Whether `factory`/`data` deploy the Kernel 0.3.3 account `sender` whose
/// ECDSA root is `owner`: the MetaFactory's `deployWithFactory` of the
/// KernelFactory with that owner's `initialize`, at an index whose CREATE2
/// address is exactly `sender`.
pub fn is_kernel_v33_deployment(owner: &str, sender: &str, factory: &str, data: &str) -> bool {
    let (Ok(owner), Ok(sender)) = (owner.parse::<Address>(), sender.parse::<Address>()) else {
        return false;
    };
    let Some(digits) = data.strip_prefix("0x") else {
        return false;
    };
    let Ok(bytes) = hex::decode(digits) else {
        return false;
    };
    let Ok(call) = deployWithFactoryCall::abi_decode(&bytes) else {
        return false;
    };
    let init = init_data(owner);
    factory == KERNEL_V33_META_FACTORY
        && call.factory == address(KERNEL_V33_FACTORY)
        && call.createData.as_ref() == init.as_slice()
        // Canonical encoding only: the call re-encodes to exactly `data`.
        && call.abi_encode() == bytes
        && proxy_address(&init, call.salt) == sender
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment(owner: Address, index: u64) -> (Address, String) {
        let init = init_data(owner);
        let salt = B256::from(alloy_primitives::U256::from(index));
        let data = deployWithFactoryCall {
            factory: address(KERNEL_V33_FACTORY),
            createData: Bytes::from(init.clone()),
            salt,
        }
        .abi_encode();
        (
            proxy_address(&init, salt),
            format!("0x{}", hex::encode(data)),
        )
    }

    #[test]
    fn accepts_exactly_the_owners_deployment_at_its_index() {
        let owner = Address::repeat_byte(0x11);
        let (sender, data) = deployment(owner, 7);
        let (owner_text, sender_text) = (format!("{owner:#x}"), format!("{sender:#x}"));
        assert!(is_kernel_v33_deployment(
            &owner_text,
            &sender_text,
            KERNEL_V33_META_FACTORY,
            &data
        ));
        // Another factory, owner, or sender.
        assert!(!is_kernel_v33_deployment(
            &owner_text,
            &sender_text,
            KERNEL_V33_FACTORY,
            &data
        ));
        let other = format!("{:#x}", Address::repeat_byte(0x22));
        assert!(!is_kernel_v33_deployment(
            &other,
            &sender_text,
            KERNEL_V33_META_FACTORY,
            &data
        ));
        let (elsewhere, _) = deployment(owner, 8);
        assert!(!is_kernel_v33_deployment(
            &owner_text,
            &format!("{elsewhere:#x}"),
            KERNEL_V33_META_FACTORY,
            &data
        ));
        assert!(!is_kernel_v33_deployment(
            &owner_text,
            &sender_text,
            KERNEL_V33_META_FACTORY,
            "0x1234"
        ));
    }
}
