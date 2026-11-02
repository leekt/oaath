//! The relay's one budgeted chain reader: the account-ownership proof an
//! import needs, and a revocation's permission state.
//!
//! ```text
//! OAATH_RPC_421614   one JSON-RPC URL for chain 421614; never logged
//! ```
//!
//! Only the read methods below are sent. One proof spends at most
//! `MAX_CALLS` requests, each bounded by `TIMEOUT`, with no retry and no
//! fallback URL. Every read is pinned to one block. An unreadable, timed-out,
//! noncanonical or contradictory answer refuses: unreadable is never absent.
//!
//! `prove_kernel_root` mirrors what the SDK's `bindAccount` proves for an
//! existing Kernel v4 account (`packages/sdk/src/kernel/create-kernel-runtime.ts`)
//! and what the portal shows before an import (`portal/src/account-import.ts`):
//!
//! 1. the endpoint serves the configured chain;
//! 2. the address has code that is not an EIP-7702 delegation;
//! 3. its ERC-1967 implementation slot names the reviewed Kernel v4
//!    implementation;
//! 4. `root()` is `0x01 ‖ the root validator for the signer's kind`;
//! 5. that validator stores this signer's key for the account: the ECDSA
//!    owner address, or the P-256 / WebAuthn `(x, y)`. As in the SDK, a
//!    WebAuthn validator stores no authenticator ID; it stays a client-side
//!    assertion binding.
//!
//! When the slot names the Kernel 0.3.3 implementation instead, it mirrors
//! the SDK's `bindKernelV33Account` (`kernel/deployment/v33.ts`) for an ECDSA
//! root: `accountId()`, `entrypoint()`, `rootValidator()` and the ECDSA
//! validator's stored owner.

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256};
use alloy_sol_types::{SolCall, SolValue, sol};
use oaath_protocol::identity::{KernelExistingAccountVersion, OwnerCredentialProfile};
use serde_json::{Value, json};

use crate::error::{RelayErrorCode, RelayResult};
use crate::registry::ECDSA_ROOT_VALIDATOR;

/// Arbitrum Sepolia, the portal's chain.
pub const IMPORT_CHAIN_ID: u64 = 421_614;
pub const MAX_CALLS: usize = 8;
pub const TIMEOUT: Duration = Duration::from_secs(8);
/// The reviewed Kernel v4 UUPS implementation (EntryPoint 0.9), as the SDK's
/// `KERNEL_V4_UUPS_IMPLEMENTATION_V09`.
pub const KERNEL_V4_IMPLEMENTATION: &str = "0x6250926dd0309d9deaaeb4a2c413da5f3c4de37a";
/// The Kernel 0.3.3 implementation (EntryPoint 0.7), its `accountId()`, and
/// EntryPoint 0.7, as the SDK's `kernelV33Deployment`.
pub const KERNEL_V33_IMPLEMENTATION: &str = "0xd6cedde84be40893d153be9d467cd6ad37875b28";
pub const KERNEL_V33_ACCOUNT_ID: &str = "kernel.advanced.v0.3.3";
pub const ENTRY_POINT_V07: &str = "0x0000000071727de22e5e9d8baf0edac6f37da032";
pub const P256_ROOT_VALIDATOR: &str = "0x9906ab44ff795883c5a725687a2705be4118b0f3";
pub const WEBAUTHN_ROOT_VALIDATOR: &str = "0x6f781fff97b830daa2e11ee0ad6344aff7131ef2";
/// ERC-1967 `implementation` slot.
const IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ALLOWED: [&str; 7] = [
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBlockByNumber",
    "eth_getCode",
    "eth_getBalance",
    "eth_getStorageAt",
    "eth_call",
];

const UNAVAILABLE: RelayErrorCode = RelayErrorCode::ChainUnavailable;
const REFUSED: RelayErrorCode = RelayErrorCode::Forbidden;

sol! {
    function balanceOf(address account) external view returns (uint256);
    function root() external view returns (bytes21);
    function ecdsaValidatorStorage(address account) external view returns (address);
    function publicKey(address account) external view returns (uint256 x, uint256 y);
    function webAuthnValidatorStorage(address account) external view returns (uint256 x, uint256 y);
    function isModuleInstalled(uint256 moduleType, address module, bytes additionalContext) external view returns (bool);
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);
    function nonce(uint192 key) external view returns (uint256);
    function accountId() external view returns (string);
    function entrypoint() external view returns (address);
    function rootValidator() external view returns (bytes21);
    function currentNonce() external view returns (uint32);
    function validationConfig(bytes21 validationId) external view returns (uint32 nonce, address hook);
}

/// One configured chain endpoint. Its URL is a credential: never printed.
pub struct ChainReader {
    chain_id: u64,
    url: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for ChainReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChainReader")
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl ChainReader {
    pub fn new(chain_id: u64, url: &str) -> Option<Self> {
        let parsed = url::Url::parse(url).ok()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(Self {
            chain_id,
            url: url.to_owned(),
            client,
        })
    }

    /// The same reader with a shorter per-request timeout (tests).
    pub fn with_timeout(mut self, timeout: Duration) -> Option<Self> {
        self.client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(self)
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// A fresh budget for one proof.
    fn session(&self) -> Reads<'_> {
        Reads {
            reader: self,
            used: 0,
        }
    }
}

struct Reads<'a> {
    reader: &'a ChainReader,
    used: usize,
}

impl Reads<'_> {
    async fn rpc(&mut self, method: &str, params: Value) -> RelayResult<Value> {
        if !ALLOWED.contains(&method) || self.used >= MAX_CALLS {
            return Err(UNAVAILABLE);
        }
        self.used += 1;
        let response = self
            .reader
            .client
            .post(&self.reader.url)
            .json(&json!({ "jsonrpc": "2.0", "id": self.used, "method": method, "params": params }))
            .send()
            .await
            .map_err(|_| UNAVAILABLE)?;
        if !response.status().is_success() {
            return Err(UNAVAILABLE);
        }
        let body: Value = response.json().await.map_err(|_| UNAVAILABLE)?;
        if body.get("error").is_some() {
            return Err(UNAVAILABLE);
        }
        body.get("result").cloned().ok_or(UNAVAILABLE)
    }

    /// A `0x` lowercase hex result.
    async fn hex(&mut self, method: &str, params: Value) -> RelayResult<Vec<u8>> {
        let result = self.rpc(method, params).await?;
        let text = result.as_str().ok_or(UNAVAILABLE)?;
        let digits = text.strip_prefix("0x").ok_or(UNAVAILABLE)?;
        hex::decode(digits).map_err(|_| UNAVAILABLE)
    }

    async fn quantity(&mut self, method: &str) -> RelayResult<u64> {
        let result = self.rpc(method, json!([])).await?;
        let digits = result
            .as_str()
            .and_then(|text| text.strip_prefix("0x"))
            .ok_or(UNAVAILABLE)?;
        u64::from_str_radix(digits, 16).map_err(|_| UNAVAILABLE)
    }

    async fn call(&mut self, to: &str, data: Vec<u8>, block: &str) -> RelayResult<Vec<u8>> {
        self.hex(
            "eth_call",
            json!([{ "to": to, "data": format!("0x{}", hex::encode(data)) }, block]),
        )
        .await
    }
}

fn address(text: &str) -> Address {
    text.parse().expect("pinned address")
}

/// The root validator and the exact owner material it must store, per kind.
fn expected_owner(owner: &OwnerCredentialProfile) -> (&'static str, Vec<u8>) {
    match owner {
        OwnerCredentialProfile::Ecdsa { address } => (
            ECDSA_ROOT_VALIDATOR,
            [
                vec![0; 12],
                hex::decode(&address[2..]).expect("captured address"),
            ]
            .concat(),
        ),
        OwnerCredentialProfile::P256 { public_key } => (
            P256_ROOT_VALIDATOR,
            hex::decode(&public_key[4..]).expect("captured point"),
        ),
        OwnerCredentialProfile::WebAuthn { public_key, .. } => (
            WEBAUTHN_ROOT_VALIDATOR,
            hex::decode(&public_key[4..]).expect("captured point"),
        ),
    }
}

/// A 32-byte ABI word holding a `width`-byte unsigned integer, or none.
fn small_uint(word: &[u8], width: usize) -> Option<u64> {
    (word.len() == 32 && word[..32 - width].iter().all(|byte| *byte == 0)).then(|| {
        word[32 - width..]
            .iter()
            .fold(0u64, |n, b| n << 8 | u64::from(*b))
    })
}

/// `bindKernelV33Account` for an ECDSA root, at `block`: the account reports
/// Kernel 0.3.3 and EntryPoint 0.7, its root is `0x01 ‖ ECDSA_ROOT_VALIDATOR`,
/// and that validator stores `owner` for it.
async fn prove_kernel_v33_root(
    reads: &mut Reads<'_>,
    account: Address,
    owner: &OwnerCredentialProfile,
    block: &str,
) -> RelayResult<()> {
    if !matches!(owner, OwnerCredentialProfile::Ecdsa { .. }) {
        return Err(REFUSED);
    }
    let account_text = format!("{account:#x}");
    let id = reads
        .call(&account_text, accountIdCall {}.abi_encode(), block)
        .await?;
    if id != (KERNEL_V33_ACCOUNT_ID.to_owned(),).abi_encode_params() {
        return Err(REFUSED);
    }
    let entry_point = reads
        .call(&account_text, entrypointCall {}.abi_encode(), block)
        .await?;
    if entry_point.len() != 32 {
        return Err(UNAVAILABLE);
    }
    if entry_point[..12] != [0; 12]
        || Address::from_slice(&entry_point[12..]) != address(ENTRY_POINT_V07)
    {
        return Err(REFUSED);
    }
    let root = reads
        .call(&account_text, rootValidatorCall {}.abi_encode(), block)
        .await?;
    if root.len() != 32 {
        return Err(UNAVAILABLE);
    }
    if root != root_word(ECDSA_ROOT_VALIDATOR).as_slice() {
        return Err(REFUSED);
    }
    let stored = reads
        .call(
            ECDSA_ROOT_VALIDATOR,
            ecdsaValidatorStorageCall { account }.abi_encode(),
            block,
        )
        .await?;
    if stored.len() != 32 {
        return Err(UNAVAILABLE);
    }
    if stored != expected_owner(owner).1 {
        return Err(REFUSED);
    }
    Ok(())
}

/// Kernel 0.3.3's effective enable nonce for `permission_id`, at one block,
/// as the SDK's `kernel_v33_permission_nonce` read: `currentNonce()`, plus
/// one when the permission's own validation already holds it. A permission
/// that cannot be enabled at it is `relay_forbidden`; anything unreadable is
/// `relay_chain_unavailable`, never zero.
pub async fn kernel_v33_enable_nonce(
    reader: &ChainReader,
    account: Address,
    permission_id: [u8; 4],
) -> RelayResult<u32> {
    let mut reads = reader.session();
    if reads.quantity("eth_chainId").await? != reader.chain_id {
        return Err(UNAVAILABLE);
    }
    let block = format!("0x{:x}", reads.quantity("eth_blockNumber").await?);
    let account_text = format!("{account:#x}");
    let current = reads
        .call(&account_text, currentNonceCall {}.abi_encode(), &block)
        .await?;
    let current = small_uint(&current, 4).ok_or(UNAVAILABLE)?;
    let mut validation = [0u8; 21];
    validation[0] = 0x02;
    validation[1..5].copy_from_slice(&permission_id);
    let config = reads
        .call(
            &account_text,
            validationConfigCall {
                validationId: FixedBytes(validation),
            }
            .abi_encode(),
            &block,
        )
        .await?;
    if config.len() != 64 || config[32..44] != [0; 12] {
        return Err(UNAVAILABLE);
    }
    let configured = small_uint(&config[..32], 4).ok_or(UNAVAILABLE)?;
    let effective = if configured == current {
        current + 1
    } else {
        current
    };
    if effective < 1 || effective > u64::from(u32::MAX) || configured >= effective {
        return Err(REFUSED);
    }
    Ok(effective as u32)
}

/// Proves, at one block, that `account` is a deployed reviewed Kernel account
/// whose root validator stores `owner`, and answers its version: Kernel v4
/// with any supported root, or Kernel 0.3.3 with an ECDSA root. A mismatch
/// is `relay_forbidden`; anything unreadable is `relay_chain_unavailable`.
pub async fn prove_kernel_root(
    reader: &ChainReader,
    account: Address,
    owner: &OwnerCredentialProfile,
) -> RelayResult<KernelExistingAccountVersion> {
    let mut reads = reader.session();
    if reads.quantity("eth_chainId").await? != reader.chain_id {
        return Err(UNAVAILABLE);
    }
    let block = format!("0x{:x}", reads.quantity("eth_blockNumber").await?);
    let account_text = format!("{account:#x}");

    let code = reads
        .hex("eth_getCode", json!([account_text, block]))
        .await?;
    if code.is_empty() || code.starts_with(&[0xef, 0x01, 0x00]) {
        return Err(REFUSED);
    }

    let slot = reads
        .hex(
            "eth_getStorageAt",
            json!([account_text, IMPLEMENTATION_SLOT, block]),
        )
        .await?;
    let slot: [u8; 32] = slot.try_into().map_err(|_| UNAVAILABLE)?;
    if slot[..12] != [0; 12] {
        return Err(REFUSED);
    }
    let implementation = Address::from_slice(&slot[12..]);
    if implementation == address(KERNEL_V33_IMPLEMENTATION) {
        prove_kernel_v33_root(&mut reads, account, owner, &block).await?;
        return Ok(KernelExistingAccountVersion::V0_3_3);
    }
    if implementation != address(KERNEL_V4_IMPLEMENTATION) {
        return Err(REFUSED);
    }

    let (validator, material) = expected_owner(owner);
    let root = reads
        .call(&account_text, rootCall {}.abi_encode(), &block)
        .await?;
    let expected_root = [vec![0x01], address(validator).to_vec(), vec![0; 11]].concat();
    if root.len() != 32 {
        return Err(UNAVAILABLE);
    }
    if root != expected_root {
        return Err(REFUSED);
    }

    let data = match owner {
        OwnerCredentialProfile::Ecdsa { .. } => ecdsaValidatorStorageCall { account }.abi_encode(),
        OwnerCredentialProfile::P256 { .. } => publicKeyCall { account }.abi_encode(),
        OwnerCredentialProfile::WebAuthn { .. } => {
            webAuthnValidatorStorageCall { account }.abi_encode()
        }
    };
    let stored = reads.call(validator, data, &block).await?;
    if stored.len() != material.len() {
        return Err(UNAVAILABLE);
    }
    if stored != material {
        return Err(REFUSED);
    }
    Ok(KernelExistingAccountVersion::V0_4_0)
}

/// One Kernel v4 permission, identified by its signer module and bytes4 id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionTarget {
    pub account: Address,
    pub signer: Address,
    pub permission_id: [u8; 4],
}

/// What a revocation is prepared from, read at one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionState {
    /// Whether the account has code; a counterfactual account can still be
    /// deployed by an enable operation.
    pub deployed: bool,
    /// For an undeployed account: native balance plus its EntryPoint deposit, at this block.
    pub available_funds: Option<U256>,
    /// Whether the permission's signer is installed; an undeployed account has none.
    pub installed: bool,
    /// Kernel's stored install nonce for the approval's key; none while undeployed.
    pub install_nonce: Option<U256>,
    /// The EntryPoint nonce of the root validator's standard-mode `lane`.
    pub nonce: U256,
}

async fn installed_at(
    reads: &mut Reads<'_>,
    target: &PermissionTarget,
    block: &str,
) -> RelayResult<bool> {
    let account = format!("{:#x}", target.account);
    let code = reads.hex("eth_getCode", json!([account, block])).await?;
    if code.is_empty() {
        return Ok(false);
    }
    let answer = reads
        .call(
            &account,
            isModuleInstalledCall {
                moduleType: U256::from(6),
                module: target.signer,
                additionalContext: Bytes::from(target.permission_id.to_vec()),
            }
            .abi_encode(),
            block,
        )
        .await?;
    match answer.as_slice() {
        word if word.len() == 32 && word[..31] == [0; 31] && word[31] == 0 => Ok(false),
        word if word.len() == 32 && word[..31] == [0; 31] && word[31] == 1 => Ok(true),
        _ => Err(UNAVAILABLE),
    }
}

/// At the latest block: whether the account is deployed and the permission
/// installed, Kernel's install nonce for `install_key`, and the root lane's
/// EntryPoint nonce. Anything unreadable is `relay_chain_unavailable`.
pub async fn permission_state(
    reader: &ChainReader,
    target: &PermissionTarget,
    entry_point: Address,
    lane: u16,
    install_key: U256,
) -> RelayResult<PermissionState> {
    let mut reads = reader.session();
    if reads.quantity("eth_chainId").await? != reader.chain_id {
        return Err(UNAVAILABLE);
    }
    let block = format!("0x{:x}", reads.quantity("eth_blockNumber").await?);
    let account = format!("{:#x}", target.account);
    let deployed = !reads
        .hex("eth_getCode", json!([account, block]))
        .await?
        .is_empty();
    let installed = deployed && installed_at(&mut reads, target, &block).await?;
    let install_nonce = if deployed {
        let stored = reads
            .call(
                &account,
                nonceCall {
                    key: alloy_primitives::aliases::U192::from(install_key),
                }
                .abi_encode(),
                &block,
            )
            .await?;
        let stored: [u8; 32] = stored.try_into().map_err(|_| UNAVAILABLE)?;
        Some(U256::from_be_bytes(stored))
    } else {
        None
    };
    let nonce = reads
        .call(
            &format!("{entry_point:#x}"),
            getNonceCall {
                sender: target.account,
                key: alloy_primitives::aliases::U192::from(lane),
            }
            .abi_encode(),
            &block,
        )
        .await?;
    let nonce: [u8; 32] = nonce.try_into().map_err(|_| UNAVAILABLE)?;
    let available_funds = if deployed {
        None
    } else {
        let result = reads.rpc("eth_getBalance", json!([account, block])).await?;
        let digits = result
            .as_str()
            .and_then(|text| text.strip_prefix("0x"))
            .filter(|digits| {
                !digits.is_empty()
                    && digits.len() <= 64
                    && (digits.len() == 1 || !digits.starts_with('0'))
                    && digits
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or(UNAVAILABLE)?;
        let balance = U256::from_str_radix(digits, 16).map_err(|_| UNAVAILABLE)?;
        let deposit = reads
            .call(
                &format!("{entry_point:#x}"),
                balanceOfCall {
                    account: target.account,
                }
                .abi_encode(),
                &block,
            )
            .await?;
        let deposit: [u8; 32] = deposit.try_into().map_err(|_| UNAVAILABLE)?;
        Some(
            balance
                .checked_add(U256::from_be_bytes(deposit))
                .ok_or(UNAVAILABLE)?,
        )
    };
    Ok(PermissionState {
        deployed,
        available_funds,
        installed,
        install_nonce,
        nonce: U256::from_be_bytes(nonce),
    })
}

/// The finalized block's number, and whether the permission is installed
/// there.
pub async fn finalized_permission(
    reader: &ChainReader,
    target: &PermissionTarget,
) -> RelayResult<(u64, bool)> {
    let mut reads = reader.session();
    if reads.quantity("eth_chainId").await? != reader.chain_id {
        return Err(UNAVAILABLE);
    }
    let block = reads
        .rpc("eth_getBlockByNumber", json!(["finalized", false]))
        .await?;
    let number = block
        .get("number")
        .and_then(Value::as_str)
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        .ok_or(UNAVAILABLE)?;
    let installed = installed_at(&mut reads, target, &format!("0x{number:x}")).await?;
    Ok((number, installed))
}

/// For tests and fixtures: the ABI words a validator returns for `owner`.
pub fn owner_words(owner: &OwnerCredentialProfile) -> Bytes {
    Bytes::from(expected_owner(owner).1)
}

/// For tests and fixtures: `root()`'s return word for `validator`.
pub fn root_word(validator: &str) -> B256 {
    let mut word = [0u8; 32];
    word[0] = 0x01;
    word[1..21].copy_from_slice(address(validator).as_slice());
    B256::from(word)
}

/// For tests and fixtures: the implementation slot's word.
pub fn implementation_word(implementation: &str) -> B256 {
    B256::from(U256::from_be_slice(address(implementation).as_slice()))
}
