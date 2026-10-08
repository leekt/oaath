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

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, sol};
use oaath_protocol::identity::OwnerCredentialProfile;
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
pub const P256_ROOT_VALIDATOR: &str = "0x9906ab44ff795883c5a725687a2705be4118b0f3";
pub const WEBAUTHN_ROOT_VALIDATOR: &str = "0x6f781fff97b830daa2e11ee0ad6344aff7131ef2";
/// ERC-1967 `implementation` slot.
const IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ALLOWED: [&str; 6] = [
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBlockByNumber",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_call",
];

const UNAVAILABLE: RelayErrorCode = RelayErrorCode::ChainUnavailable;
const REFUSED: RelayErrorCode = RelayErrorCode::Forbidden;

sol! {
    function root() external view returns (bytes21);
    function ecdsaValidatorStorage(address account) external view returns (address);
    function publicKey(address account) external view returns (uint256 x, uint256 y);
    function webAuthnValidatorStorage(address account) external view returns (uint256 x, uint256 y);
    function isModuleInstalled(uint256 moduleType, address module, bytes additionalContext) external view returns (bool);
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);
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

/// Proves, at one block, that `account` is a deployed reviewed Kernel v4
/// account whose root validator stores `owner`. A mismatch is
/// `relay_forbidden`; anything unreadable is `relay_chain_unavailable`.
pub async fn prove_kernel_root(
    reader: &ChainReader,
    account: Address,
    owner: &OwnerCredentialProfile,
) -> RelayResult<()> {
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
    if slot[..12] != [0; 12]
        || Address::from_slice(&slot[12..]) != address(KERNEL_V4_IMPLEMENTATION)
    {
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
    Ok(())
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
    /// Whether the permission's signer is installed; an undeployed account has none.
    pub installed: bool,
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

/// At the latest block: whether the permission is installed, and the root
/// lane's EntryPoint nonce. Anything unreadable is `relay_chain_unavailable`.
pub async fn permission_state(
    reader: &ChainReader,
    target: &PermissionTarget,
    entry_point: Address,
    lane: u16,
) -> RelayResult<PermissionState> {
    let mut reads = reader.session();
    if reads.quantity("eth_chainId").await? != reader.chain_id {
        return Err(UNAVAILABLE);
    }
    let block = format!("0x{:x}", reads.quantity("eth_blockNumber").await?);
    let installed = installed_at(&mut reads, target, &block).await?;
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
    Ok(PermissionState {
        installed,
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
