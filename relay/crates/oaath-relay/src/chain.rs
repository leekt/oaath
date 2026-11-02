//! The relay's one budgeted chain reader: a revocation's permission state.
//!
//! ```text
//! OAATH_RPC_421614   one JSON-RPC URL for chain 421614; never logged
//! ```
//!
//! Only the read methods below are sent. One read spends at most `MAX_CALLS`
//! requests, each bounded by `TIMEOUT`, with no retry and no fallback URL.
//! Every read is pinned to one block. An unreadable, timed-out, noncanonical
//! or contradictory answer refuses: unreadable is never absent.

use std::time::Duration;

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolCall, sol};
use serde_json::{Value, json};

use crate::error::{RelayErrorCode, RelayResult};

/// Arbitrum Sepolia, the portal's chain.
pub const IMPORT_CHAIN_ID: u64 = 421_614;
pub const MAX_CALLS: usize = 8;
pub const TIMEOUT: Duration = Duration::from_secs(8);
const ALLOWED: [&str; 6] = [
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBlockByNumber",
    "eth_getCode",
    "eth_getBalance",
    "eth_call",
];

const UNAVAILABLE: RelayErrorCode = RelayErrorCode::ChainUnavailable;

sol! {
    function balanceOf(address account) external view returns (uint256);
    function isModuleInstalled(uint256 moduleType, address module, bytes additionalContext) external view returns (bool);
    function getNonce(address sender, uint192 key) external view returns (uint256);
    function nonce(uint192 key) external view returns (uint256);
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
