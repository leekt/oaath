//! The `oaath_grant` authorization detail a dapp pushes (RFC 9396 shape) and
//! the one pure composition of it into a protocol `PermissionRequest`.
//!
//! The PAR stores only the dapp's intent. The account and its root are chosen
//! later in the portal, so the request is composed, never stored, until the
//! decision: `compose` is deterministic, so the portal's prepared request and
//! the decision's recomposed request hash identically.

use oaath_protocol::capture::MAX_SAFE_INTEGER_U64;
use oaath_protocol::grant_policy::{GrantPolicy, parse_grant_policy};
use oaath_protocol::identity::{
    KernelAccountProfile, OperatorCredentialProfile, parse_operator_credential_profile,
};
use oaath_protocol::permission::{PermissionRequest, parse_permission_request};
use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::grant_packages;
use crate::error::{RelayErrorCode, RelayResult};
use crate::records::canonical_str;

pub const GRANT_DETAIL_TYPE: &str = "oaath_grant";
/// Chains an `oaath_grant` detail may name. The Grant itself covers every
/// chain; the list only tells the portal what to show and where to read.
pub const MAX_CHAINS: usize = 256;
/// The PAR's `error_description` when a detail names more.
pub const TOO_MANY_CHAINS: &str = "chains: at most 256 chain IDs";
const MAX_RPC_URL: usize = 512;
const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;

/// One captured `oaath_grant` detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantDetail {
    /// The dapp's own signer, installed as a policy-bound permission signer.
    pub signer: OperatorCredentialProfile,
    pub policy: GrantPolicy,
    /// Display only: a grant is all-chain.
    pub chains: Vec<u64>,
    /// Exclusive grant expiry, Unix seconds.
    pub expires_at: u64,
    pub device_id: String,
    /// The app's own read-only JSON-RPC URL for some of `chains`: the portal
    /// reads that chain through it (`/rpc/tx/{id}/{chainId}`) to prepare the
    /// root's approval. Visible to the user; it never carries a credential
    /// the app would not show.
    pub rpc_urls: BTreeMap<u64, String>,
    /// A Kernel 0.3.3 account's effective enable nonce (decimal uint32 > 0) as
    /// the app read it, so the portal prepares the approval without reading
    /// any chain. A wrong value installs nothing: the signature binds it.
    pub enable_nonce: Option<String>,
}

impl GrantDetail {
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "type": GRANT_DETAIL_TYPE,
            "signer": self.signer.to_json(),
            "policy": self.policy.to_json(),
            "chains": self.chains,
            "expires_at": self.expires_at,
            "device_id": self.device_id,
        });
        if !self.rpc_urls.is_empty() {
            value["rpc_urls"] = json!(
                self.rpc_urls
                    .iter()
                    .map(|(chain, url)| (chain.to_string(), Value::String(url.clone())))
                    .collect::<serde_json::Map<_, _>>()
            );
        }
        if let Some(nonce) = &self.enable_nonce {
            value["enable_nonce"] = json!(nonce);
        }
        value
    }
}

/// An app RPC URL: absolute https with a host, no credentials or fragment.
fn rpc_url(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let url = url::Url::parse(text).ok()?;
    (text.len() <= MAX_RPC_URL
        && url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then(|| text.to_owned())
}

/// Captures `authorization_details`: exactly one `oaath_grant` whose signer
/// and policy the protocol accepts and whose policy has a reviewed Kernel
/// profile. Anything else is `relay_request_invalid`.
pub fn parse_grant_details(value: &Value) -> RelayResult<GrantDetail> {
    let [detail] = value.as_array().map(Vec::as_slice).ok_or(INVALID)? else {
        return Err(INVALID);
    };
    let record = detail.as_object().ok_or(INVALID)?;
    let keys = [
        "type",
        "signer",
        "policy",
        "chains",
        "expires_at",
        "device_id",
    ];
    let optional = usize::from(record.contains_key("rpc_urls"))
        + usize::from(record.contains_key("enable_nonce"));
    if record.len() != keys.len() + optional || !keys.iter().all(|key| record.contains_key(*key)) {
        return Err(INVALID);
    }
    if record["type"] != GRANT_DETAIL_TYPE {
        return Err(INVALID);
    }
    let signer = parse_operator_credential_profile(&record["signer"]).map_err(|_| INVALID)?;
    let policy = parse_grant_policy(&record["policy"]).map_err(|_| INVALID)?;
    let chains = record["chains"]
        .as_array()
        .filter(|chains| (1..=MAX_CHAINS).contains(&chains.len()))
        .ok_or(INVALID)?
        .iter()
        .map(|chain| {
            chain
                .as_u64()
                .filter(|id| (1..=MAX_SAFE_INTEGER_U64).contains(id))
        })
        .collect::<Option<Vec<u64>>>()
        .ok_or(INVALID)?;
    let mut unique = chains.clone();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != chains.len() {
        return Err(INVALID);
    }
    let mut rpc_urls = BTreeMap::new();
    if let Some(urls) = record.get("rpc_urls") {
        let urls = urls
            .as_object()
            .filter(|urls| !urls.is_empty())
            .ok_or(INVALID)?;
        for (chain, url) in urls {
            // A canonical decimal id of one of the detail's own chains.
            let id = chain.parse::<u64>().map_err(|_| INVALID)?;
            if id.to_string() != *chain || !chains.contains(&id) {
                return Err(INVALID);
            }
            rpc_urls.insert(id, rpc_url(url).ok_or(INVALID)?);
        }
    }
    let expires_at = record["expires_at"].as_u64().ok_or(INVALID)?;
    let enable_nonce = match record.get("enable_nonce") {
        None => None,
        Some(nonce) => {
            let text = nonce.as_str().ok_or(INVALID)?;
            let parsed = text.parse::<u32>().map_err(|_| INVALID)?;
            if parsed == 0 || parsed.to_string() != text {
                return Err(INVALID);
            }
            Some(text.to_owned())
        }
    };
    let device_id = canonical_str(record["device_id"].as_str().ok_or(INVALID)?, INVALID)?;
    grant_packages(&signer, &policy)?;
    Ok(GrantDetail {
        signer,
        policy,
        chains,
        expires_at,
        device_id: device_id.to_owned(),
        rpc_urls,
        enable_nonce,
    })
}

/// What `compose` binds from the PAR and the portal's selection.
pub struct Composition<'a> {
    pub request_id: &'a str,
    pub client_id: &'a str,
    /// `URL.origin` of the PAR's redirect URI.
    pub redirect_origin: &'a str,
    /// PAR creation time, Unix seconds.
    pub requested_at: u64,
    /// The account address: protocol context ids are lowercase canonical.
    pub account_address: &'a str,
    pub account: &'a KernelAccountProfile,
}

/// The one deterministic `PermissionRequest` for a grant: the account's
/// personal workspace context (named by its address), the dapp as application, the account profile as the
/// logical account, and the dapp's signer and policy.
pub fn compose(detail: &GrantDetail, at: &Composition<'_>) -> RelayResult<PermissionRequest> {
    parse_permission_request(&json!({
        "version": "oaath.permission-request/v1",
        "requestId": at.request_id,
        "context": {
            "version": "oaath.workspace-account-context/v1",
            "workspaceId": at.account_address,
            "workspaceKind": "personal",
            "accountId": at.account_address,
        },
        "application": {
            "applicationId": at.client_id,
            "clientId": at.client_id,
            "origin": at.redirect_origin,
            "deviceId": detail.device_id,
        },
        "chainScope": "all",
        "logicalAccount": at.account.to_json(),
        "operatorCredential": detail.signer.to_json(),
        "policy": detail.policy.to_json(),
        "requestedAt": at.requested_at,
        "expiresAt": detail.expires_at,
        "sessionSigner": null,
    }))
    .map_err(|_| INVALID)
}
