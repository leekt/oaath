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
use serde_json::{Value, json};

use super::grant_packages;
use crate::error::{RelayErrorCode, RelayResult};
use crate::records::canonical_str;

pub const GRANT_DETAIL_TYPE: &str = "oaath_grant";
const MAX_CHAINS: usize = 32;
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
}

impl GrantDetail {
    pub fn to_json(&self) -> Value {
        json!({
            "type": GRANT_DETAIL_TYPE,
            "signer": self.signer.to_json(),
            "policy": self.policy.to_json(),
            "chains": self.chains,
            "expires_at": self.expires_at,
            "device_id": self.device_id,
        })
    }
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
    if record.len() != keys.len() || !keys.iter().all(|key| record.contains_key(*key)) {
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
    let expires_at = record["expires_at"].as_u64().ok_or(INVALID)?;
    let device_id = canonical_str(record["device_id"].as_str().ok_or(INVALID)?, INVALID)?;
    grant_packages(&signer, &policy)?;
    Ok(GrantDetail {
        signer,
        policy,
        chains,
        expires_at,
        device_id: device_id.to_owned(),
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
