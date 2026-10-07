//! Admission of one root-signed grant approval artifact: the protocol
//! permission decision plus its `installApproval` (the SDK's
//! `oaath.kernel.all-chain-approval/v1`), checked against what the relay
//! derives itself. Every refusal is `relay_request_invalid`; nothing here
//! allocates or persists.

use alloy_primitives::{B256, keccak256};
use alloy_sol_types::SolValue;
use oaath_protocol::capture::parse_json;
use oaath_protocol::permission::{
    ApprovePermissionDecision, PermissionRequest, parse_approved_permission,
};
use serde_json::{Map, Value};

use super::grant_signing_request;
use super::signature::{RelyingParty, verify_root_signature};
use crate::error::{RelayErrorCode, RelayResult};

pub const ALL_CHAIN_APPROVAL_VERSION: &str = "oaath.kernel.all-chain-approval/v1";
const CAPABILITY_DOMAIN: &str = "@oaath/sdk:kernel-all-chain-capability";
const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;

/// An admitted grant: the protocol decision and the exact install approval.
#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    pub decision: ApprovePermissionDecision,
    pub install_approval: Value,
}

/// `kernelAllChainCapabilityHash`: the digest and the signature that releases it.
pub fn capability_hash(digest: B256, enable_signature: &[u8]) -> B256 {
    keccak256(
        (
            CAPABILITY_DOMAIN.to_owned(),
            digest,
            keccak256(enable_signature),
        )
            .abi_encode_params(),
    )
}

fn field<'a>(record: &'a Map<String, Value>, key: &str) -> RelayResult<&'a Value> {
    record.get(key).ok_or(INVALID)
}

/// Verifies that `artifact` approves exactly `request` for `account`, signed
/// by the account's root:
///
/// 1. the protocol decision binds the request (hash, time, attenuation);
/// 2. the install approval is the SDK shape over the account the registry
///    derived, the request's install nonce, and the packages the relay derives
///    for the dapp signer under the approved policy;
/// 3. its digest is that install's typed-data hash, and the decision's
///    capability hash commits to the digest and the enable signature;
/// 4. the enable signature is the root's over that digest.
pub fn verify_grant_approval(
    request: &PermissionRequest,
    account: &str,
    artifact: &str,
    relay_decided_at_ms: u64,
    relying_party: &RelyingParty<'_>,
) -> RelayResult<VerifiedGrant> {
    let decision = parse_approved_permission(artifact, request, relay_decided_at_ms)
        .map_err(|_| INVALID)?
        .permission;
    let Ok(Value::Object(mut value)) = parse_json(artifact) else {
        return Err(INVALID);
    };
    let install_approval = value.shift_remove("installApproval").ok_or(INVALID)?;
    let Value::Object(approval) = &install_approval else {
        return Err(INVALID);
    };
    if approval.len() != 6
        || field(approval, "version")? != ALL_CHAIN_APPROVAL_VERSION
        || field(approval, "account")? != account
    {
        return Err(INVALID);
    }
    let expected = grant_signing_request(request, &decision.approved_policy, account)?;
    if field(approval, "installNonce")? != expected.nonce.as_str()
        || field(approval, "digest")? != expected.expected_digest()
    {
        return Err(INVALID);
    }
    let Value::Array(packages) = field(approval, "packages")? else {
        return Err(INVALID);
    };
    let derived = &expected.packages;
    if packages.len() != derived.len()
        || !packages.iter().zip(derived).all(|(given, install)| {
            given.get("moduleType").and_then(Value::as_u64) == Some(u64::from(install.module_type))
                && given.get("module").and_then(Value::as_str) == Some(install.module.as_str())
                && given.get("moduleData").and_then(Value::as_str)
                    == Some(install.module_data.as_str())
                && given.get("internalData").and_then(Value::as_str)
                    == Some(install.internal_data.as_str())
                && given.as_object().is_some_and(|install| install.len() == 4)
        })
    {
        return Err(INVALID);
    }
    let signature = field(approval, "enableSignature")?
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .and_then(|digits| hex::decode(digits).ok())
        .ok_or(INVALID)?;
    let digest: B256 = expected.expected_digest().parse().map_err(|_| INVALID)?;
    if decision.capability_hash != format!("{:#x}", capability_hash(digest, &signature)) {
        return Err(INVALID);
    }
    if !verify_root_signature(
        expected.owner_credential(),
        digest,
        &signature,
        relying_party,
    ) {
        return Err(INVALID);
    }
    Ok(VerifiedGrant {
        decision,
        install_approval,
    })
}
