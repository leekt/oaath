//! Dapp grants: one dapp signer plus one GrantPolicy, approved by the account's
//! policy-free root with a Kernel 0.4.0 replayable install, or, on an imported
//! Kernel 0.3.3 account, with a chain-zero `Enable` at Kernel's validation
//! nonce over the same packages.
//!
//! The relay derives what the root signs offline, byte-identical to the SDK
//! (pinned by `relay/fixtures/grant`, exported from the SDK's own
//! `sessionOperator` packaging and `kernelPermissionInstallNonce`):
//!
//! ```text
//! packages      the SDK session permission: one type-5 package per policy
//!               (call unless sudo, expiry, operation- or rate-limit), then the type-6
//!               pinned signer for the dapp's operator credential
//! install nonce (requestHash >> 64) << 64
//! digest        EIP-712 InstallPackages under the account's chainless domain
//! ```
//!
//! No chain read is needed: the account address is the registry's offline
//! derivation and every module is a pinned CREATE2 address.

pub mod approval;
pub mod details;
pub mod signature;

use alloy_primitives::{Address, B256, FixedBytes, U256, keccak256};
use alloy_sol_types::{SolValue, sol};
use oaath_protocol::grant_policy::GrantPolicy;
use oaath_protocol::identity::{
    KernelAccountProfile, KernelExistingAccountVersion, OperatorCredentialProfile,
    OwnerCredentialProfile,
};
use oaath_protocol::kernel_install::{
    KernelInstall, kernel_v4_replayable_install_typed_data, kernel_v33_enable_typed_data,
    parse_kernel_replayable_install_owner_signing_request,
};
use oaath_protocol::permission::PermissionRequest;
use oaath_protocol::signing_request::{
    Eip712OwnerSigningRequest, OwnerSigningRequest, parse_canonical_eip712_typed_data,
    parse_owner_signing_request,
};
use serde_json::{Value, json};

use crate::error::{RelayErrorCode, RelayResult};

const CALL_POLICY: &str = "0x9a52283276a0ec8740df50bf01b28a80d880eaf2";
const VALIDITY_POLICY: &str = "0x828ef0aa6d7e90dd39bb855afe9d9b4f9bd30152";
const OPERATION_LIMIT_POLICY: &str = "0xf63d4139b25c836334edd76641356c6b74c86873";
const RATE_LIMIT_POLICY: &str = "0xe2663e2f94ef2dc11cc06a7914a037d78a0652dc";
const ECDSA_SIGNER: &str = "0x6a6f069e2a08c2468e7724ab3250cdbfba14d4ff";
const WEBAUTHN_SIGNER: &str = "0x8b2df925aa16071fcdf0053768420e242935ac65";
const EXECUTE_SELECTOR: [u8; 4] = [0xe9, 0xae, 0x5c, 0x53];

sol! {
    struct CallRule {
        uint8 condition;
        uint64 offset;
        bytes32[] params;
    }
    struct CallPermission {
        bytes1 callType;
        address target;
        bytes4 selector;
        uint256 valueLimit;
        CallRule[] rules;
    }
}

const UNSUPPORTED: RelayErrorCode = RelayErrorCode::RequestInvalid;

fn address(text: &str) -> Address {
    text.parse().expect("captured address")
}

fn hex_bytes(text: &str) -> Vec<u8> {
    hex::decode(text.trim_start_matches("0x")).expect("captured hex")
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// `uint` as a big-endian unsigned integer of `size` bytes.
fn be(value: u64, size: usize) -> Vec<u8> {
    value.to_be_bytes()[8 - size..].to_vec()
}

/// `deriveSessionPolicyProfiles` + `compileKernelPermissionPolicy`: the policy
/// packages a session installs, in install order. A constraint with no
/// reviewed Kernel profile is refused rather than silently enforcing less.
fn policy_packages(policy: &GrantPolicy) -> RelayResult<Vec<(&'static str, Vec<u8>)>> {
    if policy
        .calls
        .iter()
        .any(|call| !call.argument_equals.is_empty())
    {
        return Err(UNSUPPORTED);
    }
    let permissions: Vec<CallPermission> = policy
        .calls
        .iter()
        .map(|call| CallPermission {
            callType: FixedBytes([0]),
            target: address(&call.target),
            selector: FixedBytes::from_slice(&hex_bytes(&call.selector)),
            valueLimit: U256::from_str_radix(&call.value_limit, 10).expect("captured uint256"),
            rules: Vec::new(),
        })
        .collect();
    // A sudo policy (no calls) installs no call policy: only its validity window,
    // which the protocol capture guarantees is present.
    let mut packages = Vec::new();
    if !policy.is_sudo() {
        packages.push((CALL_POLICY, (permissions,).abi_encode_params()));
    }
    // No expiry installs no validity policy; no limit installs no limit policy.
    if let Some(valid_until) = policy.valid_until {
        if valid_until <= policy.valid_after {
            return Err(UNSUPPORTED);
        }
        packages.push((
            VALIDITY_POLICY,
            (U256::from(policy.valid_after), U256::from(valid_until)).abi_encode_params(),
        ));
    }
    match policy.per_chain_operation_limit {
        None => {}
        Some(limit) => match limit.interval_seconds {
            None => packages.push((
                OPERATION_LIMIT_POLICY,
                [be(0, 6), be(limit.count, 6), be(0, 6)].concat(),
            )),
            Some(interval) => packages.push((
                RATE_LIMIT_POLICY,
                [be(interval, 6), be(limit.count, 6)].concat(),
            )),
        },
    }
    Ok(packages)
}

/// Refuses a policy the SDK cannot compile into reviewed Kernel packages.
pub fn check_policy(policy: &GrantPolicy) -> RelayResult<()> {
    policy_packages(policy).map(|_| ())
}

/// The operator credential's pinned permission signer, key kind, and public
/// material, as the SDK's `credentialKey` publishes them.
fn signer(operator: &OperatorCredentialProfile) -> (&'static str, &'static str, Vec<u8>) {
    match operator {
        OperatorCredentialProfile::Ecdsa { address } => (ECDSA_SIGNER, "ecdsa", hex_bytes(address)),
        OperatorCredentialProfile::WebAuthn {
            public_key,
            authenticator_id_hash,
        } => {
            let point = hex_bytes(public_key);
            let material = (
                U256::from_be_slice(&point[1..33]),
                U256::from_be_slice(&point[33..65]),
                B256::from_slice(&hex_bytes(authenticator_id_hash)),
            )
                .abi_encode_params();
            (WEBAUTHN_SIGNER, "webauthn", material)
        }
    }
}

/// The session permission packages for one operator under one policy.
pub fn grant_packages(
    operator: &OperatorCredentialProfile,
    policy: &GrantPolicy,
) -> RelayResult<Vec<KernelInstall>> {
    let policies = policy_packages(policy)?;
    let (signer_module, kind, material) = signer(operator);
    let mut preimage = Vec::new();
    for (module, data) in &policies {
        preimage.extend_from_slice(address(module).as_slice());
        preimage.extend_from_slice(keccak256(data).as_slice());
    }
    preimage.extend_from_slice(address(signer_module).as_slice());
    preimage.extend_from_slice(keccak256(kind.as_bytes()).as_slice());
    preimage.extend_from_slice(keccak256(&material).as_slice());
    let permission_id = keccak256(&preimage)[..4].to_vec();
    let mut padded = permission_id.clone();
    padded.resize(32, 0);
    let mut packages: Vec<KernelInstall> = policies
        .into_iter()
        .map(|(module, data)| KernelInstall {
            module_type: 5,
            module: module.to_owned(),
            module_data: hex([padded.clone(), data].concat()),
            internal_data: hex(&permission_id),
        })
        .collect();
    packages.push(KernelInstall {
        module_type: 6,
        module: signer_module.to_owned(),
        module_data: hex([padded, material].concat()),
        internal_data: hex([permission_id, EXECUTE_SELECTOR.to_vec()].concat()),
    });
    Ok(packages)
}

/// `kernelPermissionInstallNonce`: the request hash with its low 64 bits
/// cleared, as a decimal uint256.
pub fn install_nonce(request_hash: B256) -> String {
    let hash = U256::from_be_bytes(request_hash.0);
    ((hash >> 64usize) << 64usize).to_string()
}

/// The `enable_nonce` a portal prepare carries for a Kernel 0.3.3 account:
/// Kernel's effective validation nonce as the portal read it, a canonical
/// positive decimal uint32. The relay reads no chain: a wrong nonce yields an
/// enable Kernel refuses on chain, never authority the root did not sign.
pub fn enable_nonce(value: Option<&Value>) -> RelayResult<Option<u32>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let text = value.as_str().ok_or(UNSUPPORTED)?;
    let nonce = text.parse::<u32>().map_err(|_| UNSUPPORTED)?;
    if nonce == 0 || nonce.to_string() != text {
        return Err(UNSUPPORTED);
    }
    Ok(Some(nonce))
}

/// An imported Kernel 0.3.3 account: its enable nonce is Kernel's onchain
/// validation nonce, not derived from the request.
pub fn is_kernel_v33(request: &PermissionRequest) -> bool {
    matches!(
        &request.logical_account,
        KernelAccountProfile::Existing(profile)
            if profile.kernel_version == KernelExistingAccountVersion::V0_3_3
    )
}

/// One grant's `kernel-enable` owner signing request with the nonce and
/// packages it installs.
#[derive(Debug, Clone)]
pub struct GrantSigningRequest {
    pub request: Eip712OwnerSigningRequest,
    pub nonce: String,
    pub packages: Vec<KernelInstall>,
}

impl GrantSigningRequest {
    pub fn owner_credential(&self) -> &OwnerCredentialProfile {
        &self.request.signer.owner_credential
    }

    pub fn expected_digest(&self) -> &str {
        &self.request.expected_digest
    }

    pub fn to_json(&self) -> Value {
        OwnerSigningRequest::Eip712(Box::new(self.request.clone())).to_json()
    }
}

/// The exact `kernel-enable` owner signing request the account root signs for
/// one grant: the dapp signer under `policy` (the requested policy or an
/// attenuation of it) installed into `account`. A Kernel 0.4.0 account signs a
/// replayable install whose nonce derives from the request; a Kernel 0.3.3
/// account signs `Enable` at `v33_nonce`, Kernel's effective validation nonce
/// (`enable_nonce`). Without one a v3.3 grant is refused, and a Kernel 0.4.0
/// grant refuses one.
pub fn grant_signing_request(
    request: &PermissionRequest,
    policy: &GrantPolicy,
    account: &str,
    v33_nonce: Option<u32>,
) -> RelayResult<GrantSigningRequest> {
    let packages = grant_packages(&request.operator_credential, policy)?;
    if !is_kernel_v33(request) && v33_nonce.is_some() {
        return Err(UNSUPPORTED);
    }
    let (nonce, typed_data) = if is_kernel_v33(request) {
        let nonce = v33_nonce.filter(|nonce| *nonce > 0).ok_or(UNSUPPORTED)?;
        (
            nonce.to_string(),
            kernel_v33_enable_typed_data(account, nonce, &packages),
        )
    } else {
        let nonce = install_nonce(request.hash());
        let typed_data = kernel_v4_replayable_install_typed_data(account, &nonce, &packages);
        (nonce, typed_data)
    };
    let digest = parse_canonical_eip712_typed_data(&typed_data)
        .and_then(|typed| typed.hash())
        .map_err(|_| RelayErrorCode::Internal)?;
    let value = json!({
        "version": "oaath.owner-signing-request/v1",
        "kind": "eip712",
        "purpose": "kernel-enable",
        "signer": {
            "account": account,
            "ownerCredential": request.logical_account.owner_credential().to_json(),
        },
        "typedData": typed_data,
        "expectedDigest": hex(digest),
        "replay": { "nonce": nonce, "deadline": null },
    });
    let request = if is_kernel_v33(request) {
        match parse_owner_signing_request(&value) {
            Ok(OwnerSigningRequest::Eip712(request)) => *request,
            _ => return Err(RelayErrorCode::Internal),
        }
    } else {
        parse_kernel_replayable_install_owner_signing_request(&value)
            .map_err(|_| RelayErrorCode::Internal)?
            .request
    };
    Ok(GrantSigningRequest {
        request,
        nonce,
        packages,
    })
}
