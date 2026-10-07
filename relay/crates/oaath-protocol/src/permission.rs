//! Permission request and decision wire contracts (`permission-protocol.ts`)
//! and the relay's approval meaning of a sealed decision
//! (`packages/server/src/authorization/approved-permission.ts`).

use alloy_primitives::{B256, U256, keccak256};
use alloy_sol_types::SolValue;
use serde_json::{Value, json};

use crate::capture::{
    MAX_UINT48, ZERO_HASH, canonical_bounded_string, capture_record, exact_record, field,
    has_exact_keys, lower_hash, parse_json, safe_integer, utf16_len,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure, fail};
use crate::grant_policy::{GrantPolicy, capture_policy, is_captured_policy_attenuation};
use crate::identity::{
    KernelAccountProfile, OperatorCredentialProfile, b256_of, capture_kernel_account,
    capture_operator_credential, hex_hash,
};
use crate::ids::canonical_identifier;
use crate::web_url::http_origin;
use crate::workspace::{
    WORKSPACE_ACCOUNT_CONTEXT_VERSION, WorkspaceAccountContext, capture_workspace_account_context,
};

pub const PERMISSION_REQUEST_VERSION: &str = "oaath.permission-request/v2";
pub const PERMISSION_DECISION_VERSION: &str = "oaath.permission-decision/v1";
pub const PERMISSION_REQUEST_HASH_DOMAIN: &str = "@oaath/protocol:permission-request";
pub const PERMISSION_DECISION_HASH_DOMAIN: &str = "@oaath/protocol:permission-decision";

const MAX_REQUEST_ID_LENGTH: usize = 256;

/// The requesting application as the Grant identity binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationBinding {
    pub application_id: String,
    pub client_id: String,
    /// Normalized `URL.origin` of the declared http(s) origin.
    pub origin: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionSessionSignerMode {
    ApplicationBackend,
    OaathHosted,
}

impl PermissionSessionSignerMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationBackend => "application_backend",
            Self::OaathHosted => "oaath_hosted",
        }
    }
}

/// Remote session-key custody the owner is asked to approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSessionSigner {
    pub mode: PermissionSessionSignerMode,
    pub provider_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRequest {
    /// The requested Grant uses this exact identifier as its grantId.
    pub request_id: String,
    pub context: WorkspaceAccountContext,
    pub application: ApplicationBinding,
    pub logical_account: KernelAccountProfile,
    pub operator_credential: OperatorCredentialProfile,
    pub policy: GrantPolicy,
    pub requested_at: u64,
    /// Exclusive Grant expiry. The inclusive policy expiry is earlier.
    pub expires_at: u64,
    /// Remote session-key custody, or `None` for frontend custody.
    pub session_signer: Option<PermissionSessionSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectPermissionDecision {
    pub request_id: String,
    pub request_hash: String,
    pub decided_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovePermissionDecision {
    pub request_id: String,
    pub request_hash: String,
    pub decided_at: u64,
    pub approved_policy: GrantPolicy,
    /// Commitment to the separately owned replayable approval capability.
    pub capability_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionDecision {
    Reject(RejectPermissionDecision),
    Approve(ApprovePermissionDecision),
}

fn uint48(value: &Value, code: ErrorCode) -> ProtocolResult<u64> {
    safe_integer(value, 0, MAX_UINT48).or_fail(code)
}

fn request_id(value: &Value, code: ErrorCode) -> ProtocolResult<String> {
    Ok(canonical_bounded_string(value, MAX_REQUEST_ID_LENGTH)
        .or_fail(code)?
        .to_owned())
}

fn capture_application(value: &Value, code: ErrorCode) -> ProtocolResult<ApplicationBinding> {
    let record =
        exact_record(value, &["applicationId", "clientId", "origin", "deviceId"]).or_fail(code)?;
    let identifier = |key: &str| {
        canonical_identifier(field(record, key))
            .map(str::to_owned)
            .or_fail(code)
    };
    Ok(ApplicationBinding {
        application_id: identifier("applicationId")?,
        client_id: identifier("clientId")?,
        origin: field(record, "origin")
            .as_str()
            .and_then(http_origin)
            .or_fail(code)?,
        device_id: identifier("deviceId")?,
    })
}

fn capture_session_signer(
    value: &Value,
    code: ErrorCode,
) -> ProtocolResult<Option<PermissionSessionSigner>> {
    if value.is_null() {
        return Ok(None);
    }
    let record = exact_record(value, &["mode", "providerId"]).or_fail(code)?;
    // Frontend custody is null, never a second object representation.
    let mode = match field(record, "mode").as_str() {
        Some("application_backend") => PermissionSessionSignerMode::ApplicationBackend,
        Some("oaath_hosted") => PermissionSessionSignerMode::OaathHosted,
        _ => return fail(code),
    };
    let provider_id = field(record, "providerId")
        .as_str()
        .filter(|text| (1..=MAX_REQUEST_ID_LENGTH).contains(&utf16_len(text)));
    Ok(Some(PermissionSessionSigner {
        mode,
        provider_id: provider_id.or_fail(code)?.to_owned(),
    }))
}

pub(crate) fn capture_request(value: &Value, code: ErrorCode) -> ProtocolResult<PermissionRequest> {
    let record = exact_record(
        value,
        &[
            "version",
            "requestId",
            "context",
            "application",
            "chainScope",
            "logicalAccount",
            "operatorCredential",
            "policy",
            "requestedAt",
            "expiresAt",
            "sessionSigner",
        ],
    )
    .or_fail(code)?;
    ensure(field(record, "version") == PERMISSION_REQUEST_VERSION, code)?;
    ensure(field(record, "chainScope") == "all", code)?;
    let policy = capture_policy(field(record, "policy"), code)?;
    let requested_at = uint48(field(record, "requestedAt"), code)?;
    let expires_at = uint48(field(record, "expiresAt"), code)?;
    ensure(expires_at > requested_at, code)?;
    ensure(
        policy
            .valid_until
            .is_some_and(|until| until >= requested_at && until < expires_at),
        code,
    )?;
    Ok(PermissionRequest {
        request_id: request_id(field(record, "requestId"), code)?,
        context: capture_workspace_account_context(field(record, "context"), code)?,
        application: capture_application(field(record, "application"), code)?,
        logical_account: capture_kernel_account(field(record, "logicalAccount"), code)?,
        operator_credential: capture_operator_credential(
            field(record, "operatorCredential"),
            code,
        )?,
        policy,
        requested_at,
        expires_at,
        session_signer: capture_session_signer(field(record, "sessionSigner"), code)?,
    })
}

pub fn parse_permission_request(value: &Value) -> ProtocolResult<PermissionRequest> {
    capture_request(value, ErrorCode::PermissionRequestInvalid)
}

impl PermissionRequest {
    /// `hashPermissionRequest` over this captured request.
    pub fn hash(&self) -> B256 {
        let application = &self.application;
        let context = &self.context;
        keccak256(
            (
                PERMISSION_REQUEST_HASH_DOMAIN.to_owned(),
                PERMISSION_REQUEST_VERSION.to_owned(),
                self.request_id.clone(),
                "all".to_owned(),
                (
                    application.application_id.clone(),
                    application.client_id.clone(),
                    application.origin.clone(),
                    application.device_id.clone(),
                ),
                (
                    WORKSPACE_ACCOUNT_CONTEXT_VERSION.to_owned(),
                    context.workspace_id.clone(),
                    context.workspace_kind.as_str().to_owned(),
                    context.account_id.clone(),
                ),
                self.logical_account.hash(),
                self.operator_credential.hash(),
                self.policy.hash(),
                U256::from(self.requested_at),
                U256::from(self.expires_at),
                self.session_signer
                    .as_ref()
                    .map_or("frontend", |signer| signer.mode.as_str())
                    .to_owned(),
                self.session_signer
                    .as_ref()
                    .map_or(String::new(), |signer| signer.provider_id.clone()),
            )
                .abi_encode_params(),
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "version": PERMISSION_REQUEST_VERSION,
            "requestId": self.request_id,
            "context": self.context.to_json(),
            "application": {
                "applicationId": self.application.application_id,
                "clientId": self.application.client_id,
                "origin": self.application.origin,
                "deviceId": self.application.device_id,
            },
            "chainScope": "all",
            "logicalAccount": self.logical_account.to_json(),
            "operatorCredential": self.operator_credential.to_json(),
            "policy": self.policy.to_json(),
            "requestedAt": self.requested_at,
            "expiresAt": self.expires_at,
            "sessionSigner": self.session_signer.as_ref().map(|signer| json!({
                "mode": signer.mode.as_str(),
                "providerId": signer.provider_id,
            })),
        })
    }
}

pub fn hash_permission_request(value: &Value) -> ProtocolResult<String> {
    Ok(hex_hash(parse_permission_request(value)?.hash()))
}

fn capture_decision(value: &Value, code: ErrorCode) -> ProtocolResult<PermissionDecision> {
    let record = capture_record(value).or_fail(code)?;
    let kind = record.get("kind").and_then(Value::as_str);
    let keys: &[&str] = match kind {
        Some("reject") => &["version", "kind", "requestId", "requestHash", "decidedAt"],
        Some("approve") => &[
            "version",
            "kind",
            "requestId",
            "requestHash",
            "decidedAt",
            "approvedPolicy",
            "capabilityHash",
        ],
        _ => return fail(code),
    };
    ensure(has_exact_keys(record, keys), code)?;
    ensure(
        field(record, "version") == PERMISSION_DECISION_VERSION,
        code,
    )?;
    let request_id = request_id(field(record, "requestId"), code)?;
    let request_hash = lower_hash(field(record, "requestHash"))
        .or_fail(code)?
        .to_owned();
    let decided_at = uint48(field(record, "decidedAt"), code)?;
    if kind == Some("reject") {
        return Ok(PermissionDecision::Reject(RejectPermissionDecision {
            request_id,
            request_hash,
            decided_at,
        }));
    }
    let approved_policy = capture_policy(field(record, "approvedPolicy"), code)?;
    let capability_hash = lower_hash(field(record, "capabilityHash"))
        .filter(|hash| *hash != ZERO_HASH)
        .or_fail(code)?
        .to_owned();
    Ok(PermissionDecision::Approve(ApprovePermissionDecision {
        request_id,
        request_hash,
        decided_at,
        approved_policy,
        capability_hash,
    }))
}

pub fn parse_permission_decision(value: &Value) -> ProtocolResult<PermissionDecision> {
    capture_decision(value, ErrorCode::PermissionDecisionInvalid)
}

impl PermissionDecision {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Reject(decision) => &decision.request_id,
            Self::Approve(decision) => &decision.request_id,
        }
    }

    pub fn decided_at(&self) -> u64 {
        match self {
            Self::Reject(decision) => decision.decided_at,
            Self::Approve(decision) => decision.decided_at,
        }
    }

    /// `hashPermissionDecision` over this captured decision.
    pub fn hash(&self) -> B256 {
        let domain = PERMISSION_DECISION_HASH_DOMAIN.to_owned();
        let version = PERMISSION_DECISION_VERSION.to_owned();
        keccak256(match self {
            Self::Reject(decision) => (
                domain,
                version,
                "reject".to_owned(),
                decision.request_id.clone(),
                b256_of(&decision.request_hash),
                U256::from(decision.decided_at),
            )
                .abi_encode_params(),
            Self::Approve(decision) => (
                domain,
                version,
                "approve".to_owned(),
                decision.request_id.clone(),
                b256_of(&decision.request_hash),
                U256::from(decision.decided_at),
                decision.approved_policy.hash(),
                b256_of(&decision.capability_hash),
            )
                .abi_encode_params(),
        })
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Reject(decision) => json!({
                "version": PERMISSION_DECISION_VERSION,
                "kind": "reject",
                "requestId": decision.request_id,
                "requestHash": decision.request_hash,
                "decidedAt": decision.decided_at,
            }),
            Self::Approve(decision) => json!({
                "version": PERMISSION_DECISION_VERSION,
                "kind": "approve",
                "requestId": decision.request_id,
                "requestHash": decision.request_hash,
                "decidedAt": decision.decided_at,
                "approvedPolicy": decision.approved_policy.to_json(),
                "capabilityHash": decision.capability_hash,
            }),
        }
    }
}

pub fn hash_permission_decision(value: &Value) -> ProtocolResult<String> {
    Ok(hex_hash(parse_permission_decision(value)?.hash()))
}

/// A sealed approval the relay accepted for one stored permission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPermission {
    pub permission: ApprovePermissionDecision,
    pub plaintext: String,
}

/// The protocol approval meaning at admission and after durable recovery:
/// the decision binds this exact request, attenuates its policy, and was
/// decided no later than the relay decision time. Evaluated at the decision
/// time, so a retained approval stays readable after its windows close.
/// Kernel capability verification belongs to the SDK.
pub fn parse_approved_permission(
    plaintext: &str,
    request: &PermissionRequest,
    relay_decided_at_ms: u64,
) -> ProtocolResult<ApprovedPermission> {
    let mut value = parse_json(plaintext)
        .ok()
        .or_fail(ErrorCode::PermissionArtifactJsonInvalid)?;
    // The phone's install approval travels beside the SDK decision.
    if let Value::Object(record) = &mut value {
        record.shift_remove("installApproval");
    }
    let PermissionDecision::Approve(permission) = parse_permission_decision(&value)? else {
        return fail(ErrorCode::PermissionArtifactNotApproved);
    };
    ensure(
        permission.decided_at <= relay_decided_at_ms / 1_000,
        ErrorCode::PermissionArtifactNotApproved,
    )?;
    ensure(
        permission.request_id == request.request_id
            && permission.request_hash == hex_hash(request.hash()),
        ErrorCode::PermissionDecisionBindingMismatch,
    )?;
    ensure(
        permission.decided_at >= request.requested_at && permission.decided_at < request.expires_at,
        ErrorCode::PermissionDecisionStale,
    )?;
    ensure(
        is_captured_policy_attenuation(&request.policy, &permission.approved_policy),
        ErrorCode::PermissionPolicyWidening,
    )?;
    ensure(
        permission
            .approved_policy
            .valid_until
            .is_none_or(|until| permission.decided_at <= until),
        ErrorCode::PermissionDecisionStale,
    )?;
    Ok(ApprovedPermission {
        permission,
        plaintext: plaintext.to_owned(),
    })
}
