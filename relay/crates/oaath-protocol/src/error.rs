//! Structured protocol failure codes.
//!
//! Each code string is the exact `code` the TypeScript owner throws. Machine
//! decisions use [`ErrorCode`], never the display text.

/// The structured code of one protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    ProtocolIdInvalid,
    AuthorizationCodeVerifierMismatch,
    GrantReferenceInvalid,
    ServiceBootstrapInvalid,
    SigningArtifactInvalid,
    SigningRequestInvalid,
    OwnerCredentialProfileInvalid,
    OperatorCredentialProfileInvalid,
    KernelAccountProfileInvalid,
    /// The derived profile uses the meta-factory route, or the owner validator
    /// does not match the owner kind. Rust-owned: the SDK
    /// refuses the same inputs before reading the factory.
    KernelAccountDerivationInvalid,
    GrantPolicyInvalid,
    GrantPolicyAttenuationInputInvalid,
    PermissionRequestInvalid,
    PermissionDecisionInvalid,
    PermissionProtocolInputInvalid,
    PermissionDecisionBindingMismatch,
    PermissionDecisionStale,
    PermissionPolicyWidening,
    /// The sealed permission artifact plaintext is not JSON. TypeScript throws
    /// a bare `SyntaxError` here; this code names that failure.
    PermissionArtifactJsonInvalid,
    /// The decision is not an approval at the relay decision time. TypeScript
    /// throws a bare `Error` here; this code names that failure.
    PermissionArtifactNotApproved,
    /// The relay's own rejection of a Kernel owner-signing artifact.
    RelayRequestInvalid,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolIdInvalid => "protocol_id_invalid",
            Self::AuthorizationCodeVerifierMismatch => "authorization_code_verifier_mismatch",
            Self::GrantReferenceInvalid => "grant_reference_invalid",
            Self::ServiceBootstrapInvalid => "service_bootstrap_invalid",
            Self::SigningArtifactInvalid => "signing_artifact_invalid",
            Self::SigningRequestInvalid => "signing_request_invalid",
            Self::OwnerCredentialProfileInvalid => "owner_credential_profile_invalid",
            Self::OperatorCredentialProfileInvalid => "operator_credential_profile_invalid",
            Self::KernelAccountProfileInvalid => "kernel_account_profile_invalid",
            Self::KernelAccountDerivationInvalid => "kernel_account_derivation_invalid",
            Self::GrantPolicyInvalid => "grant_policy_invalid",
            Self::GrantPolicyAttenuationInputInvalid => "grant_policy_attenuation_input_invalid",
            Self::PermissionRequestInvalid => "permission_request_invalid",
            Self::PermissionDecisionInvalid => "permission_decision_invalid",
            Self::PermissionProtocolInputInvalid => "permission_protocol_input_invalid",
            Self::PermissionDecisionBindingMismatch => "permission_decision_binding_mismatch",
            Self::PermissionDecisionStale => "permission_decision_stale",
            Self::PermissionPolicyWidening => "permission_policy_widening",
            Self::PermissionArtifactJsonInvalid => "permission_artifact_json_invalid",
            Self::PermissionArtifactNotApproved => "permission_artifact_not_approved",
            Self::RelayRequestInvalid => "relay_request_invalid",
        }
    }
}

/// One fail-closed protocol rejection. Carries only its structured code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", .code.as_str())]
pub struct ProtocolError {
    pub code: ErrorCode,
}

impl ProtocolError {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Fails with `code`.
pub(crate) fn fail<T>(code: ErrorCode) -> ProtocolResult<T> {
    Err(ProtocolError::new(code))
}

/// Fails with `code` unless `condition` holds.
pub(crate) fn ensure(condition: bool, code: ErrorCode) -> ProtocolResult<()> {
    if condition { Ok(()) } else { fail(code) }
}

/// Converts an absent capture into a failure with `code`.
pub(crate) trait OrFail<T> {
    fn or_fail(self, code: ErrorCode) -> ProtocolResult<T>;
}

impl<T> OrFail<T> for Option<T> {
    fn or_fail(self, code: ErrorCode) -> ProtocolResult<T> {
        self.ok_or(ProtocolError::new(code))
    }
}
