//! Authoritative classification of one immutable stored authorization scope
//! (`packages/server/src/authorization/scope.ts`).

use serde_json::{Value, json};

use crate::capture::parse_json;
use crate::identity::OwnerCredentialProfile;
use crate::kernel_install::{
    KernelReplayableInstallOwnerSigningRequest,
    parse_kernel_replayable_install_owner_signing_request,
};
use crate::permission::{PermissionRequest, parse_permission_request};
use crate::signing_request::{OwnerSigningRequest, parse_owner_signing_request};

/// Whether the owner may approve the scope or only reject it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDecision {
    ApproveOrReject,
    RejectOnly,
}

impl ScopeDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApproveOrReject => "approve-or-reject",
            Self::RejectOnly => "reject-only",
        }
    }
}

/// An exact permission request or the one exact P-256 Kernel
/// replayable-install request may be approved. Other closed owner-signing
/// requests are captured but reject-only. Unknown and malformed scopes stay
/// readable and rejectable but never authorize artifact creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredAuthorizationScope {
    PermissionRequest(PermissionRequest),
    KernelOwnerSigningRequest(KernelReplayableInstallOwnerSigningRequest),
    OwnerSigningRequest(OwnerSigningRequest),
    Unverified,
}

impl StoredAuthorizationScope {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::PermissionRequest(_) => "permission-request",
            Self::KernelOwnerSigningRequest(_) => "kernel-owner-signing-request",
            Self::OwnerSigningRequest(_) => "owner-signing-request",
            Self::Unverified => "unverified",
        }
    }

    pub const fn decision(&self) -> ScopeDecision {
        match self {
            Self::PermissionRequest(_) | Self::KernelOwnerSigningRequest(_) => {
                ScopeDecision::ApproveOrReject
            }
            Self::OwnerSigningRequest(_) | Self::Unverified => ScopeDecision::RejectOnly,
        }
    }

    pub fn to_json(&self) -> Value {
        let request = match self {
            Self::PermissionRequest(request) => request.to_json(),
            Self::KernelOwnerSigningRequest(request) => request.to_json(),
            Self::OwnerSigningRequest(request) => request.to_json(),
            Self::Unverified => {
                return json!({"kind": self.kind(), "decision": self.decision().as_str()});
            }
        };
        json!({"kind": self.kind(), "decision": self.decision().as_str(), "request": request})
    }
}

/// Classifies the stored scope text; the stored request id is authoritative.
pub fn classify_stored_authorization_scope(
    requested_scope: &str,
    request_id: &str,
) -> StoredAuthorizationScope {
    let Ok(Value::Object(parsed)) = parse_json(requested_scope) else {
        return StoredAuthorizationScope::Unverified;
    };
    let mut with_request_id = parsed.clone();
    with_request_id.insert("requestId".to_owned(), Value::String(request_id.to_owned()));
    if let Ok(request) = parse_permission_request(&Value::Object(with_request_id)) {
        return StoredAuthorizationScope::PermissionRequest(request);
    }
    let parsed = Value::Object(parsed);
    let Ok(request) = parse_owner_signing_request(&parsed) else {
        return StoredAuthorizationScope::Unverified;
    };
    if let Ok(kernel) = parse_kernel_replayable_install_owner_signing_request(&parsed)
        && matches!(
            kernel.owner_credential(),
            OwnerCredentialProfile::P256 { .. }
        )
    {
        return StoredAuthorizationScope::KernelOwnerSigningRequest(kernel);
    }
    StoredAuthorizationScope::OwnerSigningRequest(request)
}
