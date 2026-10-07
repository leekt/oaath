//! The relay's release policy over the `oaath-protocol` contracts.
//!
//! The relay owns transitions, storage, and the wire; the protocol owns what a
//! scope, an approval artifact, and a policy mean. Every function here is
//! pure: it allocates and persists nothing.

use oaath_protocol::owner_signing::verify_kernel_v4_replayable_install_owner_signing_artifact;
use oaath_protocol::permission::{
    ApprovePermissionDecision, PermissionRequest, parse_approved_permission,
};
use oaath_protocol::scope::{StoredAuthorizationScope, classify_stored_authorization_scope};

use crate::error::{RelayErrorCode, RelayResult};

/// Admits one approval artifact for one immutable stored scope and returns
/// the exact plaintext to seal (`submitAuthorizationDecision`):
///
/// - a permission request needs an approved decision bound to it, within its
///   policy, decided no later than the relay decision time;
/// - the P-256 Kernel replayable-install request needs its canonical,
///   verified owner-signing artifact;
/// - every other scope is reject-only.
///
/// Every refusal is `relay_request_invalid`.
pub fn approve_scope(
    requested_scope: &str,
    request_id: &str,
    artifact: &str,
    decided_at_ms: u64,
) -> RelayResult<String> {
    let approved = match classify_stored_authorization_scope(requested_scope, request_id) {
        StoredAuthorizationScope::PermissionRequest(request) => {
            parse_approved_permission(artifact, &request, decided_at_ms)
                .map(|approved| approved.plaintext)
        }
        StoredAuthorizationScope::KernelOwnerSigningRequest(request) => {
            verify_kernel_v4_replayable_install_owner_signing_artifact(&request, artifact)
        }
        StoredAuthorizationScope::OwnerSigningRequest(_) | StoredAuthorizationScope::Unverified => {
            return Err(RelayErrorCode::RequestInvalid);
        }
    };
    approved.map_err(|_| RelayErrorCode::RequestInvalid)
}

/// The exact permission request a stored scope was created from, if it is one.
pub fn stored_permission_request(
    requested_scope: &str,
    request_id: &str,
) -> Option<PermissionRequest> {
    match classify_stored_authorization_scope(requested_scope, request_id) {
        StoredAuthorizationScope::PermissionRequest(request) => Some(request),
        _ => None,
    }
}

/// `parseApprovedPermission` over a retained artifact plaintext.
pub fn retained_approval(
    plaintext: &str,
    request: &PermissionRequest,
    relay_decided_at_ms: u64,
) -> Option<ApprovePermissionDecision> {
    parse_approved_permission(plaintext, request, relay_decided_at_ms)
        .ok()
        .map(|approved| approved.permission)
}
