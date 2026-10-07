//! The relay's release policy over the `oaath-protocol` contracts.
//!
//! The relay owns transitions, storage, and the wire; the protocol owns what a
//! scope, an approval artifact, and a policy mean. Every function here is
//! pure: it allocates and persists nothing.

use oaath_protocol::permission::PermissionRequest;
use oaath_protocol::scope::{StoredAuthorizationScope, classify_stored_authorization_scope};

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
