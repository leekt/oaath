//! Non-secret owner-phone comparison code.

use crate::authorization::challenge::sha256_base64url;

/// Bounded base64url match code length. 48 bits is plenty to compare by eye.
pub const NATIVE_DISPLAY_PAYLOAD_LENGTH: usize = 8;
pub const NATIVE_DISPLAY_DOMAIN: &str = "oaath.native-display/v1:";

/// One non-secret comparison code for the requesting app, phone, inbox, and push.
pub fn owner_phone_display_payload(owner_subject: &str, operation_id: &str) -> String {
    let mut digest = sha256_base64url(&format!(
        "{NATIVE_DISPLAY_DOMAIN}{owner_subject}:{operation_id}"
    ));
    digest.truncate(NATIVE_DISPLAY_PAYLOAD_LENGTH);
    digest
}
