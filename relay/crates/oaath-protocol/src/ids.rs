//! Canonical lowercase identifiers (`ids.ts`).

use serde_json::Value;

/// `^[a-z0-9][a-z0-9._-]{0,63}$`: client, device, account, and workspace ids.
pub fn is_canonical_identifier(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=64).contains(&bytes.len())
        && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

pub(crate) fn canonical_identifier(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| is_canonical_identifier(text))
}
