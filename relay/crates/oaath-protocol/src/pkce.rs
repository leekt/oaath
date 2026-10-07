//! PKCE S256 challenge derivation (`pkce.ts`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::error::{ErrorCode, ProtocolResult, ensure};

/// RFC 7636 S256 challenge of a 43 to 128 character unreserved verifier.
pub fn derive_code_challenge(code_verifier: &str) -> ProtocolResult<String> {
    ensure(
        (43..=128).contains(&code_verifier.len())
            && code_verifier.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            }),
        ErrorCode::AuthorizationCodeVerifierMismatch,
    )?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes())))
}
