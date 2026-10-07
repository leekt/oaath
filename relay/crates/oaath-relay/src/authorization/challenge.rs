//! PKCE S256 verification and the relay's random/digest primitives. The
//! verifier is never stored: the store holds the S256 challenge, and consume
//! recomputes it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};

const IDENTIFIER_BYTES: usize = 32;

/// 256 bits of CSPRNG output, base64url encoded.
pub fn random_identifier() -> String {
    let mut bytes = [0u8; IDENTIFIER_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sha256_base64url(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// RFC 7636 code verifier: 43-128 unreserved characters.
fn is_code_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

fn timing_safe_equal(left: &str, right: &str) -> bool {
    // Both operands are base64url digests, so length is not itself a secret.
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |difference, (l, r)| difference | (l ^ r))
        == 0
}

/// True only when `code_verifier` is a well-formed RFC 7636 verifier whose S256
/// digest equals the stored challenge. Any malformed input is a mismatch.
pub fn verify_pkce_s256(code_verifier: &str, stored_code_challenge: &str) -> bool {
    is_code_verifier(code_verifier)
        && timing_safe_equal(&sha256_base64url(code_verifier), stored_code_challenge)
}

/// True when the value can be a stored S256 challenge (43 base64url characters).
pub fn is_code_challenge_s256(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER: &str = "u9Xq2Tb7yZ0aVc4Nk1Lm6Pr8Sd3Wf5Hg7Jt9Bn2Qx0z";

    #[test]
    fn accepts_only_the_verifier_behind_the_stored_challenge() {
        let challenge = sha256_base64url(VERIFIER);
        assert!(is_code_challenge_s256(&challenge));
        assert!(verify_pkce_s256(VERIFIER, &challenge));
        assert!(!verify_pkce_s256(
            &format!("{}Z", &VERIFIER[..42]),
            &challenge
        ));
        assert!(!verify_pkce_s256("short", &challenge));
        assert!(!verify_pkce_s256(&"a".repeat(129), &challenge));
        assert!(!verify_pkce_s256(
            &format!("{} ", &VERIFIER[..42]),
            &challenge
        ));
        assert!(!verify_pkce_s256(VERIFIER, "not-the-stored-challenge"));
    }

    #[test]
    fn mints_43_character_identifiers() {
        let first = random_identifier();
        assert!(is_code_challenge_s256(&first));
        assert_ne!(first, random_identifier());
    }
}
