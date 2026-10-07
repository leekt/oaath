//! Verification of the one root signature over a Kernel replayable-install
//! digest, per root credential kind, exactly as the SDK key profiles verify
//! their own signatures (pinned by `relay/fixtures/grant`):
//!
//! - ECDSA: 65-byte `r || s || v` recovering to the owner over the digest, or
//!   over its EIP-191 message hash (Kernel's ECDSA validator accepts both);
//!   a portal sign-in message is recovered over its EIP-191 hash only;
//! - P-256: compact low-S `r || s` over the digest;
//! - WebAuthn: the reviewed validator's ABI assertion envelope, verified like
//!   `packages/sdk/src/kernel/key/webauthn.ts` `verify`.
//!
//! Anything malformed or unsupported is `false`.

use alloy_primitives::{B256, Bytes, U256, eip191_hash_message, keccak256};
use alloy_sol_types::SolValue;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oaath_protocol::identity::OwnerCredentialProfile;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The relying party a WebAuthn root's assertion must name.
pub struct RelyingParty<'a> {
    pub rp_id: &'a str,
    pub origin: &'a str,
}

const MIN_AUTHENTICATOR_DATA_BYTES: usize = 37;
const MAX_AUTHENTICATOR_DATA_BYTES: usize = 2048;
const MAX_CLIENT_DATA_LENGTH: usize = 4096;
const TYPE_FIELD: &[u8] = br#""type":"webauthn.get""#;

fn hex_bytes(text: &str) -> Vec<u8> {
    hex::decode(text.trim_start_matches("0x")).expect("captured hex")
}

pub fn verify_root_signature(
    owner: &OwnerCredentialProfile,
    digest: B256,
    signature: &[u8],
    relying_party: &RelyingParty<'_>,
) -> bool {
    match owner {
        OwnerCredentialProfile::Ecdsa { address } => verify_ecdsa(address, digest, signature),
        OwnerCredentialProfile::P256 { public_key } => {
            p256_signature(signature).is_some_and(|sig| p256_verify(public_key, &digest.0, &sig))
        }
        OwnerCredentialProfile::WebAuthn { public_key, .. } => {
            verify_webauthn(public_key, digest, signature, relying_party)
        }
    }
}

fn verify_ecdsa(owner: &str, digest: B256, signature: &[u8]) -> bool {
    let eip191 = keccak256([b"\x19Ethereum Signed Message:\n32".as_slice(), &digest.0].concat());
    recovers_owner(owner, &[digest, eip191], signature)
}

/// An EIP-191 `personal_sign` signature by `owner` over the exact `message`.
pub fn verify_ecdsa_message(owner: &str, message: &[u8], signature: &[u8]) -> bool {
    recovers_owner(owner, &[eip191_hash_message(message)], signature)
}

/// A low-S 65-byte `r || s || v` signature over one of `hashes` that recovers
/// to `owner`.
fn recovers_owner(owner: &str, hashes: &[B256], signature: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 65]>::try_from(signature) else {
        return false;
    };
    let recovery = match bytes[64] {
        0 | 27 => 0,
        1 | 28 => 1,
        _ => return false,
    };
    let Ok(sig) = k256::ecdsa::Signature::from_slice(&bytes[..64]) else {
        return false;
    };
    // A high-S signature is malleable; wallets never produce one.
    if sig.normalize_s().is_some() {
        return false;
    }
    let Some(recovery) = k256::ecdsa::RecoveryId::from_byte(recovery) else {
        return false;
    };
    let owner = hex_bytes(owner);
    hashes.iter().any(|hash| {
        k256::ecdsa::VerifyingKey::recover_from_prehash(&hash.0, &sig, recovery).is_ok_and(|key| {
            let point = key.to_encoded_point(false);
            keccak256(&point.as_bytes()[1..])[12..] == owner[..]
        })
    })
}

fn p256_signature(signature: &[u8]) -> Option<p256::ecdsa::Signature> {
    let sig = p256::ecdsa::Signature::from_slice(signature).ok()?;
    sig.normalize_s().is_none().then_some(sig)
}

fn p256_verify(public_key: &str, prehash: &[u8], signature: &p256::ecdsa::Signature) -> bool {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&hex_bytes(public_key))
        .is_ok_and(|key| key.verify_prehash(prehash, signature).is_ok())
}

fn verify_webauthn(
    public_key: &str,
    digest: B256,
    signature: &[u8],
    relying_party: &RelyingParty<'_>,
) -> bool {
    type Assertion = (Bytes, String, U256, U256, U256, bool);
    let Ok((authenticator_data, client_data, type_location, r, s, use_precompiled)) =
        Assertion::abi_decode_params(signature)
    else {
        return false;
    };
    if use_precompiled
        || !(MIN_AUTHENTICATOR_DATA_BYTES..=MAX_AUTHENTICATOR_DATA_BYTES)
            .contains(&authenticator_data.len())
        || client_data.is_empty()
        || client_data.encode_utf16().count() > MAX_CLIENT_DATA_LENGTH
    {
        return false;
    }
    if authenticator_data[..32] != Sha256::digest(relying_party.rp_id.as_bytes())[..] {
        return false;
    }
    // User present and verified; a backed-up credential must be eligible.
    let flags = authenticator_data[32];
    if flags & 0x01 == 0 || flags & 0x04 == 0 || (flags & 0x08 == 0 && flags & 0x10 != 0) {
        return false;
    }
    let Ok(location) = usize::try_from(type_location) else {
        return false;
    };
    if client_data
        .as_bytes()
        .get(location..location.saturating_add(TYPE_FIELD.len()))
        != Some(TYPE_FIELD)
    {
        return false;
    }
    let Ok(Value::Object(client)) = serde_json::from_str::<Value>(&client_data) else {
        return false;
    };
    if client.get("type").and_then(Value::as_str) != Some("webauthn.get")
        || client.get("challenge").and_then(Value::as_str)
            != Some(URL_SAFE_NO_PAD.encode(digest.0).as_str())
        || client.get("origin").and_then(Value::as_str) != Some(relying_party.origin)
        || client.get("crossOrigin") == Some(&Value::Bool(true))
    {
        return false;
    }
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&r.to_be_bytes::<32>());
    compact[32..].copy_from_slice(&s.to_be_bytes::<32>());
    let Some(sig) = p256_signature(&compact) else {
        return false;
    };
    let message = Sha256::digest(
        [
            authenticator_data.as_ref(),
            &Sha256::digest(client_data.as_bytes())[..],
        ]
        .concat(),
    );
    p256_verify(public_key, &message, &sig)
}
