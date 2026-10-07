//! The owner-signing artifact (`owner-signing-artifact.ts`) and the relay's
//! Kernel replayable-install artifact verification
//! (`packages/server/src/authorization/owner-signing.ts`).

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;

use crate::capture::{
    exact_record, field, hex_bytes, is_lower_hex, lower_hash, parse_json, utf16_len,
};
use crate::error::{ErrorCode, OrFail, ProtocolError, ProtocolResult, ensure};
use crate::identity::{OwnerCredentialProfile, hex_hash};
use crate::kernel_install::KernelReplayableInstallOwnerSigningRequest;

pub const OWNER_SIGNING_ARTIFACT_VERSION: &str = "oaath.owner-signing-artifact/v1";

/// The relay's bound on one artifact plaintext, in UTF-16 units.
const MAX_ARTIFACT_PLAINTEXT: usize = 32_768;

/// A returned compact low-S P-256 signature over one request. Capturing it
/// neither verifies the signature nor authorizes the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSigningArtifact {
    pub request_hash: String,
    pub signature: String,
}

/// A compact P-256 signature with both scalars in range and a low `s`.
fn low_s_signature(value: &Value) -> Option<&str> {
    let text = value.as_str().filter(|text| is_lower_hex(text, 64))?;
    let signature = Signature::from_slice(&hex_bytes(text)).ok()?;
    signature.normalize_s().is_none().then_some(text)
}

pub fn parse_owner_signing_artifact(value: &Value) -> ProtocolResult<OwnerSigningArtifact> {
    let code = ErrorCode::SigningArtifactInvalid;
    let record =
        exact_record(value, &["version", "kind", "requestHash", "signature"]).or_fail(code)?;
    ensure(
        field(record, "version") == OWNER_SIGNING_ARTIFACT_VERSION
            && field(record, "kind") == "p256",
        code,
    )?;
    Ok(OwnerSigningArtifact {
        request_hash: lower_hash(field(record, "requestHash"))
            .or_fail(code)?
            .to_owned(),
        signature: low_s_signature(field(record, "signature"))
            .or_fail(code)?
            .to_owned(),
    })
}

impl OwnerSigningArtifact {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "version": OWNER_SIGNING_ARTIFACT_VERSION,
            "kind": "p256",
            "requestHash": self.request_hash,
            "signature": self.signature,
        })
    }

    /// The one canonical JSON string representation, in fixed field order.
    pub fn serialize(&self) -> String {
        format!(
            r#"{{"version":"{OWNER_SIGNING_ARTIFACT_VERSION}","kind":"p256","requestHash":"{}","signature":"{}"}}"#,
            self.request_hash, self.signature
        )
    }
}

pub fn serialize_owner_signing_artifact(value: &Value) -> ProtocolResult<String> {
    Ok(parse_owner_signing_artifact(value)?.serialize())
}

/// The server's `boundedText`: 1 through `maximum` UTF-16 units, no controls.
fn bounded_plaintext(text: &str) -> bool {
    (1..=MAX_ARTIFACT_PLAINTEXT).contains(&utf16_len(text))
        && !text
            .chars()
            .any(|character| (character as u32) < 0x20 || character == '\u{7f}')
}

/// Returns the canonical artifact plaintext only after the P-256 owner, the
/// canonical JSON form, the request hash, and the compact low-S signature over
/// the exact Kernel digest all agree. Every failure is `relay_request_invalid`.
pub fn verify_kernel_v4_replayable_install_owner_signing_artifact(
    request: &KernelReplayableInstallOwnerSigningRequest,
    artifact_plaintext: &str,
) -> ProtocolResult<String> {
    let code = ErrorCode::RelayRequestInvalid;
    let OwnerCredentialProfile::P256 { public_key } = request.owner_credential() else {
        return Err(ProtocolError::new(code));
    };
    ensure(bounded_plaintext(artifact_plaintext), code)?;
    let value = parse_json(artifact_plaintext).ok().or_fail(code)?;
    let artifact = parse_owner_signing_artifact(&value).ok().or_fail(code)?;
    let canonical = artifact.serialize();
    ensure(canonical == artifact_plaintext, code)?;
    ensure(artifact.request_hash == hex_hash(request.hash()), code)?;
    let key = VerifyingKey::from_sec1_bytes(&hex_bytes(public_key))
        .ok()
        .or_fail(code)?;
    let signature = Signature::from_slice(&hex_bytes(&artifact.signature))
        .ok()
        .or_fail(code)?;
    key.verify_prehash(&hex_bytes(request.expected_digest()), &signature)
        .ok()
        .or_fail(code)?;
    Ok(canonical)
}
