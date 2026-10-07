//! The owner-signing artifact (`owner-signing-artifact.ts`).

use p256::ecdsa::Signature;
use serde_json::Value;

use crate::capture::{exact_record, field, hex_bytes, is_lower_hex, lower_hash};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure};

pub const OWNER_SIGNING_ARTIFACT_VERSION: &str = "oaath.owner-signing-artifact/v1";

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
