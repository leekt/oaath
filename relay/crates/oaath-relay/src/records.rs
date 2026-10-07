//! Exact current-version durable relay records and the shared text rules.
//!
//! Durable storage is a trust boundary: every read is captured into an exact,
//! owned record before typed code consumes it. There is exactly one current
//! version per record and no reader for any older version.

use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::{RelayErrorCode, RelayResult};

pub const AUTHORIZATION_REQUEST_RECORD_VERSION: &str = "oaath.authorization-request-record/v1";
pub const AUTHORIZATION_DECISION_RECORD_VERSION: &str = "oaath.authorization-decision-record/v1";
pub const AUTHORIZATION_CODE_RECORD_VERSION: &str = "oaath.authorization-code-record/v1";
pub const ENCRYPTED_ARTIFACT_RECORD_VERSION: &str = "oaath.encrypted-artifact-record/v1";
pub const CAPABILITY_INVALIDATION_RECORD_VERSION: &str = "oaath.capability-invalidation-record/v1";

/// Bounded field limits owned here and shared with wire capture. Lengths are
/// UTF-16 code units, exactly as JavaScript's `String.length` counts them.
pub mod limits {
    pub const IDENTIFIER: usize = 256;
    pub const REDIRECT_URI: usize = 2048;
    pub const CODE_CHALLENGE: usize = 128;
    pub const CODE_VERIFIER: usize = 128;
    pub const REQUESTED_SCOPE: usize = 8192;
    pub const ARTIFACT_PLAINTEXT: usize = 32_768;
    pub const CIPHERTEXT_REF: usize = 65_536;
}

/// `Number.MAX_SAFE_INTEGER`: every relay timestamp stays inside it.
pub const MAX_TIMESTAMP: u64 = (1 << 53) - 1;

const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

/// A bounded non-empty string without control characters.
pub fn bounded_text(
    value: Option<&Value>,
    maximum: usize,
    code: RelayErrorCode,
) -> RelayResult<&str> {
    match value {
        Some(Value::String(text)) => bounded_str(text, maximum, code),
        _ => Err(code),
    }
}

pub fn bounded_str(text: &str, maximum: usize, code: RelayErrorCode) -> RelayResult<&str> {
    let length = text.encode_utf16().count();
    if length < 1 || length > maximum {
        return Err(code);
    }
    // Control characters would corrupt logs and downstream headers.
    if text.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(code);
    }
    Ok(text)
}

/// A bounded URL-safe identifier: `^[A-Za-z0-9._~-]+$`, at most 256 units.
pub fn canonical_identifier(value: Option<&Value>, code: RelayErrorCode) -> RelayResult<&str> {
    match value {
        Some(Value::String(text)) => canonical_str(text, code),
        _ => Err(code),
    }
}

pub fn canonical_str(text: &str, code: RelayErrorCode) -> RelayResult<&str> {
    let text = bounded_str(text, limits::IDENTIFIER, code)?;
    if !text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
    {
        return Err(code);
    }
    Ok(text)
}

/// A non-negative safe integer, as `Number.isSafeInteger` admits it.
pub fn timestamp(value: Option<&Value>, code: RelayErrorCode) -> RelayResult<u64> {
    let Some(Value::Number(number)) = value else {
        return Err(code);
    };
    let parsed = number
        .as_u64()
        .or_else(|| {
            // `1.0` is the safe integer 1 in JavaScript.
            let float = number.as_f64()?;
            (float.fract() == 0.0 && float.is_sign_positive() && float <= MAX_TIMESTAMP as f64)
                .then_some(float as u64)
        })
        .ok_or(code)?;
    if parsed > MAX_TIMESTAMP {
        return Err(code);
    }
    Ok(parsed)
}

fn nullable_timestamp(value: Option<&Value>, code: RelayErrorCode) -> RelayResult<Option<u64>> {
    match value {
        Some(Value::Null) => Ok(None),
        other => timestamp(other, code).map(Some),
    }
}

/// True for a lowercase `0x`-prefixed 32-byte hash.
pub fn is_lowercase_hash(text: &str) -> bool {
    text.len() == 66
        && text.starts_with("0x")
        && text[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Captures a plain object whose own keys are exactly `keys`.
pub fn exact_record<'a>(
    value: &'a Value,
    keys: &[&str],
    code: RelayErrorCode,
) -> RelayResult<&'a Map<String, Value>> {
    let Value::Object(record) = value else {
        return Err(code);
    };
    if record.len() != keys.len() || !keys.iter().all(|key| record.contains_key(*key)) {
        return Err(code);
    }
    Ok(record)
}

fn version(value: Option<&Value>, expected: &str) -> RelayResult<()> {
    match value {
        Some(Value::String(text)) if text == expected => Ok(()),
        _ => Err(UNREADABLE),
    }
}

fn owned(text: &str) -> String {
    text.to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationRequestRecord {
    pub version: &'static str,
    pub request_id: String,
    /// Client bound by the deployment authentication port, never by wire input.
    pub client_id: String,
    /// Requesting member's subject, independent of the approving device.
    pub subject: String,
    pub owner_device_id: String,
    pub owner_subject: String,
    /// Organization/audience bound by the authentication port at creation.
    pub organization_audience: Option<String>,
    pub redirect_uri: String,
    /// PKCE S256 challenge; the verifier never reaches the store.
    pub code_challenge: String,
    /// Opaque owner-reviewed scope payload.
    pub requested_scope: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionOutcome {
    Approved,
    Rejected,
    Withdrawn,
}

impl DecisionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Withdrawn => "withdrawn",
        }
    }

    fn parse(value: Option<&Value>) -> RelayResult<Self> {
        match value.and_then(Value::as_str) {
            Some("approved") => Ok(Self::Approved),
            Some("rejected") => Ok(Self::Rejected),
            Some("withdrawn") => Ok(Self::Withdrawn),
            _ => Err(UNREADABLE),
        }
    }
}

/// Terminal decision. Its existence is the single authoritative fact that an
/// authorization request was decided; the request record never mutates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationDecisionRecord {
    pub version: &'static str,
    pub request_id: String,
    pub outcome: DecisionOutcome,
    pub decided_at: u64,
    /// KMS-sealed copy of the released code for authenticated client pickup.
    /// Present exactly when the outcome is an approval.
    pub code_ref: Option<String>,
    pub code_expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationCodeRecord {
    pub version: &'static str,
    /// SHA-256 (base64url) of the released code. The code is never stored.
    pub code_hash: String,
    pub request_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub artifact_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// Set exactly once. A non-null value is terminal.
    pub consumed_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedArtifactRecord {
    pub version: &'static str,
    pub artifact_id: String,
    pub request_id: String,
    pub client_id: String,
    /// Opaque KMS reference. Plaintext never reaches the store.
    pub ciphertext_ref: String,
    pub created_at: u64,
    /// Set exactly once. A non-null value is terminal.
    pub claimed_at: Option<u64>,
}

/// One durable capability invalidation for a Grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityInvalidationRecord {
    pub version: &'static str,
    pub grant_id: String,
    /// The authenticated client that recorded the invalidation.
    pub client_id: String,
    pub capability_hash: String,
    pub invalidated_at: u64,
}

impl AuthorizationRequestRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "requestId",
                "clientId",
                "subject",
                "ownerDeviceId",
                "ownerSubject",
                "organizationAudience",
                "redirectUri",
                "codeChallenge",
                "requestedScope",
                "createdAt",
                "expiresAt",
            ],
            UNREADABLE,
        )?;
        version(r.get("version"), AUTHORIZATION_REQUEST_RECORD_VERSION)?;
        Ok(Self {
            version: AUTHORIZATION_REQUEST_RECORD_VERSION,
            request_id: owned(canonical_identifier(r.get("requestId"), UNREADABLE)?),
            client_id: owned(canonical_identifier(r.get("clientId"), UNREADABLE)?),
            subject: owned(canonical_identifier(r.get("subject"), UNREADABLE)?),
            owner_device_id: owned(canonical_identifier(r.get("ownerDeviceId"), UNREADABLE)?),
            owner_subject: owned(canonical_identifier(r.get("ownerSubject"), UNREADABLE)?),
            organization_audience: match r.get("organizationAudience") {
                Some(Value::Null) => None,
                other => Some(owned(canonical_identifier(other, UNREADABLE)?)),
            },
            redirect_uri: owned(bounded_text(
                r.get("redirectUri"),
                limits::REDIRECT_URI,
                UNREADABLE,
            )?),
            code_challenge: owned(canonical_identifier(r.get("codeChallenge"), UNREADABLE)?),
            requested_scope: owned(bounded_text(
                r.get("requestedScope"),
                limits::REQUESTED_SCOPE,
                UNREADABLE,
            )?),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            expires_at: timestamp(r.get("expiresAt"), UNREADABLE)?,
        })
    }
}

impl AuthorizationDecisionRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "requestId",
                "outcome",
                "decidedAt",
                "codeRef",
                "codeExpiresAt",
            ],
            UNREADABLE,
        )?;
        let outcome = DecisionOutcome::parse(r.get("outcome"))?;
        let code_ref_null = matches!(r.get("codeRef"), Some(Value::Null));
        // A sealed code exists only for an approval. The portal's own grants
        // (`member_grant.rs`) are approved without releasing one.
        if outcome != DecisionOutcome::Approved && !code_ref_null {
            return Err(UNREADABLE);
        }
        if code_ref_null != matches!(r.get("codeExpiresAt"), Some(Value::Null)) {
            return Err(UNREADABLE);
        }
        version(r.get("version"), AUTHORIZATION_DECISION_RECORD_VERSION)?;
        Ok(Self {
            version: AUTHORIZATION_DECISION_RECORD_VERSION,
            request_id: owned(canonical_identifier(r.get("requestId"), UNREADABLE)?),
            outcome,
            decided_at: timestamp(r.get("decidedAt"), UNREADABLE)?,
            code_ref: if code_ref_null {
                None
            } else {
                Some(owned(bounded_text(
                    r.get("codeRef"),
                    limits::CIPHERTEXT_REF,
                    UNREADABLE,
                )?))
            },
            code_expires_at: nullable_timestamp(r.get("codeExpiresAt"), UNREADABLE)?,
        })
    }
}

impl AuthorizationCodeRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "codeHash",
                "requestId",
                "clientId",
                "redirectUri",
                "codeChallenge",
                "artifactId",
                "createdAt",
                "expiresAt",
                "consumedAt",
            ],
            UNREADABLE,
        )?;
        version(r.get("version"), AUTHORIZATION_CODE_RECORD_VERSION)?;
        Ok(Self {
            version: AUTHORIZATION_CODE_RECORD_VERSION,
            code_hash: owned(canonical_identifier(r.get("codeHash"), UNREADABLE)?),
            request_id: owned(canonical_identifier(r.get("requestId"), UNREADABLE)?),
            client_id: owned(canonical_identifier(r.get("clientId"), UNREADABLE)?),
            redirect_uri: owned(bounded_text(
                r.get("redirectUri"),
                limits::REDIRECT_URI,
                UNREADABLE,
            )?),
            code_challenge: owned(canonical_identifier(r.get("codeChallenge"), UNREADABLE)?),
            artifact_id: owned(canonical_identifier(r.get("artifactId"), UNREADABLE)?),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            expires_at: timestamp(r.get("expiresAt"), UNREADABLE)?,
            consumed_at: nullable_timestamp(r.get("consumedAt"), UNREADABLE)?,
        })
    }
}

impl EncryptedArtifactRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "artifactId",
                "requestId",
                "clientId",
                "ciphertextRef",
                "createdAt",
                "claimedAt",
            ],
            UNREADABLE,
        )?;
        version(r.get("version"), ENCRYPTED_ARTIFACT_RECORD_VERSION)?;
        Ok(Self {
            version: ENCRYPTED_ARTIFACT_RECORD_VERSION,
            artifact_id: owned(canonical_identifier(r.get("artifactId"), UNREADABLE)?),
            request_id: owned(canonical_identifier(r.get("requestId"), UNREADABLE)?),
            client_id: owned(canonical_identifier(r.get("clientId"), UNREADABLE)?),
            ciphertext_ref: owned(bounded_text(
                r.get("ciphertextRef"),
                limits::CIPHERTEXT_REF,
                UNREADABLE,
            )?),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            claimed_at: nullable_timestamp(r.get("claimedAt"), UNREADABLE)?,
        })
    }
}

impl CapabilityInvalidationRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "grantId",
                "clientId",
                "capabilityHash",
                "invalidatedAt",
            ],
            UNREADABLE,
        )?;
        let capability_hash = bounded_text(r.get("capabilityHash"), 66, UNREADABLE)?;
        if !is_lowercase_hash(capability_hash) {
            return Err(UNREADABLE);
        }
        version(r.get("version"), CAPABILITY_INVALIDATION_RECORD_VERSION)?;
        Ok(Self {
            version: CAPABILITY_INVALIDATION_RECORD_VERSION,
            grant_id: owned(canonical_identifier(r.get("grantId"), UNREADABLE)?),
            client_id: owned(canonical_identifier(r.get("clientId"), UNREADABLE)?),
            capability_hash: owned(capability_hash),
            invalidated_at: timestamp(r.get("invalidatedAt"), UNREADABLE)?,
        })
    }
}

/// Serializes a record into the exact JSON shape its parser reads back.
pub fn to_value<Record: Serialize>(record: &Record) -> Value {
    serde_json::to_value(record).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn counts_utf16_units_and_rejects_control_characters() {
        assert!(bounded_str("😀", 2, RelayErrorCode::RequestInvalid).is_ok());
        assert!(bounded_str("😀", 1, RelayErrorCode::RequestInvalid).is_err());
        assert!(bounded_str("", 1, RelayErrorCode::RequestInvalid).is_err());
        assert!(bounded_str("a\u{0}b", 8, RelayErrorCode::RequestInvalid).is_err());
        assert!(bounded_str("a\u{7f}b", 8, RelayErrorCode::RequestInvalid).is_err());
        assert!(bounded_str("a\u{80}b", 8, RelayErrorCode::RequestInvalid).is_ok());
        assert!(canonical_str("A-z0._~", RelayErrorCode::RequestInvalid).is_ok());
        assert!(canonical_str("not canonical", RelayErrorCode::RequestInvalid).is_err());
        assert!(canonical_str("not%20canonical", RelayErrorCode::RequestInvalid).is_err());
        assert!(canonical_str(&"a".repeat(257), RelayErrorCode::RequestInvalid).is_err());
    }

    fn request() -> Value {
        json!({
            "version": AUTHORIZATION_REQUEST_RECORD_VERSION,
            "requestId": "request-1",
            "clientId": "client-a",
            "subject": "subject-1",
            "ownerDeviceId": "phone-1",
            "ownerSubject": "subject-1",
            "organizationAudience": null,
            "redirectUri": "https://app.example/callback",
            "codeChallenge": "challenge",
            "requestedScope": "{}",
            "createdAt": 1,
            "expiresAt": 2,
        })
    }

    #[test]
    fn accepts_the_exact_current_version() {
        let parsed = AuthorizationRequestRecord::parse(&request()).unwrap();
        assert_eq!(to_value(&parsed), request());
    }

    #[test]
    fn rejects_an_old_extra_bearing_missing_or_malformed_record() {
        let mut old = request();
        old["version"] = json!("oaath.authorization-request-record/v0");
        let mut extra = request();
        extra["extra"] = json!(1);
        let mut missing = request();
        missing.as_object_mut().unwrap().remove("subject");
        let mut negative = request();
        negative["createdAt"] = json!(-1);
        let mut unsafe_time = request();
        unsafe_time["expiresAt"] = json!(9_007_199_254_740_992u64);
        let mut fraction = request();
        fraction["expiresAt"] = json!(1.5);
        for value in [
            old,
            extra,
            missing,
            negative,
            unsafe_time,
            fraction,
            json!([]),
        ] {
            assert_eq!(
                AuthorizationRequestRecord::parse(&value),
                Err(RelayErrorCode::RecordUnreadable)
            );
        }
    }

    #[test]
    fn rejects_an_unsupported_or_contradictory_decision() {
        let decision = |outcome: &str, code_ref: Value, expires: Value| {
            json!({
                "version": AUTHORIZATION_DECISION_RECORD_VERSION,
                "requestId": "request-1",
                "outcome": outcome,
                "decidedAt": 1,
                "codeRef": code_ref,
                "codeExpiresAt": expires,
            })
        };
        assert!(
            AuthorizationDecisionRecord::parse(&decision("approved", json!("ref"), json!(5)))
                .is_ok()
        );
        assert!(
            AuthorizationDecisionRecord::parse(&decision("withdrawn", json!(null), json!(null)))
                .is_ok()
        );
        // The portal's own grants are approved without a released code.
        assert!(
            AuthorizationDecisionRecord::parse(&decision("approved", json!(null), json!(null)))
                .is_ok()
        );
        for value in [
            decision("maybe", json!(null), json!(null)),
            decision("rejected", json!("ref"), json!(5)),
            decision("approved", json!("ref"), json!(null)),
        ] {
            assert_eq!(
                AuthorizationDecisionRecord::parse(&value),
                Err(RelayErrorCode::RecordUnreadable)
            );
        }
    }

    #[test]
    fn rejects_a_malformed_invalidation_hash() {
        let record = |hash: &str| {
            json!({
                "version": CAPABILITY_INVALIDATION_RECORD_VERSION,
                "grantId": "grant-1",
                "clientId": "client-a",
                "capabilityHash": hash,
                "invalidatedAt": 1,
            })
        };
        assert!(
            CapabilityInvalidationRecord::parse(&record(&format!("0x{}", "ab".repeat(32)))).is_ok()
        );
        assert!(
            CapabilityInvalidationRecord::parse(&record(&format!("0x{}", "AB".repeat(32))))
                .is_err()
        );
    }
}
