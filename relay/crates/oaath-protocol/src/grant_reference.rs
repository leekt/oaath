//! Adopter-facing Grant reference and revision-verification wire contract
//! (`grant-reference.ts`).

use serde_json::{Value, json};

use crate::capture::{
    MAX_UINT48, canonical_bounded_string, capture_record, exact_record, field, has_exact_keys,
    lower_hash, safe_integer,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure, fail};

pub const GRANT_REFERENCE_VERSION: &str = "oaath.grant-reference/v1";
/// The one authority revision an approved Grant has today.
pub const GRANT_REFERENCE_APPROVED_REVISION: u64 = 1;

const CODE: ErrorCode = ErrorCode::GrantReferenceInvalid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRefState {
    Pending,
    Active,
    Revoked,
    Expired,
}

impl GrantRefState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

/// Immutable server-verified evidence suitable for persistence by the adopter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OaathGrantRef {
    pub grant_id: String,
    pub revision: u64,
    pub subject: String,
    pub client_id: String,
    pub organization_audience: String,
    pub state: GrantRefState,
    pub policy_digest: String,
}

/// Every field is an assertion compared against durable evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyGrantRevisionInput {
    pub grant_id: String,
    pub revision: u64,
    pub subject: String,
    pub client_id: String,
    pub organization_audience: String,
    pub required_calls_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantVerificationDeniedCode {
    Pending,
    Rejected,
    Revoked,
    Expired,
    RevisionMismatch,
    SubjectMismatch,
    ClientMismatch,
    AudienceMismatch,
    CallsMismatch,
}

impl GrantVerificationDeniedCode {
    const ALL: [Self; 9] = [
        Self::Pending,
        Self::Rejected,
        Self::Revoked,
        Self::Expired,
        Self::RevisionMismatch,
        Self::SubjectMismatch,
        Self::ClientMismatch,
        Self::AudienceMismatch,
        Self::CallsMismatch,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "grant_pending",
            Self::Rejected => "grant_rejected",
            Self::Revoked => "grant_revoked",
            Self::Expired => "grant_expired",
            Self::RevisionMismatch => "grant_revision_mismatch",
            Self::SubjectMismatch => "grant_subject_mismatch",
            Self::ClientMismatch => "grant_client_mismatch",
            Self::AudienceMismatch => "grant_audience_mismatch",
            Self::CallsMismatch => "grant_calls_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantVerificationUnknownCode {
    /// No Grant the caller is entitled to see; absence, not an existence oracle.
    Unknown,
    /// Stored evidence is unreadable or contradictory. Never authorizes.
    Unreadable,
}

impl GrantVerificationUnknownCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "grant_unknown",
            Self::Unreadable => "grant_unreadable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantVerificationResult {
    Authorized(OaathGrantRef),
    Denied(GrantVerificationDeniedCode),
    Unknown(GrantVerificationUnknownCode),
}

/// `^[A-Za-z0-9._~-]{1,256}$`, the relay's authenticated identifier domain.
fn identifier(value: &Value) -> ProtocolResult<String> {
    let text = value.as_str().filter(|text| {
        (1..=256).contains(&text.len())
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
    });
    Ok(text.or_fail(CODE)?.to_owned())
}

fn grant_id(value: &Value) -> ProtocolResult<String> {
    Ok(canonical_bounded_string(value, 256)
        .or_fail(CODE)?
        .to_owned())
}

fn revision(value: &Value) -> ProtocolResult<u64> {
    safe_integer(value, 1, MAX_UINT48).or_fail(CODE)
}

fn digest(value: &Value) -> ProtocolResult<String> {
    Ok(lower_hash(value).or_fail(CODE)?.to_owned())
}

pub fn parse_verify_grant_revision_input(
    value: &Value,
) -> ProtocolResult<VerifyGrantRevisionInput> {
    let record = exact_record(
        value,
        &[
            "grantId",
            "revision",
            "subject",
            "clientId",
            "organizationAudience",
            "requiredCallsDigest",
        ],
    )
    .or_fail(CODE)?;
    Ok(VerifyGrantRevisionInput {
        grant_id: grant_id(field(record, "grantId"))?,
        revision: revision(field(record, "revision"))?,
        subject: identifier(field(record, "subject"))?,
        client_id: identifier(field(record, "clientId"))?,
        organization_audience: identifier(field(record, "organizationAudience"))?,
        required_calls_digest: digest(field(record, "requiredCallsDigest"))?,
    })
}

pub fn parse_oaath_grant_ref(value: &Value) -> ProtocolResult<OaathGrantRef> {
    let record = exact_record(
        value,
        &[
            "version",
            "grantId",
            "revision",
            "subject",
            "clientId",
            "organizationAudience",
            "state",
            "policyDigest",
        ],
    )
    .or_fail(CODE)?;
    ensure(field(record, "version") == GRANT_REFERENCE_VERSION, CODE)?;
    let state = match field(record, "state").as_str() {
        Some("pending") => GrantRefState::Pending,
        Some("active") => GrantRefState::Active,
        Some("revoked") => GrantRefState::Revoked,
        Some("expired") => GrantRefState::Expired,
        _ => return fail(CODE),
    };
    Ok(OaathGrantRef {
        grant_id: grant_id(field(record, "grantId"))?,
        revision: revision(field(record, "revision"))?,
        subject: identifier(field(record, "subject"))?,
        client_id: identifier(field(record, "clientId"))?,
        organization_audience: identifier(field(record, "organizationAudience"))?,
        state,
        policy_digest: digest(field(record, "policyDigest"))?,
    })
}

pub fn parse_grant_verification_result(value: &Value) -> ProtocolResult<GrantVerificationResult> {
    let record = capture_record(value).or_fail(CODE)?;
    let state = record.get("state").and_then(Value::as_str);
    let keys: &[&str] = match state {
        Some("authorized") => &["state", "ref"],
        Some("denied" | "unknown") => &["state", "code"],
        _ => return fail(CODE),
    };
    ensure(has_exact_keys(record, keys), CODE)?;
    let code = field(record, "code").as_str();
    match state {
        Some("authorized") => Ok(GrantVerificationResult::Authorized(parse_oaath_grant_ref(
            field(record, "ref"),
        )?)),
        Some("denied") => GrantVerificationDeniedCode::ALL
            .into_iter()
            .find(|denied| Some(denied.as_str()) == code)
            .map(GrantVerificationResult::Denied)
            .or_fail(CODE),
        _ => match code {
            Some("grant_unknown") => Ok(GrantVerificationResult::Unknown(
                GrantVerificationUnknownCode::Unknown,
            )),
            Some("grant_unreadable") => Ok(GrantVerificationResult::Unknown(
                GrantVerificationUnknownCode::Unreadable,
            )),
            _ => fail(CODE),
        },
    }
}

impl OaathGrantRef {
    pub fn to_json(&self) -> Value {
        json!({
            "version": GRANT_REFERENCE_VERSION,
            "grantId": self.grant_id,
            "revision": self.revision,
            "subject": self.subject,
            "clientId": self.client_id,
            "organizationAudience": self.organization_audience,
            "state": self.state.as_str(),
            "policyDigest": self.policy_digest,
        })
    }
}

impl VerifyGrantRevisionInput {
    pub fn to_json(&self) -> Value {
        json!({
            "grantId": self.grant_id,
            "revision": self.revision,
            "subject": self.subject,
            "clientId": self.client_id,
            "organizationAudience": self.organization_audience,
            "requiredCallsDigest": self.required_calls_digest,
        })
    }
}

impl GrantVerificationResult {
    pub fn to_json(&self) -> Value {
        match self {
            Self::Authorized(reference) => {
                json!({"state": "authorized", "ref": reference.to_json()})
            }
            Self::Denied(code) => json!({"state": "denied", "code": code.as_str()}),
            Self::Unknown(code) => json!({"state": "unknown", "code": code.as_str()}),
        }
    }
}
