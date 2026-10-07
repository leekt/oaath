//! Closed relay failure codes and their stable HTTP projection.
//!
//! Machine decisions and wire responses use these codes only. No diagnostic
//! text ever reaches a response body.

use serde::Serialize;

/// The closed relay failure set, identical to `packages/server/src/relay/errors.ts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, thiserror::Error)]
pub enum RelayErrorCode {
    /// Wire input is missing, malformed, oversized, or contains unknown fields.
    #[error("relay_request_invalid")]
    #[serde(rename = "relay_request_invalid")]
    RequestInvalid,
    /// The deployment authentication port did not authenticate the caller.
    #[error("relay_unauthenticated")]
    #[serde(rename = "relay_unauthenticated")]
    Unauthenticated,
    /// Authenticated caller may not act in the required role.
    #[error("relay_forbidden")]
    #[serde(rename = "relay_forbidden")]
    Forbidden,
    /// Route, or a record the caller is entitled to see, does not exist.
    #[error("relay_not_found")]
    #[serde(rename = "relay_not_found")]
    NotFound,
    /// Route exists with a different method.
    #[error("relay_method_not_allowed")]
    #[serde(rename = "relay_method_not_allowed")]
    MethodNotAllowed,
    /// The authorization request or code is past its injected-clock expiry.
    #[error("relay_expired")]
    #[serde(rename = "relay_expired")]
    Expired,
    /// The authorization request already reached a terminal decision.
    #[error("relay_already_decided")]
    #[serde(rename = "relay_already_decided")]
    AlreadyDecided,
    /// The one-time authorization code was already consumed.
    #[error("relay_code_already_consumed")]
    #[serde(rename = "relay_code_already_consumed")]
    CodeAlreadyConsumed,
    /// The one-time encrypted artifact was already claimed.
    #[error("relay_artifact_already_claimed")]
    #[serde(rename = "relay_artifact_already_claimed")]
    ArtifactAlreadyClaimed,
    /// Authorization code redemption failed, for every reason it can fail, so
    /// the endpoint never confirms that a guessed code was correct. A code
    /// that existed is burned.
    #[error("relay_code_invalid")]
    #[serde(rename = "relay_code_invalid")]
    CodeInvalid,
    /// The optional deployment limiter rejected the call.
    #[error("relay_rate_limited")]
    #[serde(rename = "relay_rate_limited")]
    RateLimited,
    /// A durable record could not be read as the current schema version.
    #[error("relay_record_unreadable")]
    #[serde(rename = "relay_record_unreadable")]
    RecordUnreadable,
    /// The KMS port was unavailable or returned an unusable result.
    #[error("relay_kms_unavailable")]
    #[serde(rename = "relay_kms_unavailable")]
    KmsUnavailable,
    /// The store failed before any state change could have been committed.
    #[error("relay_store_unavailable")]
    #[serde(rename = "relay_store_unavailable")]
    StoreUnavailable,
    /// The store could not prove whether a transition committed. Never retried.
    #[error("relay_state_ambiguous")]
    #[serde(rename = "relay_state_ambiguous")]
    StateAmbiguous,
    /// EXPERIMENTAL PREVIEW: the APNs payload exceeded Apple's limit.
    #[error("relay_apns_payload_too_large")]
    #[serde(rename = "relay_apns_payload_too_large")]
    ApnsPayloadTooLarge,
    /// EXPERIMENTAL PREVIEW: the injected Apple credential is unusable.
    #[error("relay_apns_credentials_invalid")]
    #[serde(rename = "relay_apns_credentials_invalid")]
    ApnsCredentialsInvalid,
    /// A deployment-injected chain execution port failed or answered unusably.
    #[error("relay_chain_unavailable")]
    #[serde(rename = "relay_chain_unavailable")]
    ChainUnavailable,
    /// The Grant's capability is durably invalidated.
    #[error("relay_capability_invalidated")]
    #[serde(rename = "relay_capability_invalidated")]
    CapabilityInvalidated,
    /// An invariant the relay owns was violated.
    #[error("relay_internal")]
    #[serde(rename = "relay_internal")]
    Internal,
}

impl RelayErrorCode {
    /// Status projection. `relay_state_ambiguous` is deliberately 500 and not
    /// 503, because 503 invites the retry that an ambiguous commit forbids.
    pub fn status(self) -> u16 {
        match self {
            Self::RequestInvalid => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::Expired => 410,
            Self::AlreadyDecided => 409,
            Self::CodeAlreadyConsumed => 409,
            Self::ArtifactAlreadyClaimed => 409,
            Self::CodeInvalid => 400,
            Self::RateLimited => 429,
            Self::RecordUnreadable => 500,
            Self::KmsUnavailable => 503,
            Self::StoreUnavailable => 503,
            Self::StateAmbiguous => 500,
            Self::ApnsPayloadTooLarge => 500,
            Self::ApnsCredentialsInvalid => 500,
            Self::ChainUnavailable => 503,
            Self::CapabilityInvalidated => 409,
            Self::Internal => 500,
        }
    }
}

pub type RelayResult<T> = Result<T, RelayErrorCode>;
