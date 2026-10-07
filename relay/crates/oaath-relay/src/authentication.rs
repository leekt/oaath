//! The caller an internal transition acts for: an OAuth client redeeming its
//! own code or artifact, or invalidating its own grant. `clientId` comes from
//! the authenticated OAuth exchange, never from wire input naming it.

use axum::http::HeaderMap;
use serde::Deserialize;

/// `client` is the requesting application; `owner` is the approving account owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayCallerRole {
    Client,
    Owner,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayCaller {
    pub role: RelayCallerRole,
    pub client_id: String,
    /// Pairwise user/device subject.
    pub subject: String,
    /// Redirect URIs the deployment registered for this client. `owner`
    /// callers pass an empty list.
    pub redirect_uris: Vec<String>,
    /// The organization/audience the deployment binds this caller to, or none.
    #[serde(default)]
    pub organization_audience: Option<String>,
}

/// The bearer token from an `authorization: Bearer <token>` header, if any.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
