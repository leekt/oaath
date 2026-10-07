//! Deployment-owned client/device authentication port and the optional limiter.
//!
//! The relay never parses credentials. It hands the request headers to the
//! deployment, which returns the authenticated bindings or nothing. `clientId`
//! and `subject` come only from here: wire input may never declare either.

use std::collections::HashMap;

use async_trait::async_trait;
use axum::http::HeaderMap;
use serde::Deserialize;

use crate::error::{RelayErrorCode, RelayResult};
use crate::records::{bounded_str, canonical_str, limits};

/// `client` is the requesting application; `owner` is the approving account owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayCallerRole {
    Client,
    Owner,
}

const MAX_REDIRECT_URIS: usize = 8;

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

/// Why the port did not authenticate. `Failed` is projected to
/// `relay_unauthenticated`; `Code` lets the port choose a relay code.
#[derive(Debug)]
pub enum AuthenticationFailure {
    Failed,
    Code(RelayErrorCode),
}

#[async_trait]
pub trait RelayAuthentication: Send + Sync {
    /// `Ok(None)` when the caller is not authenticated.
    async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<RelayCaller>, AuthenticationFailure>;
}

/// A port that breaks its own contract is an internal failure, not a 401.
fn capture_caller(caller: RelayCaller) -> RelayResult<RelayCaller> {
    let internal = RelayErrorCode::Internal;
    canonical_str(&caller.client_id, internal)?;
    canonical_str(&caller.subject, internal)?;
    if caller.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(internal);
    }
    for uri in &caller.redirect_uris {
        bounded_str(uri, limits::REDIRECT_URI, internal)?;
    }
    if let Some(audience) = &caller.organization_audience {
        canonical_str(audience, internal)?;
    }
    Ok(caller)
}

pub async fn authenticate_caller(
    authentication: &dyn RelayAuthentication,
    headers: &HeaderMap,
    roles: &[RelayCallerRole],
) -> RelayResult<RelayCaller> {
    let caller = match authentication.authenticate(headers).await {
        Ok(Some(caller)) => capture_caller(caller)?,
        Ok(None) | Err(AuthenticationFailure::Failed) => {
            return Err(RelayErrorCode::Unauthenticated);
        }
        Err(AuthenticationFailure::Code(code)) => return Err(code),
    };
    if !roles.contains(&caller.role) {
        return Err(RelayErrorCode::Forbidden);
    }
    Ok(caller)
}

/// The bearer token from an `authorization: Bearer <token>` header, if any.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// DEV ONLY: static bearer tokens mapped to callers from a local config file.
/// A later stage replaces this with portal sessions; never deploy it.
pub struct DevTokenAuthentication {
    callers: HashMap<String, RelayCaller>,
}

impl DevTokenAuthentication {
    pub fn new(callers: HashMap<String, RelayCaller>) -> Self {
        Self { callers }
    }
}

#[async_trait]
impl RelayAuthentication for DevTokenAuthentication {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<RelayCaller>, AuthenticationFailure> {
        Ok(bearer_token(headers).and_then(|token| self.callers.get(token).cloned()))
    }
}

/// Optional deployment-owned limiter. There is no default limiter: an unset
/// port means no limiting. A limiter that fails is treated as limited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitVerdict {
    Allowed,
    Limited,
}

#[derive(Debug)]
pub struct RateLimiterUnavailable;

#[async_trait]
pub trait RelayRateLimiter: Send + Sync {
    /// `route` is a stable route name, never a credential-bearing URL.
    async fn check(
        &self,
        route: &str,
        client_id: &str,
    ) -> Result<RateLimitVerdict, RateLimiterUnavailable>;
}

pub async fn assert_within_rate_limit(
    limiter: Option<&dyn RelayRateLimiter>,
    route: &str,
    client_id: &str,
) -> RelayResult<()> {
    let Some(limiter) = limiter else {
        return Ok(());
    };
    match limiter.check(route, client_id).await {
        Ok(RateLimitVerdict::Allowed) => Ok(()),
        _ => Err(RelayErrorCode::RateLimited),
    }
}
