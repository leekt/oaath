//! OAuth client and pushed-authorization-request records.
//!
//! A client is immutable once registered; its redirect URIs are fixed and
//! matched exactly. A PAR is immutable: it holds only the client's intent, and
//! its identifier becomes the authorization request id when the portal decides.

use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::error::{RelayErrorCode, RelayResult};
use crate::records::{
    bounded_str, bounded_text, canonical_identifier, exact_record, limits, timestamp,
};

pub const OAUTH_CLIENT_RECORD_VERSION: &str = "oaath.oauth-client-record/v1";
pub const OAUTH_PAR_RECORD_VERSION: &str = "oaath.oauth-par-record/v1";

pub const MAX_CLIENT_NAME: usize = 128;
pub const MAX_REDIRECT_URIS: usize = 8;
/// Bound for the opaque client `state` and OIDC `nonce`.
pub const MAX_STATE: usize = 512;

const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

/// An absolute https redirect URI, or http on `localhost`/`127.0.0.1` for
/// development, with no fragment or credentials.
pub fn redirect_uri_allowed(uri: &str) -> bool {
    if bounded_str(uri, limits::REDIRECT_URI, RelayErrorCode::RequestInvalid).is_err() {
        return false;
    }
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    let scheme_allowed = match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1")),
        _ => false,
    };
    scheme_allowed
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

fn version(value: Option<&Value>, expected: &str) -> RelayResult<()> {
    match value {
        Some(Value::String(text)) if text == expected => Ok(()),
        _ => Err(UNREADABLE),
    }
}

fn optional_text(value: Option<&Value>, maximum: usize) -> RelayResult<Option<String>> {
    match value {
        Some(Value::Null) => Ok(None),
        other => Ok(Some(bounded_text(other, maximum, UNREADABLE)?.to_owned())),
    }
}

/// One public (`token_endpoint_auth_method: none`) client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthClientRecord {
    pub version: &'static str,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: u64,
}

impl OAuthClientRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "clientId",
                "clientName",
                "redirectUris",
                "createdAt",
            ],
            UNREADABLE,
        )?;
        version(r.get("version"), OAUTH_CLIENT_RECORD_VERSION)?;
        let Some(Value::Array(uris)) = r.get("redirectUris") else {
            return Err(UNREADABLE);
        };
        let redirect_uris = uris
            .iter()
            .map(|uri| match uri.as_str() {
                Some(uri) if redirect_uri_allowed(uri) => Ok(uri.to_owned()),
                _ => Err(UNREADABLE),
            })
            .collect::<RelayResult<Vec<_>>>()?;
        if redirect_uris.is_empty() || redirect_uris.len() > MAX_REDIRECT_URIS {
            return Err(UNREADABLE);
        }
        Ok(Self {
            version: OAUTH_CLIENT_RECORD_VERSION,
            client_id: canonical_identifier(r.get("clientId"), UNREADABLE)?.to_owned(),
            client_name: bounded_text(r.get("clientName"), MAX_CLIENT_NAME, UNREADABLE)?.to_owned(),
            redirect_uris,
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
        })
    }
}

/// One pushed authorization request (RFC 9126), login only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParRecord {
    pub version: &'static str,
    /// Also the transaction id and the future authorization request id.
    pub par_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// PKCE S256 challenge; the verifier never reaches the relay before /token.
    pub code_challenge: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    /// Space-separated scope; always contains `openid`.
    pub scope: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl ParRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "parId",
                "clientId",
                "redirectUri",
                "codeChallenge",
                "state",
                "nonce",
                "scope",
                "createdAt",
                "expiresAt",
            ],
            UNREADABLE,
        )?;
        version(r.get("version"), OAUTH_PAR_RECORD_VERSION)?;
        let redirect_uri = bounded_text(r.get("redirectUri"), limits::REDIRECT_URI, UNREADABLE)?;
        if !redirect_uri_allowed(redirect_uri) {
            return Err(UNREADABLE);
        }
        Ok(Self {
            version: OAUTH_PAR_RECORD_VERSION,
            par_id: canonical_identifier(r.get("parId"), UNREADABLE)?.to_owned(),
            client_id: canonical_identifier(r.get("clientId"), UNREADABLE)?.to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            code_challenge: canonical_identifier(r.get("codeChallenge"), UNREADABLE)?.to_owned(),
            state: optional_text(r.get("state"), MAX_STATE)?,
            nonce: optional_text(r.get("nonce"), MAX_STATE)?,
            scope: bounded_text(r.get("scope"), MAX_STATE, UNREADABLE)?.to_owned(),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            expires_at: timestamp(r.get("expiresAt"), UNREADABLE)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::redirect_uri_allowed;

    #[test]
    fn allows_https_and_loopback_http_redirects_only() {
        for allowed in [
            "https://app.example/callback",
            "https://app.example/callback?mode=login",
            "http://localhost:5173/callback",
            "http://127.0.0.1/cb",
        ] {
            assert!(redirect_uri_allowed(allowed), "{allowed}");
        }
        for refused in [
            "http://app.example/callback",
            "https://app.example/callback#fragment",
            "https://user:pass@app.example/callback",
            "javascript:alert(1)",
            "app://callback",
            "/callback",
            "",
        ] {
            assert!(!redirect_uri_allowed(refused), "{refused}");
        }
    }
}
