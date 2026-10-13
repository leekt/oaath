//! The relay's one configured ERC-4337 bundler, for submitting root-signed
//! revocations.
//!
//! ```text
//! OAATH_BUNDLER_421614   one bundler JSON-RPC URL for chain 421614; never logged
//! OAATH_BUNDLER_API_KEY_421614   optional server-owned JSON-RPC apiKey credential
//! ```
//!
//! Explicit configuration only: without it nothing is estimated or submitted.
//! Each request is one attempt bounded by `TIMEOUT`, with no retry and no
//! fallback URL. The caller owns the per-operation request budget and records
//! every spend before the request leaves. A JSON-RPC error is the bundler's
//! answer (`Rejected`); a timeout, a transport failure or an unusable reply is
//! `Unavailable`, which never means "not accepted".

use std::time::Duration;

use serde_json::{Value, json};

pub const TIMEOUT: Duration = Duration::from_secs(10);
const ALLOWED: [&str; 4] = [
    "pimlico_getUserOperationGasPrice",
    "eth_estimateUserOperationGas",
    "eth_sendUserOperation",
    "eth_getUserOperationReceipt",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundlerFailure {
    /// The bundler answered with a JSON-RPC error.
    Rejected,
    /// No usable answer: timed out, unreachable, or malformed.
    Unavailable,
}

/// One configured bundler endpoint. Its URL is a credential: never printed.
pub struct Bundler {
    chain_id: u64,
    url: String,
    client: reqwest::Client,
    api_key: Option<String>,
}

impl std::fmt::Debug for Bundler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Bundler")
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl Bundler {
    pub fn new(chain_id: u64, url: &str) -> Option<Self> {
        Self::with_timeout(chain_id, url, TIMEOUT)
    }

    /// The same bundler with another per-request timeout (tests).
    pub fn with_timeout(chain_id: u64, url: &str, timeout: Duration) -> Option<Self> {
        let parsed = url::Url::parse(url).ok()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(Self {
            chain_id,
            url: url.to_owned(),
            client,
            api_key: None,
        })
    }

    /// Captures an optional server credential without exposing it in diagnostics.
    pub fn with_api_key(mut self, api_key: Option<&str>) -> Self {
        self.api_key = api_key
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .map(str::to_owned);
        self
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// One request, one attempt.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, BundlerFailure> {
        if !ALLOWED.contains(&method) {
            return Err(BundlerFailure::Unavailable);
        }
        let mut payload = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        if let Some(api_key) = &self.api_key {
            payload["apiKey"] = json!(api_key);
        }
        let response = self
            .client
            .post(&self.url)
            .json(&payload)
            .send()
            .await
            .map_err(|_| BundlerFailure::Unavailable)?;
        let body: Value = response
            .json()
            .await
            .map_err(|_| BundlerFailure::Unavailable)?;
        if body.get("error").is_some_and(Value::is_object) {
            return Err(BundlerFailure::Rejected);
        }
        body.get("result")
            .cloned()
            .ok_or(BundlerFailure::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, http::HeaderMap, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn server_credential_authenticates_every_bundler_method() {
        for api_key in [None, Some("test-server-key")] {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let app = Router::new().route(
                "/",
                post(move |headers: HeaderMap, Json(payload): Json<Value>| {
                    let observed = observed.clone();
                    async move {
                        observed.fetch_add(1, Ordering::SeqCst);
                        assert!(headers.get("authorization").is_none());
                        assert_eq!(payload.get("apiKey").and_then(Value::as_str), api_key);
                        Json(json!({"jsonrpc": "2.0", "id": 1, "result": "accepted"}))
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let bundler = Bundler::new(421614, &url).unwrap().with_api_key(api_key);
            for method in ALLOWED {
                assert_eq!(bundler.call(method, json!([])).await, Ok(json!("accepted")));
            }
            assert_eq!(calls.load(Ordering::SeqCst), ALLOWED.len());
            server.abort();
        }
    }

    #[tokio::test]
    async fn authenticated_requests_never_follow_redirects_or_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let app = Router::new().fallback(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { axum::response::Redirect::temporary("/redirected") }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let bundler = Bundler::new(421614, &url)
            .unwrap()
            .with_api_key(Some("test-server-key"));
        assert_eq!(
            bundler.call(ALLOWED[0], json!([])).await,
            Err(BundlerFailure::Unavailable)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[test]
    fn credential_is_omitted_from_debug_and_blank_keys_are_absent() {
        let bundler = Bundler::new(421614, "http://127.0.0.1:1")
            .unwrap()
            .with_api_key(Some("test-server-key"));
        assert!(!format!("{bundler:?}").contains("test-server-key"));
        assert!(
            Bundler::new(421614, "http://127.0.0.1:1")
                .unwrap()
                .with_api_key(Some(" "))
                .api_key
                .is_none()
        );
    }
}
