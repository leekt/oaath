//! The relay's one configured ERC-4337 bundler, for submitting root-signed
//! revocations.
//!
//! ```text
//! OAATH_BUNDLER_421614   one bundler JSON-RPC URL for chain 421614; never logged
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
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// One request, one attempt.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, BundlerFailure> {
        if !ALLOWED.contains(&method) {
            return Err(BundlerFailure::Unavailable);
        }
        let response = self
            .client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
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
