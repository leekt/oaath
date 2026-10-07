//! DEV ONLY local relay configuration (`OAATH_CONFIG`).
//!
//! It wires the static-token authentication, one owner route, an optional
//! static bootstrap selection. A later stage
//! replaces authentication with portal sessions. The file holds bearer
//! tokens: keep it out of logs and version control.

use std::collections::HashMap;

use oaath_protocol::capture::parse_json;
use serde::Deserialize;

use crate::authentication::RelayCaller;
use crate::bootstrap::{BootstrapChain, BootstrapSelection};
use crate::records::AuthorizationOwnerRoute;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevConfig {
    /// Bearer token -> authenticated caller.
    pub tokens: HashMap<String, RelayCaller>,
    pub owner_route: AuthorizationOwnerRoute,
    #[serde(default)]
    pub bootstrap: Option<DevBootstrap>,
    #[serde(default)]
    pub request_ttl_ms: Option<u64>,
    #[serde(default)]
    pub code_ttl_ms: Option<u64>,
    #[serde(default)]
    pub max_body_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevBootstrap {
    pub selection: BootstrapSelection,
    pub chains: Vec<BootstrapChain>,
}

impl DevConfig {
    /// Parse failures never echo the file, which holds bearer tokens.
    /// The bootstrap selection reaches the protocol parser, so the file is
    /// read with `-0` preserved.
    pub fn parse(text: &str) -> Result<Self, String> {
        let value = parse_json(text).map_err(|error| {
            format!(
                "config is not JSON at line {} column {}",
                error.line(),
                error.column()
            )
        })?;
        serde_json::from_value(value).map_err(|_| "config does not match its schema".to_owned())
    }
}
