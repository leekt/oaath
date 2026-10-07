//! DEV ONLY local relay configuration (`OAATH_CONFIG`).
//!
//! It wires the static-token authentication, one owner route, an optional
//! static bootstrap selection. A later stage
//! replaces authentication with portal sessions. The file holds bearer
//! tokens: keep it out of logs and version control.

use std::collections::HashMap;
use std::sync::Arc;

use oaath_protocol::capture::parse_json;
use serde::Deserialize;

use crate::RelayOptions;
use crate::authentication::{DevTokenAuthentication, NoAuthentication, RelayCaller};
use crate::authorization::request::{NoOwnerRouting, StaticOwnerRouting};
use crate::bootstrap::{
    BootstrapChain, BootstrapConfiguration, BootstrapSelection, StaticBootstrapResolver,
};
use crate::clock::RelayClock;
use crate::kms::RelayKms;
use crate::oauth::OAuthConfiguration;
use crate::records::AuthorizationOwnerRoute;
use crate::store::RelayStore;

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

/// The binary's composition. Without a DEV config nobody authenticates: the
/// caller-authenticated relay routes answer `relay_unauthenticated`, no owner
/// is routed, and no bootstrap is served, while `/portal/*`, `/oauth/*`, and
/// discovery need no caller.
pub fn compose(
    store: Arc<dyn RelayStore>,
    kms: Arc<dyn RelayKms>,
    clock: Arc<dyn RelayClock>,
    oauth: Option<OAuthConfiguration>,
    config: Option<DevConfig>,
) -> RelayOptions {
    let mut options = RelayOptions {
        store,
        authentication: Arc::new(NoAuthentication),
        owner_routing: Arc::new(NoOwnerRouting),
        kms,
        clock,
        rate_limit: None,
        request_ttl_ms: None,
        code_ttl_ms: None,
        max_body_bytes: None,
        bootstrap: None,
        oauth,
    };
    let Some(config) = config else {
        tracing::info!("authentication: none; caller-authenticated relay routes refuse");
        return options;
    };
    tracing::warn!("authentication: DEV static bearer tokens; never deploy this configuration");
    options.authentication = Arc::new(DevTokenAuthentication::new(config.tokens));
    options.owner_routing = Arc::new(StaticOwnerRouting(config.owner_route));
    options.request_ttl_ms = config.request_ttl_ms;
    options.code_ttl_ms = config.code_ttl_ms;
    options.max_body_bytes = config.max_body_bytes;
    options.bootstrap = config.bootstrap.map(|bootstrap| BootstrapConfiguration {
        resolver: Arc::new(StaticBootstrapResolver(bootstrap.selection)),
        chains: bootstrap.chains,
    });
    options
}
