//! `oaath-relay`: the relay HTTP server.
//!
//! ```text
//! OAATH_LISTEN        listen address, default 127.0.0.1:8787
//! OAATH_POSTGRES_URL  PostgreSQL store; the memory store when unset
//! OAATH_KMS_KEY       64 hex characters: the AES-256-GCM artifact key
//! OAATH_CONFIG        path to the DEV ONLY JSON config (tokens, owner route,
//!                     bootstrap selection)
//! OAATH_ISSUER        OAuth/OIDC issuer URL (no trailing slash); enables
//!                     /oauth/*, discovery, and the portal transaction routes
//! OAATH_ID_TOKEN_KEY  path to the ES256 (P-256) PKCS#8 PEM id_token key
//! OAATH_ID_TOKEN_KID  the key's `kid`
//! --create-schema     create the current PostgreSQL schema first; fails if
//!                     any object already exists
//! ```
//!
//! Logs never include codes, artifacts, verifiers, tokens, keys, or bodies.

use std::process::ExitCode;
use std::sync::Arc;

use oaath_relay::authentication::DevTokenAuthentication;
use oaath_relay::authorization::request::StaticOwnerRouting;
use oaath_relay::bootstrap::{BootstrapConfiguration, StaticBootstrapResolver};
use oaath_relay::clock::SystemClock;
use oaath_relay::config::DevConfig;
use oaath_relay::kms::AesGcmKms;
use oaath_relay::oauth::OAuthConfiguration;
use oaath_relay::oauth::id_token::IdTokenKey;
use oaath_relay::store::RelayStore;
use oaath_relay::store::memory::MemoryRelayStore;
use oaath_relay::store::postgres::{
    PostgresRelayStore, RELAY_POSTGRES_SCHEMA_VERSION, create_relay_schema,
};
use oaath_relay::{Relay, RelayOptions};
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let mut create_schema = false;
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--create-schema" => create_schema = true,
            _ => return Err("unknown argument; supported: --create-schema".into()),
        }
    }
    let listen = std::env::var("OAATH_LISTEN").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let kms = std::env::var("OAATH_KMS_KEY")
        .ok()
        .and_then(|key| AesGcmKms::from_hex(&key))
        .ok_or("OAATH_KMS_KEY must be 64 hex characters")?;
    let config_path = std::env::var("OAATH_CONFIG").map_err(|_| "OAATH_CONFIG is required")?;
    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|_| "OAATH_CONFIG could not be read".to_owned())?;
    let config = DevConfig::parse(&config_text)?;

    let store: Arc<dyn RelayStore> = match std::env::var("OAATH_POSTGRES_URL") {
        Ok(url) if !url.is_empty() => {
            let pool = PgPoolOptions::new()
                .connect(&url)
                .await
                .map_err(|_| "PostgreSQL is unreachable")?;
            if create_schema {
                create_relay_schema(&pool)
                    .await
                    .map_err(|_| "schema creation failed; it is not a migration")?;
                tracing::info!(version = RELAY_POSTGRES_SCHEMA_VERSION, "schema created");
            }
            tracing::info!(schema = RELAY_POSTGRES_SCHEMA_VERSION, "store: PostgreSQL");
            Arc::new(PostgresRelayStore::owning(pool))
        }
        _ => {
            if create_schema {
                return Err("--create-schema requires OAATH_POSTGRES_URL".into());
            }
            tracing::info!("store: memory (set OAATH_POSTGRES_URL for PostgreSQL)");
            Arc::new(MemoryRelayStore::new())
        }
    };

    let oauth = match std::env::var("OAATH_ISSUER") {
        Ok(issuer) if !issuer.is_empty() => Some(oauth_configuration(issuer)?),
        _ => None,
    };

    tracing::warn!("authentication: DEV static bearer tokens; never deploy this configuration");
    let relay = Relay::new(RelayOptions {
        store: store.clone(),
        authentication: Arc::new(DevTokenAuthentication::new(config.tokens)),
        owner_routing: Arc::new(StaticOwnerRouting(config.owner_route)),
        kms: Arc::new(kms),
        clock: Arc::new(SystemClock),
        rate_limit: None,
        request_ttl_ms: config.request_ttl_ms,
        code_ttl_ms: config.code_ttl_ms,
        max_body_bytes: config.max_body_bytes,
        bootstrap: config.bootstrap.map(|bootstrap| BootstrapConfiguration {
            resolver: Arc::new(StaticBootstrapResolver(bootstrap.selection)),
            chains: bootstrap.chains,
        }),
        oauth,
    })
    .map_err(|code| format!("relay configuration is invalid ({code})"))?;

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|_| format!("cannot listen on {listen}"))?;
    let address = listener
        .local_addr()
        .map_err(|_| "listener has no address")?;
    tracing::info!(%address, "OAAth relay listening");
    axum::serve(listener, Arc::new(relay).router())
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|_| "server failed")?;
    let _ = store.close().await;
    tracing::info!("OAAth relay stopped");
    Ok(())
}

/// The issuer and its id_token key. Errors never echo the key.
fn oauth_configuration(issuer: String) -> Result<OAuthConfiguration, String> {
    let parsed = url::Url::parse(&issuer).map_err(|_| "OAATH_ISSUER must be a URL")?;
    if !matches!(parsed.scheme(), "https" | "http") || issuer.ends_with('/') {
        return Err("OAATH_ISSUER must be an http(s) URL without a trailing slash".into());
    }
    let path = std::env::var("OAATH_ID_TOKEN_KEY").map_err(|_| "OAATH_ID_TOKEN_KEY is required")?;
    let kid = std::env::var("OAATH_ID_TOKEN_KID").map_err(|_| "OAATH_ID_TOKEN_KID is required")?;
    let pem = std::fs::read_to_string(path).map_err(|_| "OAATH_ID_TOKEN_KEY could not be read")?;
    let key = IdTokenKey::from_pkcs8_pem(&kid, &pem)
        .ok_or("OAATH_ID_TOKEN_KEY must be a P-256 PKCS#8 PEM key with a URL-safe kid")?;
    tracing::info!(%issuer, "oauth: enabled");
    Ok(OAuthConfiguration { issuer, key })
}

async fn shutdown() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {
            _ = interrupt => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = interrupt.await;
}
