//! URL-only bootstrap surface: one authenticated, versioned service document.
//!
//! The deployment resolves each caller's workspace and account; the relay adds
//! the authenticated client bindings and the configured chain descriptors; the
//! protocol owns the document's exact shape.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use oaath_protocol::service_bootstrap::{SERVICE_BOOTSTRAP_VERSION, parse_service_bootstrap};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::authentication::RelayCaller;
use crate::error::{RelayErrorCode, RelayResult};
use crate::records::{MAX_TIMESTAMP, is_lowercase_hash};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapApplication {
    pub application_id: String,
    pub application_name: String,
}

/// Selection resolved from the deployment's membership and account records.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapSelection {
    pub application: BootstrapApplication,
    pub context: Value,
    pub account: Value,
    pub owner_validator: Option<String>,
    pub chain_ids: Vec<u64>,
}

/// Called for each authenticated bootstrap request.
#[async_trait]
pub trait RelayBootstrapResolver: Send + Sync {
    /// `Ok(None)` means the caller has no assigned account.
    async fn resolve(&self, caller: &RelayCaller) -> RelayResult<Option<BootstrapSelection>>;
}

/// DEV ONLY: one selection for every caller.
pub struct StaticBootstrapResolver(pub BootstrapSelection);

#[async_trait]
impl RelayBootstrapResolver for StaticBootstrapResolver {
    async fn resolve(&self, _caller: &RelayCaller) -> RelayResult<Option<BootstrapSelection>> {
        Ok(Some(self.0.clone()))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapFeePayer {
    pub address: String,
    pub balance: String,
}

/// The static facts one served chain advertises. The chain execution ports
/// behind them arrive in a later stage.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapChain {
    pub chain_id: u64,
    /// Decimal `enableVerificationGasFloor`, below 2^120, when configured.
    #[serde(default)]
    pub enable_verification_gas_floor: Option<String>,
    pub usage: bool,
    pub fee_payer: Option<BootstrapFeePayer>,
    pub static_paymaster_configuration_hash: Option<String>,
}

pub struct BootstrapConfiguration {
    pub resolver: Arc<dyn RelayBootstrapResolver>,
    pub chains: Vec<BootstrapChain>,
}

/// Construction-time capture: a malformed chain set is an internal failure.
pub fn capture_chains(chains: &[BootstrapChain]) -> RelayResult<()> {
    if chains.is_empty() {
        return Err(RelayErrorCode::Internal);
    }
    let mut seen = BTreeSet::new();
    for chain in chains {
        if chain.chain_id < 1 || chain.chain_id > MAX_TIMESTAMP || !seen.insert(chain.chain_id) {
            return Err(RelayErrorCode::Internal);
        }
        if let Some(hash) = &chain.static_paymaster_configuration_hash
            && !is_lowercase_hash(hash)
        {
            return Err(RelayErrorCode::Internal);
        }
        if let Some(floor) = &chain.enable_verification_gas_floor {
            let parsed: u128 = floor.parse().map_err(|_| RelayErrorCode::Internal)?;
            if parsed >= 1 << 120 || parsed.to_string() != *floor {
                return Err(RelayErrorCode::Internal);
            }
        }
    }
    Ok(())
}

/// Builds the candidate document and serves exactly what the protocol parses.
pub async fn serve_bootstrap(
    configuration: &BootstrapConfiguration,
    caller: &RelayCaller,
) -> RelayResult<Value> {
    let selection = configuration
        .resolver
        .resolve(caller)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    let mut chains = Vec::with_capacity(selection.chain_ids.len());
    for chain_id in &selection.chain_ids {
        let chain = configuration
            .chains
            .iter()
            .find(|chain| chain.chain_id == *chain_id)
            .ok_or(RelayErrorCode::Internal)?;
        let mut descriptor = serde_json::Map::new();
        descriptor.insert("chainId".into(), json!(chain.chain_id));
        if let Some(floor) = &chain.enable_verification_gas_floor {
            descriptor.insert("gas".into(), json!({ "enableVerificationGasFloor": floor }));
        }
        descriptor.insert("usage".into(), json!(chain.usage));
        descriptor.insert(
            "feePayer".into(),
            chain.fee_payer.as_ref().map_or(
                Value::Null,
                |payer| json!({ "address": payer.address, "balance": payer.balance }),
            ),
        );
        descriptor.insert("paymasterService".into(), Value::Null);
        descriptor.insert(
            "staticPaymasterConfigurationHash".into(),
            json!(chain.static_paymaster_configuration_hash),
        );
        chains.push(Value::Object(descriptor));
    }
    let candidate = json!({
        "version": SERVICE_BOOTSTRAP_VERSION,
        "application": {
            "applicationId": selection.application.application_id,
            "applicationName": selection.application.application_name,
            "clientId": caller.client_id,
            "redirectUris": caller.redirect_uris,
        },
        "userHandle": caller.subject,
        "context": selection.context,
        "account": selection.account,
        "ownerValidator": selection.owner_validator,
        "chains": chains,
        "sessionSigner": { "mode": "frontend", "providerId": null },
    });
    parse_service_bootstrap(&candidate)
        .map(|document| document.to_json())
        .map_err(|_| RelayErrorCode::Internal)
}
