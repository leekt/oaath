//! Workspace account context and the service bootstrap document
//! (`service-bootstrap.ts`).

use std::collections::HashSet;

use alloy_primitives::U256;
use serde_json::{Map, Value, json};

use crate::capture::{
    bounded_text, capture_dense_array, capture_record, exact_record, field, has_exact_keys,
    is_canonical_decimal, loose_safe_integer, lower_address, lower_hash,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure, fail};
use crate::identity::{KernelAccountProfile, OwnerCredentialProfile, capture_kernel_account};
use crate::ids::canonical_identifier;
use crate::web_url::canonical_https_url;

pub const SERVICE_BOOTSTRAP_VERSION: &str = "oaath.service-bootstrap/v4";
pub const WORKSPACE_ACCOUNT_CONTEXT_VERSION: &str = "oaath.workspace-account-context/v1";

const MAX_REDIRECT_URIS: usize = 8;
const MAX_CHAINS: usize = 32;
const MAX_NAME_LENGTH: usize = 256;
const MAX_HANDLE_LENGTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceKind {
    Personal,
    Team,
}

impl WorkspaceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Team => "team",
        }
    }
}

/// A selected logical account in one personal or team workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceAccountContext {
    pub workspace_id: String,
    pub workspace_kind: WorkspaceKind,
    pub account_id: String,
}

impl WorkspaceAccountContext {
    pub fn to_json(&self) -> Value {
        json!({
            "version": WORKSPACE_ACCOUNT_CONTEXT_VERSION,
            "workspaceId": self.workspace_id,
            "workspaceKind": self.workspace_kind.as_str(),
            "accountId": self.account_id,
        })
    }
}

pub(crate) fn capture_workspace_account_context(
    value: &Value,
    code: ErrorCode,
) -> ProtocolResult<WorkspaceAccountContext> {
    let record = exact_record(
        value,
        &["version", "workspaceId", "workspaceKind", "accountId"],
    )
    .or_fail(code)?;
    ensure(
        field(record, "version") == WORKSPACE_ACCOUNT_CONTEXT_VERSION,
        code,
    )?;
    let workspace_kind = match field(record, "workspaceKind").as_str() {
        Some("personal") => WorkspaceKind::Personal,
        Some("team") => WorkspaceKind::Team,
        _ => return fail(code),
    };
    Ok(WorkspaceAccountContext {
        workspace_id: canonical_identifier(field(record, "workspaceId"))
            .or_fail(code)?
            .to_owned(),
        workspace_kind,
        account_id: canonical_identifier(field(record, "accountId"))
            .or_fail(code)?
            .to_owned(),
    })
}

pub fn parse_workspace_account_context(value: &Value) -> ProtocolResult<WorkspaceAccountContext> {
    capture_workspace_account_context(value, ErrorCode::ServiceBootstrapInvalid)
}

/// Logical account and its deployment-owned owner-validator binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub account: KernelAccountProfile,
    /// Required exactly for an ECDSA owner credential.
    pub owner_validator: Option<String>,
}

pub fn capture_service_account(
    account: &Value,
    validator: &Value,
    code: ErrorCode,
) -> ProtocolResult<ServiceAccount> {
    let account = capture_kernel_account(account, code)?;
    let owner_validator = if validator.is_null() {
        None
    } else {
        Some(lower_address(validator).or_fail(code)?.to_owned())
    };
    ensure(
        matches!(
            account.owner_credential(),
            OwnerCredentialProfile::Ecdsa { .. }
        ) == owner_validator.is_some(),
        code,
    )?;
    Ok(ServiceAccount {
        account,
        owner_validator,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBootstrapApplication {
    pub application_id: String,
    pub application_name: String,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBootstrapFeePayer {
    pub address: String,
    pub balance: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBootstrapChain {
    /// Optional enable-verification gas floor, a decimal below 2^120.
    pub enable_verification_gas_floor: Option<String>,
    pub chain_id: u64,
    pub usage: bool,
    pub fee_payer: Option<ServiceBootstrapFeePayer>,
    pub paymaster_service_provider_id: Option<String>,
    pub static_paymaster_configuration_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSignerMode {
    Frontend,
    ApplicationBackend,
    OaathHosted,
}

impl SessionSignerMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frontend => "frontend",
            Self::ApplicationBackend => "application_backend",
            Self::OaathHosted => "oaath_hosted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBootstrapSessionSigner {
    pub mode: SessionSignerMode,
    /// `None` exactly for frontend custody.
    pub provider_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBootstrap {
    pub context: WorkspaceAccountContext,
    pub application: ServiceBootstrapApplication,
    pub user_handle: String,
    pub account: KernelAccountProfile,
    pub owner_validator: Option<String>,
    pub chains: Vec<ServiceBootstrapChain>,
    pub session_signer: ServiceBootstrapSessionSigner,
}

fn capture_chain(value: &Value, code: ErrorCode) -> ProtocolResult<ServiceBootstrapChain> {
    let record = capture_record(value).or_fail(code)?;
    let has_gas = record.contains_key("gas");
    let mut keys = vec![
        "chainId",
        "usage",
        "feePayer",
        "paymasterService",
        "staticPaymasterConfigurationHash",
    ];
    if has_gas {
        keys.push("gas");
    }
    ensure(has_exact_keys(record, &keys), code)?;
    let enable_verification_gas_floor = if has_gas {
        let policy =
            exact_record(field(record, "gas"), &["enableVerificationGasFloor"]).or_fail(code)?;
        let floor = field(policy, "enableVerificationGasFloor")
            .as_str()
            .filter(|floor| {
                is_canonical_decimal(floor, 37)
                    && U256::from_str_radix(floor, 10)
                        .is_ok_and(|value| value < U256::from(1) << 120)
            });
        Some(floor.or_fail(code)?.to_owned())
    } else {
        None
    };
    let chain_id = loose_safe_integer(field(record, "chainId"))
        .filter(|id| *id >= 1)
        .or_fail(code)?;
    let usage = field(record, "usage").as_bool().or_fail(code)?;
    let fee_payer = match field(record, "feePayer") {
        Value::Null => None,
        payer => {
            let payer = exact_record(payer, &["address", "balance"]).or_fail(code)?;
            let balance = field(payer, "balance")
                .as_str()
                .filter(|text| is_canonical_decimal(text, 78));
            Some(ServiceBootstrapFeePayer {
                address: lower_address(field(payer, "address"))
                    .or_fail(code)?
                    .to_owned(),
                balance: balance.or_fail(code)?.to_owned(),
            })
        }
    };
    let paymaster_service_provider_id = match field(record, "paymasterService") {
        Value::Null => None,
        service => {
            let service = exact_record(service, &["providerId"]).or_fail(code)?;
            Some(
                bounded_text(field(service, "providerId"), MAX_NAME_LENGTH)
                    .or_fail(code)?
                    .to_owned(),
            )
        }
    };
    let static_paymaster_configuration_hash =
        match field(record, "staticPaymasterConfigurationHash") {
            Value::Null => None,
            hash => Some(lower_hash(hash).or_fail(code)?.to_owned()),
        };
    Ok(ServiceBootstrapChain {
        enable_verification_gas_floor,
        chain_id: chain_id as u64,
        usage,
        fee_payer,
        paymaster_service_provider_id,
        static_paymaster_configuration_hash,
    })
}

fn capture_session_signer(
    value: &Value,
    code: ErrorCode,
) -> ProtocolResult<ServiceBootstrapSessionSigner> {
    let record = exact_record(value, &["mode", "providerId"]).or_fail(code)?;
    let mode = match field(record, "mode").as_str() {
        Some("frontend") => SessionSignerMode::Frontend,
        Some("application_backend") => SessionSignerMode::ApplicationBackend,
        Some("oaath_hosted") => SessionSignerMode::OaathHosted,
        _ => return fail(code),
    };
    let provider_id = field(record, "providerId");
    if mode == SessionSignerMode::Frontend {
        ensure(provider_id.is_null(), code)?;
        return Ok(ServiceBootstrapSessionSigner {
            mode,
            provider_id: None,
        });
    }
    Ok(ServiceBootstrapSessionSigner {
        mode,
        provider_id: Some(
            bounded_text(provider_id, MAX_NAME_LENGTH)
                .or_fail(code)?
                .to_owned(),
        ),
    })
}

pub fn parse_service_bootstrap(value: &Value) -> ProtocolResult<ServiceBootstrap> {
    let code = ErrorCode::ServiceBootstrapInvalid;
    let record = exact_record(
        value,
        &[
            "version",
            "context",
            "application",
            "userHandle",
            "account",
            "ownerValidator",
            "chains",
            "sessionSigner",
        ],
    )
    .or_fail(code)?;
    ensure(field(record, "version") == SERVICE_BOOTSTRAP_VERSION, code)?;
    let application = exact_record(
        field(record, "application"),
        &[
            "applicationId",
            "applicationName",
            "clientId",
            "redirectUris",
        ],
    )
    .or_fail(code)?;
    let redirect_entries = capture_dense_array(field(application, "redirectUris")).or_fail(code)?;
    ensure(
        (1..=MAX_REDIRECT_URIS).contains(&redirect_entries.len()),
        code,
    )?;
    let chain_entries = capture_dense_array(field(record, "chains")).or_fail(code)?;
    ensure((1..=MAX_CHAINS).contains(&chain_entries.len()), code)?;
    let mut chain_ids = HashSet::new();
    let mut chains = Vec::with_capacity(chain_entries.len());
    for entry in chain_entries {
        let chain = capture_chain(entry, code)?;
        ensure(chain_ids.insert(chain.chain_id), code)?;
        chains.push(chain);
    }
    let ServiceAccount {
        account,
        owner_validator,
    } = capture_service_account(
        field(record, "account"),
        field(record, "ownerValidator"),
        code,
    )?;
    let redirect_uris = redirect_entries
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(|uri| canonical_https_url(uri))
                .map(str::to_owned)
                .or_fail(code)
        })
        .collect::<ProtocolResult<Vec<_>>>()?;
    Ok(ServiceBootstrap {
        context: capture_workspace_account_context(field(record, "context"), code)?,
        application: ServiceBootstrapApplication {
            application_id: canonical_identifier(field(application, "applicationId"))
                .or_fail(code)?
                .to_owned(),
            application_name: bounded_text(field(application, "applicationName"), MAX_NAME_LENGTH)
                .or_fail(code)?
                .to_owned(),
            client_id: canonical_identifier(field(application, "clientId"))
                .or_fail(code)?
                .to_owned(),
            redirect_uris,
        },
        user_handle: bounded_text(field(record, "userHandle"), MAX_HANDLE_LENGTH)
            .or_fail(code)?
            .to_owned(),
        account,
        owner_validator,
        chains,
        session_signer: capture_session_signer(field(record, "sessionSigner"), code)?,
    })
}

impl ServiceBootstrapChain {
    pub fn to_json(&self) -> Value {
        let mut chain = Map::new();
        chain.insert("chainId".into(), json!(self.chain_id));
        chain.insert("usage".into(), json!(self.usage));
        if let Some(floor) = &self.enable_verification_gas_floor {
            chain.insert("gas".into(), json!({"enableVerificationGasFloor": floor}));
        }
        chain.insert(
            "feePayer".into(),
            self.fee_payer.as_ref().map_or(
                Value::Null,
                |payer| json!({"address": payer.address, "balance": payer.balance}),
            ),
        );
        chain.insert(
            "paymasterService".into(),
            self.paymaster_service_provider_id
                .as_ref()
                .map_or(Value::Null, |provider| json!({"providerId": provider})),
        );
        chain.insert(
            "staticPaymasterConfigurationHash".into(),
            json!(self.static_paymaster_configuration_hash),
        );
        Value::Object(chain)
    }
}

impl ServiceBootstrap {
    pub fn to_json(&self) -> Value {
        json!({
            "version": SERVICE_BOOTSTRAP_VERSION,
            "context": self.context.to_json(),
            "application": {
                "applicationId": self.application.application_id,
                "applicationName": self.application.application_name,
                "clientId": self.application.client_id,
                "redirectUris": self.application.redirect_uris,
            },
            "userHandle": self.user_handle,
            "account": self.account.to_json(),
            "ownerValidator": self.owner_validator,
            "chains": self.chains.iter().map(ServiceBootstrapChain::to_json).collect::<Vec<_>>(),
            "sessionSigner": {
                "mode": self.session_signer.mode.as_str(),
                "providerId": self.session_signer.provider_id,
            },
        })
    }
}
