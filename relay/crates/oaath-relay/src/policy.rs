//! Policy templates: an account root's named, reusable GrantPolicy bodies.
//!
//! ```text
//! GET    /portal/accounts/{id}/policies                                       -> {policies: [...]}
//! POST   /portal/accounts/{id}/policies        {name, policy, lifetime_seconds} -> template
//! PUT    /portal/accounts/{id}/policies/{tid}  {name, policy, lifetime_seconds} -> template
//! DELETE /portal/accounts/{id}/policies/{tid}                                 -> {}
//! ```
//!
//! ```text
//! state and owner      template: created -> updated* -> deleted, by the
//!                      account's root only
//! persisted evidence   oaath_policy_template_v1; database configuration only
//! resource occupied?   nothing: a grant copies the compiled policy, so editing
//!                      or deleting a template never changes an issued grant
//! forbidden            a non-root caller; a body the SDK cannot compile into
//!                      reviewed Kernel packages (argument rules, an empty call
//!                      list, an out-of-range limit or lifetime)
//! ```
//!
//! A template is a protocol GrantPolicy without its validity window:
//!
//! ```text
//! policy  { calls: [{target, selector, valueLimit}],
//!           perChainOperationLimit: {count, intervalSeconds | null} }
//! ```
//!
//! A grant from it is valid from its request time for `lifetime_seconds`.

use oaath_protocol::grant_policy::{GrantPolicy, parse_grant_policy};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::authorization::challenge::random_identifier;
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::check_policy;
use crate::records::{bounded_text, canonical_identifier, exact_record, timestamp};
use crate::store::{RelayStore, RelayTransaction, settle};

pub const POLICY_TEMPLATE_RECORD_VERSION: &str = "oaath.policy-template-record/v1";
pub const MIN_LIFETIME_SECONDS: u64 = 60;
pub const MAX_LIFETIME_SECONDS: u64 = 366 * 86_400;
const MAX_NAME: usize = 64;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;
const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

/// The window-free policy body, checked to compile and kept canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplatePolicy(Value);

impl TemplatePolicy {
    /// Captures `{calls, perChainOperationLimit}`; `code` on any refusal.
    pub fn capture(
        value: &Value,
        lifetime_seconds: u64,
        code: RelayErrorCode,
    ) -> RelayResult<Self> {
        let record = exact_record(value, &["calls", "perChainOperationLimit"], code)?;
        let calls = record
            .get("calls")
            .and_then(Value::as_array)
            .ok_or(code)?
            .iter()
            .map(|call| {
                exact_record(call, &["target", "selector", "valueLimit"], code)?;
                Ok(json!({
                    "target": call["target"],
                    "selector": call["selector"],
                    "valueLimit": call["valueLimit"],
                    "argumentEquals": [],
                }))
            })
            .collect::<RelayResult<Vec<_>>>()?;
        let policy = parse_grant_policy(&json!({
            "version": "oaath.grant-policy/v1",
            "calls": calls,
            "validAfter": 0,
            "validUntil": lifetime_seconds,
            "perChainOperationLimit": record["perChainOperationLimit"],
        }))
        .map_err(|_| code)?;
        check_policy(&policy).map_err(|_| code)?;
        Ok(Self(Self::body(&policy)))
    }

    fn body(policy: &GrantPolicy) -> Value {
        let mut full = policy.to_json();
        let calls: Vec<Value> = full["calls"]
            .as_array_mut()
            .map(|calls| {
                calls
                    .iter_mut()
                    .map(|call| {
                        if let Some(call) = call.as_object_mut() {
                            call.shift_remove("argumentEquals");
                        }
                        call.clone()
                    })
                    .collect()
            })
            .unwrap_or_default();
        json!({ "calls": calls, "perChainOperationLimit": full["perChainOperationLimit"] })
    }

    pub fn to_json(&self) -> &Value {
        &self.0
    }

    /// The grant policy valid from `valid_after` for `lifetime_seconds`.
    pub fn grant_policy(
        &self,
        valid_after: u64,
        lifetime_seconds: u64,
    ) -> RelayResult<GrantPolicy> {
        let calls: Vec<Value> = self.0["calls"]
            .as_array()
            .ok_or(UNREADABLE)?
            .iter()
            .map(|call| {
                let mut call = call.clone();
                call["argumentEquals"] = json!([]);
                call
            })
            .collect();
        parse_grant_policy(&json!({
            "version": "oaath.grant-policy/v1",
            "calls": calls,
            "validAfter": valid_after,
            "validUntil": valid_after + lifetime_seconds,
            "perChainOperationLimit": self.0["perChainOperationLimit"],
        }))
        .map_err(|_| UNREADABLE)
    }
}

/// One account's policy template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTemplateRecord {
    pub version: &'static str,
    pub template_id: String,
    pub account_id: String,
    pub name: String,
    /// Canonical JSON of the window-free policy body.
    pub policy: String,
    pub lifetime_seconds: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

fn lifetime(value: Option<&Value>, code: RelayErrorCode) -> RelayResult<u64> {
    let seconds = timestamp(value, code)?;
    if !(MIN_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS).contains(&seconds) {
        return Err(code);
    }
    Ok(seconds)
}

impl PolicyTemplateRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "templateId",
                "accountId",
                "name",
                "policy",
                "lifetimeSeconds",
                "createdAt",
                "updatedAt",
            ],
            UNREADABLE,
        )?;
        if r.get("version").and_then(Value::as_str) != Some(POLICY_TEMPLATE_RECORD_VERSION) {
            return Err(UNREADABLE);
        }
        let record = Self {
            version: POLICY_TEMPLATE_RECORD_VERSION,
            template_id: canonical_identifier(r.get("templateId"), UNREADABLE)?.to_owned(),
            account_id: canonical_identifier(r.get("accountId"), UNREADABLE)?.to_owned(),
            name: bounded_text(r.get("name"), MAX_NAME, UNREADABLE)?.to_owned(),
            policy: r
                .get("policy")
                .and_then(Value::as_str)
                .ok_or(UNREADABLE)?
                .to_owned(),
            lifetime_seconds: lifetime(r.get("lifetimeSeconds"), UNREADABLE)?,
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            updated_at: timestamp(r.get("updatedAt"), UNREADABLE)?,
        };
        // The stored body must be the canonical, compilable form.
        let canonical = record.template_policy()?.to_json().to_string();
        if canonical != record.policy || record.updated_at < record.created_at {
            return Err(UNREADABLE);
        }
        Ok(record)
    }

    pub fn template_policy(&self) -> RelayResult<TemplatePolicy> {
        let value: Value = serde_json::from_str(&self.policy).map_err(|_| UNREADABLE)?;
        TemplatePolicy::capture(&value, self.lifetime_seconds, UNREADABLE)
    }
}

#[derive(Debug, Serialize)]
pub struct TemplateView {
    pub template_id: String,
    pub name: String,
    pub policy: Value,
    pub lifetime_seconds: u64,
    /// Unix seconds.
    pub created_at: u64,
    pub updated_at: u64,
}

impl TemplateView {
    fn of(record: &PolicyTemplateRecord) -> RelayResult<Self> {
        Ok(Self {
            template_id: record.template_id.clone(),
            name: record.name.clone(),
            policy: record.template_policy()?.to_json().clone(),
            lifetime_seconds: record.lifetime_seconds,
            created_at: record.created_at / 1_000,
            updated_at: record.updated_at / 1_000,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Templates {
    pub policies: Vec<TemplateView>,
}

/// The account, when `session` is its root.
pub async fn require_root(
    transaction: &mut dyn RelayTransaction,
    account_id: &str,
    session: &str,
) -> RelayResult<crate::registry::AccountRecord> {
    let account = transaction
        .lock_account(account_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    if account.root_signer_id != session {
        return Err(RelayErrorCode::Forbidden);
    }
    Ok(account)
}

/// The account's template, for its root.
pub async fn root_template(
    transaction: &mut dyn RelayTransaction,
    account_id: &str,
    template_id: &str,
    session: &str,
) -> RelayResult<PolicyTemplateRecord> {
    require_root(transaction, account_id, session).await?;
    transaction
        .lock_policy_template(template_id)
        .await?
        .filter(|template| template.account_id == account_id)
        .ok_or(RelayErrorCode::NotFound)
}

fn captured_body(body: &Map<String, Value>) -> RelayResult<(String, TemplatePolicy, u64)> {
    exact_record(
        &Value::Object(body.clone()),
        &["name", "policy", "lifetime_seconds"],
        INVALID,
    )?;
    let name = bounded_text(body.get("name"), MAX_NAME, INVALID)?.trim();
    if name.is_empty() {
        return Err(INVALID);
    }
    let lifetime_seconds = lifetime(body.get("lifetime_seconds"), INVALID)?;
    let policy = TemplatePolicy::capture(&body["policy"], lifetime_seconds, INVALID)?;
    Ok((name.to_owned(), policy, lifetime_seconds))
}

pub async fn list_templates(
    store: &dyn RelayStore,
    account_id: &str,
    session: &str,
) -> RelayResult<Templates> {
    let mut transaction = store.begin().await?;
    let result = async {
        require_root(&mut *transaction, account_id, session).await?;
        transaction.list_policy_templates(account_id).await
    }
    .await;
    let records = settle(transaction, result).await?;
    Ok(Templates {
        policies: records
            .iter()
            .map(TemplateView::of)
            .collect::<RelayResult<_>>()?,
    })
}

/// Creates (`template_id` none) or replaces one template.
pub async fn save_template(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    account_id: &str,
    template_id: Option<&str>,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<TemplateView> {
    let (name, policy, lifetime_seconds) = captured_body(body)?;
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let record = match template_id {
            None => {
                require_root(&mut *transaction, account_id, session).await?;
                let record = PolicyTemplateRecord {
                    version: POLICY_TEMPLATE_RECORD_VERSION,
                    template_id: random_identifier(),
                    account_id: account_id.to_owned(),
                    name,
                    policy: policy.to_json().to_string(),
                    lifetime_seconds,
                    created_at: now,
                    updated_at: now,
                };
                if !transaction.insert_policy_template(&record).await? {
                    return Err(RelayErrorCode::Internal);
                }
                record
            }
            Some(template_id) => {
                let existing =
                    root_template(&mut *transaction, account_id, template_id, session).await?;
                let record = PolicyTemplateRecord {
                    name,
                    policy: policy.to_json().to_string(),
                    lifetime_seconds,
                    updated_at: now.max(existing.created_at),
                    ..existing
                };
                if !transaction.update_policy_template(&record).await? {
                    return Err(RelayErrorCode::Internal);
                }
                record
            }
        };
        TemplateView::of(&record)
    }
    .await;
    settle(transaction, result).await
}

pub async fn delete_template(
    store: &dyn RelayStore,
    account_id: &str,
    template_id: &str,
    session: &str,
) -> RelayResult<Value> {
    let mut transaction = store.begin().await?;
    let result = async {
        root_template(&mut *transaction, account_id, template_id, session).await?;
        if !transaction.delete_policy_template(template_id).await? {
            return Err(RelayErrorCode::Internal);
        }
        Ok(json!({}))
    }
    .await;
    settle(transaction, result).await
}
