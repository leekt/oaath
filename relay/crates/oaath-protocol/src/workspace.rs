//! The workspace account context a permission request names
//! (`service-bootstrap.ts`'s `parseWorkspaceAccountContext`).

use serde_json::{Value, json};

use crate::capture::{exact_record, field};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure, fail};
use crate::ids::canonical_identifier;

pub const WORKSPACE_ACCOUNT_CONTEXT_VERSION: &str = "oaath.workspace-account-context/v1";

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
