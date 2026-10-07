//! Replays every TypeScript-generated protocol fixture and requires the same
//! accept/reject decision, error code, canonical output, and hash.
//!
//! Regenerate with `bun run fixtures:protocol`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use oaath_protocol::capture::parse_json;
use oaath_protocol::grant_policy::{
    hash_grant_policy, hash_grant_policy_calls, is_grant_policy_attenuation, parse_grant_policy,
};
use oaath_protocol::grant_reference::{
    parse_grant_verification_result, parse_oaath_grant_ref, parse_verify_grant_revision_input,
};
use oaath_protocol::identity::{
    KernelAccountProfile, hash_owner_credential_profile, parse_kernel_account_profile,
    parse_operator_credential_profile, parse_owner_credential_profile,
};
use oaath_protocol::kernel_account::derive_kernel_v4_account_address;
use oaath_protocol::kernel_install::parse_kernel_replayable_install_owner_signing_request;
use oaath_protocol::owner_signing::{
    parse_owner_signing_artifact, serialize_owner_signing_artifact,
    verify_kernel_v4_replayable_install_owner_signing_artifact,
};
use oaath_protocol::permission::{
    PermissionDecision, hash_permission_decision, hash_permission_request,
    parse_approved_permission, parse_permission_decision, parse_permission_request,
};
use oaath_protocol::pkce::derive_code_challenge;
use oaath_protocol::scope::classify_stored_authorization_scope;
use oaath_protocol::signing_request::{hash_owner_signing_request, parse_owner_signing_request};
use oaath_protocol::workspace::parse_workspace_account_context;
use oaath_protocol::{ErrorCode, ProtocolError, ProtocolResult};
use serde_json::{Value, json};

fn text(value: &Value) -> &str {
    value.as_str().expect("fixture field is a string")
}

fn evaluate(function: &str, input: &Value) -> ProtocolResult<Value> {
    let string = |result: ProtocolResult<String>| result.map(Value::String);
    match function {
        "deriveCodeChallenge" => string(derive_code_challenge(text(input))),
        "parseOwnerCredentialProfile" => parse_owner_credential_profile(input).map(|p| p.to_json()),
        "hashOwnerCredentialProfile" => string(hash_owner_credential_profile(input)),
        "parseOperatorCredentialProfile" => {
            parse_operator_credential_profile(input).map(|p| p.to_json())
        }
        "parseKernelAccountProfile" => parse_kernel_account_profile(input).map(|p| p.to_json()),
        "deriveKernelV4AccountAddress" => {
            // An existing account already has its address; only a derived
            // profile reaches the derivation.
            let KernelAccountProfile::Derived(profile) =
                parse_kernel_account_profile(&input["account"])?
            else {
                return Err(ProtocolError::new(
                    ErrorCode::KernelAccountDerivationInvalid,
                ));
            };
            string(derive_kernel_v4_account_address(
                &profile,
                input["ownerValidator"].as_str(),
            ))
        }
        "parseGrantPolicy" => parse_grant_policy(input).map(|p| p.to_json()),
        "hashGrantPolicy" => string(hash_grant_policy(input)),
        "hashGrantPolicyCalls" => string(hash_grant_policy_calls(input)),
        "isGrantPolicyAttenuation" => {
            is_grant_policy_attenuation(&input["requested"], &input["approved"]).map(Value::Bool)
        }
        "parseWorkspaceAccountContext" => {
            parse_workspace_account_context(input).map(|c| c.to_json())
        }
        "parsePermissionRequest" => parse_permission_request(input).map(|r| r.to_json()),
        "hashPermissionRequest" => string(hash_permission_request(input)),
        "parsePermissionDecision" => parse_permission_decision(input).map(|d| d.to_json()),
        "hashPermissionDecision" => string(hash_permission_decision(input)),
        "parseApprovedPermission" => {
            let request = parse_permission_request(&input["request"]).expect("fixture request");
            let relay_decided_at = input["relayDecidedAt"].as_u64().expect("relay time");
            parse_approved_permission(text(&input["plaintext"]), &request, relay_decided_at).map(
                |approved| {
                    json!({
                        "permission": PermissionDecision::Approve(approved.permission).to_json(),
                        "plaintext": approved.plaintext,
                    })
                },
            )
        }
        "parseOwnerSigningRequest" => parse_owner_signing_request(input).map(|r| r.to_json()),
        "hashOwnerSigningRequest" => string(hash_owner_signing_request(input)),
        "parseKernelReplayableInstallOwnerSigningRequest" => {
            parse_kernel_replayable_install_owner_signing_request(input).map(|r| r.to_json())
        }
        "parseOwnerSigningArtifact" => parse_owner_signing_artifact(input).map(|a| a.to_json()),
        "serializeOwnerSigningArtifact" => string(serialize_owner_signing_artifact(input)),
        "verifyKernelV4ReplayableInstallOwnerSigningArtifact" => {
            // The relay maps every request or artifact failure to one code.
            let request = parse_kernel_replayable_install_owner_signing_request(&input["request"])
                .map_err(|_| ProtocolError::new(ErrorCode::RelayRequestInvalid))?;
            string(verify_kernel_v4_replayable_install_owner_signing_artifact(
                &request,
                text(&input["artifactPlaintext"]),
            ))
        }
        "classifyStoredAuthorizationScope" => Ok(classify_stored_authorization_scope(
            text(&input["requestedScope"]),
            text(&input["requestId"]),
        )
        .to_json()),
        "parseVerifyGrantRevisionInput" => {
            parse_verify_grant_revision_input(input).map(|i| i.to_json())
        }
        "parseOaathGrantRef" => parse_oaath_grant_ref(input).map(|r| r.to_json()),
        "parseGrantVerificationResult" => {
            parse_grant_verification_result(input).map(|r| r.to_json())
        }
        other => panic!("fixture names an unported function {other}"),
    }
}

#[test]
fn typescript_fixtures_replay_exactly() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/protocol");
    let mut counts = BTreeMap::new();
    let mut failures = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(&directory)
        .expect("fixtures exist; run bun run fixtures:protocol")
        .map(|entry| entry.expect("fixture entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let cases: Vec<Value> =
            serde_json::from_str(&fs::read_to_string(&path).expect("fixture file")).expect("JSON");
        for case in cases {
            let function = text(&case["fn"]);
            let name = text(&case["name"]);
            let input = match case.get("inputText") {
                Some(raw) => parse_json(text(raw)).expect("inputText parses"),
                None => case["input"].clone(),
            };
            let actual = match evaluate(function, &input) {
                Ok(value) => json!({"ok": value}),
                Err(error) => json!({"error": error.code.as_str()}),
            };
            if actual != case["expect"] {
                failures.push(format!(
                    "{function} / {name}\n  expected {}\n  actual   {}",
                    case["expect"], actual
                ));
            }
            *counts.entry(function.to_owned()).or_insert(0usize) += 1;
        }
    }
    let total: usize = counts.values().sum();
    eprintln!("replayed {total} fixtures: {counts:#?}");
    assert!(total > 0, "no fixtures found in {}", directory.display());
    assert!(
        failures.is_empty(),
        "{} of {total} fixtures differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
