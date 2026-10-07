//! Replays the SDK-signed owner-operation fixtures through the request and
//! binding stages. A case the SDK refuses at `request` or `binding` must fail
//! here at that stage with its code; every other case must capture, bind, and
//! round-trip to the exact TypeScript JSON with the same hash. The `signature`
//! stage belongs to the relay's root-signature verifier.
//!
//! Regenerate with `bun run fixtures:protocol`.

use std::fs;
use std::path::PathBuf;

use oaath_protocol::ErrorCode;
use oaath_protocol::capture::parse_json;
use oaath_protocol::identity::OwnerCredentialProfile;
use oaath_protocol::owner_operation::{
    parse_signed_owner_operation, verify_owner_operation_binding,
};
use serde_json::Value;

#[test]
fn sdk_signed_owner_operations_replay_through_request_and_binding() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kernel-approval/portal-root-owner-operations.json");
    let fixtures = parse_json(&fs::read_to_string(&path).expect("run bun run fixtures:protocol"))
        .expect("JSON");
    let ecdsa_validator = fixtures["ecdsaValidator"].as_str().expect("validator");
    let cases = fixtures["cases"].as_array().expect("cases");
    assert!(cases.len() >= 50, "too few owner-operation fixtures");
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let stage = case["expect"]["failure"].as_str();
        let parsed = parse_signed_owner_operation(&case["signed"]);
        if stage == Some("request") {
            assert_eq!(
                parsed.map(|_| ()).unwrap_err().code,
                ErrorCode::SigningRequestInvalid,
                "{name}"
            );
            continue;
        }
        let signed = parsed.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(signed.to_json(), case["signed"], "{name}: canonical JSON");
        assert_eq!(
            format!("{:?}", signed.request.digest()),
            case["signed"]["request"]["userOperationHash"]
                .as_str()
                .expect("hash"),
            "{name}: digest"
        );
        let validator = match signed.request.owner_credential() {
            OwnerCredentialProfile::Ecdsa { .. } => Some(ecdsa_validator),
            _ => None,
        };
        let binding = verify_owner_operation_binding(&signed.request, validator);
        if stage == Some("binding") {
            assert_eq!(
                binding.unwrap_err().code,
                ErrorCode::KernelRuntimeBindingMismatch,
                "{name}"
            );
        } else {
            binding.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(
                case["expect"]["valid"] == Value::Bool(true) || stage == Some("signature"),
                "{name}: unknown stage"
            );
        }
    }
}
