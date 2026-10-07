//! Grant packaging, install approval, and root-signature verification,
//! replayed against the SDK-generated `relay/fixtures/grant` cases.

use alloy_primitives::B256;
use oaath_protocol::capture::parse_json;
use oaath_protocol::identity::parse_owner_credential_profile;
use oaath_protocol::permission::{PermissionRequest, parse_permission_request};
use oaath_relay::error::RelayErrorCode;
use oaath_relay::grant::approval::verify_grant_approval;
use oaath_relay::grant::grant_signing_request;
use oaath_relay::grant::signature::{RelyingParty, verify_root_signature};
use serde_json::{Value, json};

fn cases(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/../../fixtures/grant/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn request(case: &Value) -> PermissionRequest {
    parse_permission_request(&case["input"]["request"]).unwrap()
}

const RP: RelyingParty<'static> = RelyingParty {
    rp_id: "oaath.test",
    origin: "https://oaath.test",
};

/// The fixtures decide at the request time: 100 seconds.
const DECIDED_AT_MS: u64 = 100_000;

#[test]
fn derives_the_sdk_signing_request_for_every_root_and_signer_kind() {
    let mut accepted = 0;
    for case in cases("kernelGrantApproval") {
        let name = case["name"].as_str().unwrap();
        let request = request(&case);
        let account = case["input"]["account"].as_str().unwrap();
        let result = grant_signing_request(&request, &request.policy, account);
        if let Some(code) = case["expect"].get("error") {
            assert_eq!(code, "kernel_runtime_policy_unavailable", "{name}");
            assert_eq!(result.err(), Some(RelayErrorCode::RequestInvalid), "{name}");
            continue;
        }
        let expected = &case["expect"]["ok"];
        let signing = result.unwrap();
        assert_eq!(signing.to_json(), expected["signingRequest"], "{name}");
        assert_eq!(signing.nonce, expected["installNonce"].as_str().unwrap());
        assert_eq!(
            signing.expected_digest(),
            expected["digest"].as_str().unwrap()
        );
        let packages: Vec<Value> = signing
            .packages
            .iter()
            .map(|install| {
                json!({
                    "moduleType": install.module_type,
                    "module": install.module,
                    "moduleData": install.module_data,
                    "internalData": install.internal_data,
                })
            })
            .collect();
        assert_eq!(Value::Array(packages), expected["packages"], "{name}");
        accepted += 1;
    }
    assert_eq!(accepted, 7);
}

#[test]
fn admits_every_sdk_signed_grant_approval() {
    for case in cases("kernelGrantApproval") {
        let Some(expected) = case["expect"].get("ok") else {
            continue;
        };
        let name = case["name"].as_str().unwrap();
        let verified = verify_grant_approval(
            &request(&case),
            case["input"]["account"].as_str().unwrap(),
            expected["artifact"].as_str().unwrap(),
            DECIDED_AT_MS,
            &RP,
        )
        .unwrap_or_else(|code| panic!("{name}: {code}"));
        assert_eq!(
            verified.decision.capability_hash,
            expected["capabilityHash"].as_str().unwrap()
        );
        assert_eq!(
            verified.install_approval,
            parse_json(expected["artifact"].as_str().unwrap()).unwrap()["installApproval"]
        );
    }
}

fn first_grant() -> (PermissionRequest, String, Value) {
    let case = cases("kernelGrantApproval").remove(0);
    let artifact = parse_json(case["expect"]["ok"]["artifact"].as_str().unwrap()).unwrap();
    (
        request(&case),
        case["input"]["account"].as_str().unwrap().to_owned(),
        artifact,
    )
}

#[test]
fn refuses_a_tampered_misbound_or_foreign_approval() {
    let (request, account, artifact) = first_grant();
    let verify = |artifact: &Value, account: &str, request: &PermissionRequest| {
        verify_grant_approval(request, account, &artifact.to_string(), DECIDED_AT_MS, &RP)
    };
    assert!(verify(&artifact, &account, &request).is_ok());

    let mut tampered = Vec::new();
    let mut capability = artifact.clone();
    capability["capabilityHash"] = json!(format!("0x{}", "ab".repeat(32)));
    tampered.push(capability);
    let mut missing = artifact.clone();
    missing
        .as_object_mut()
        .unwrap()
        .shift_remove("installApproval");
    tampered.push(missing);
    // A widened policy is no attenuation of the request.
    let mut widened = artifact.clone();
    widened["approvedPolicy"]["calls"][1]["valueLimit"] = json!("1001");
    tampered.push(widened);
    // Another key's signature over the same digest.
    let other = cases("kernelGrantApproval")
        .into_iter()
        .find(|case| case["name"] == "p256 root, ecdsa signer")
        .unwrap();
    let other = parse_json(other["expect"]["ok"]["artifact"].as_str().unwrap()).unwrap();
    let mut foreign = artifact.clone();
    foreign["installApproval"]["enableSignature"] =
        other["installApproval"]["enableSignature"].clone();
    tampered.push(foreign);
    let mut packages = artifact.clone();
    packages["installApproval"]["packages"]
        .as_array_mut()
        .unwrap()
        .pop();
    tampered.push(packages);
    let mut nonce = artifact.clone();
    nonce["installApproval"]["installNonce"] = json!("0");
    tampered.push(nonce);
    for value in &tampered {
        assert_eq!(
            verify(value, &account, &request).err(),
            Some(RelayErrorCode::RequestInvalid),
            "{value}"
        );
    }
    // The registry's account, and only it.
    assert!(verify(&artifact, &format!("0x{}", "ce".repeat(20)), &request).is_err());
    // A replay onto another request.
    let mut replayed = request.clone();
    replayed.request_id = "grant-fixture-2".to_owned();
    assert!(verify(&artifact, &account, &replayed).is_err());
}

#[test]
fn verifies_root_signatures_exactly_as_the_sdk_keys() {
    for case in cases("kernelEnableSignature") {
        let input = &case["input"];
        let owner = parse_owner_credential_profile(&input["ownerCredential"]).unwrap();
        let digest: B256 = input["digest"].as_str().unwrap().parse().unwrap();
        let signature = hex::decode(&input["signature"].as_str().unwrap()[2..]).unwrap();
        let relying_party = RelyingParty {
            rp_id: input["rpId"].as_str().unwrap(),
            origin: input["origin"].as_str().unwrap(),
        };
        assert_eq!(
            verify_root_signature(&owner, digest, &signature, &relying_party),
            case["expect"]["ok"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
