//! Authorization lifecycle: every terminal transition happens once and every
//! ambiguous or hostile path fails closed
//! (ported from `packages/server/test/authorization.test.ts`).

mod support;

use oaath_relay::display::owner_phone_display_payload;
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::*;

#[tokio::test]
async fn returns_the_owner_phone_match_code() {
    let h = harness();
    let created = h.create_request_with(&approvable_scope()).await;
    let request_id = text(&created, "requestId");
    assert_eq!(
        text(&created, "matchCode"),
        owner_phone_display_payload("subject-1", request_id)
    );
    let again = h.create_request_with(&approvable_scope()).await;
    assert_ne!(again["matchCode"], created["matchCode"]);
}

/// The TypeScript-generated Kernel owner-signing fixture: a P-256
/// replayable-install request and its canonical signed artifact.
fn kernel_fixture(name: &str) -> (String, Value) {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/verifyKernelV4ReplayableInstallOwnerSigningArtifact.json"
    ))
    .unwrap();
    let fixture = fixtures
        .into_iter()
        .find(|fixture| fixture["name"] == json!(name))
        .unwrap();
    (
        fixture["input"]["request"].to_string(),
        fixture["input"]["artifactPlaintext"].clone(),
    )
}

/// Every scope the current server may only reject, as `authorization.test.ts`
/// lists them, plus malformed text.
fn reject_only_scopes() -> Vec<String> {
    vec![
        "{\"permission\":\"opaque\"}".into(),
        "not json".into(),
        "[1]".into(),
        json!({
            "version": "oaath.owner-signing-request/v1",
            "kind": "eip712",
            "purpose": "application",
            "signer": {
                "account": format!("0x{}", "11".repeat(20)),
                "ownerCredential": {
                    "version": "oaath.owner-credential-profile/v1",
                    "kind": "ecdsa",
                    "address": format!("0x{}", "22".repeat(20)),
                },
            },
            "typedData": {
                "types": {
                    "EIP712Domain": [{ "name": "chainId", "type": "uint256" }],
                    "Message": [{ "name": "value", "type": "uint256" }],
                },
                "primaryType": "Message",
                "domain": { "chainId": "1" },
                "message": { "value": "7" },
            },
            "expectedDigest": format!("0x{}", "33".repeat(32)),
            "replay": { "nonce": null, "deadline": null },
        })
        .to_string(),
        json!({
            "version": "oaath.owner-signing-request/v1",
            "kind": "raw-digest",
            "digest": format!("0x{}", "44".repeat(32)),
            "reason": "The device cannot derive this digest",
            "decision": "reject-only",
        })
        .to_string(),
        json!({
            "version": "oaath.signature-request/v1",
            "kind": "signature-request",
            "digest": format!("0x{}", "4b".repeat(32)),
            "display": json!({ "digest": format!("0x{}", "4b".repeat(32)), "kind": "user-operation" }).to_string(),
        })
        .to_string(),
        // A closed Kernel install request whose owner is not P-256.
        kernel_fixture("ecdsa owner").0,
    ]
}

#[tokio::test]
async fn keeps_a_reject_only_scope_reject_only_before_artifact_sealing() {
    for scope in reject_only_scopes() {
        let h = harness();
        let request_id = text(&h.create_request_with(&scope).await, "requestId").to_owned();
        h.decide(
            &request_id,
            OWNER_TOKEN,
            json!({ "outcome": "approved", "artifact": "must-not-be-sealed" }),
        )
        .await
        .failure(E::RequestInvalid);
        assert_eq!(h.kms.encryptions(), 0);
        assert_eq!(
            h.fetch(&request_id, OWNER_TOKEN).await.ok(200)["decision"],
            Value::Null
        );
        h.decide(&request_id, OWNER_TOKEN, json!({ "outcome": "rejected" }))
            .await
            .ok(200);
        assert_eq!(h.kms.encryptions(), 0);
    }
}

#[tokio::test]
async fn refuses_a_permission_artifact_the_protocol_does_not_bind() {
    let h = harness();
    let request_id = h.create_request().await;
    let scope = approvable_scope();
    for artifact in [
        decision_artifact(&scope, "another-request", 100, json!({})),
        decision_artifact(
            &scope,
            &request_id,
            100,
            json!({ "requestHash": format!("0x{}", "cc".repeat(32)) }),
        ),
        decision_artifact(&scope, &request_id, 100, json!({ "kind": "reject" })),
        // Decided after the relay decision time.
        decision_artifact(&scope, &request_id, CLOCK_SECONDS + 1, json!({})),
        // Wider than the requested policy.
        decision_artifact(
            &scope,
            &request_id,
            100,
            json!({ "approvedPolicy": { "version": "oaath.grant-policy/v2", "calls": [call("101")], "validAfter": 100, "validUntil": 190, "perChainOperationLimit": { "count": 10, "intervalSeconds": null } } }),
        ),
    ] {
        h.decide(
            &request_id,
            OWNER_TOKEN,
            json!({ "outcome": "approved", "artifact": artifact }),
        )
        .await
        .failure(E::RequestInvalid);
    }
    assert_eq!(h.kms.encryptions(), 0);
    h.approve(&request_id).await;
}

#[tokio::test]
async fn releases_only_a_verified_canonical_kernel_owner_artifact() {
    let (scope, artifact) = kernel_fixture("valid");
    let artifact = artifact.as_str().unwrap().to_owned();
    let h = harness();
    let request_id = text(&h.create_request_with(&scope).await, "requestId").to_owned();
    // A non-canonical spelling of the same signed artifact is refused.
    let pretty =
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(&artifact).unwrap()).unwrap();
    h.decide(
        &request_id,
        OWNER_TOKEN,
        json!({ "outcome": "approved", "artifact": pretty }),
    )
    .await
    .failure(E::RequestInvalid);
    let decision = h.approve_with(&request_id, &artifact).await;
    let consumed = h.consume(text(&decision, "code")).await.ok(200).clone();
    let claimed = h.claim(text(&consumed, "artifactId")).await.ok(200).clone();
    assert_eq!(claimed["artifact"], json!(artifact));
}

#[tokio::test]
async fn verifies_kernel_artifacts_after_terminal_and_expiry_precedence_but_before_kms() {
    let (scope, artifact) = kernel_fixture("valid");
    let artifact = artifact.as_str().unwrap().to_owned();
    let h = harness();
    let request_id = text(&h.create_request_with(&scope).await, "requestId").to_owned();
    h.decide(
        &request_id,
        OWNER_TOKEN,
        json!({ "outcome": "approved", "artifact": "{}" }),
    )
    .await
    .failure(E::RequestInvalid);
    assert_eq!(h.kms.encryptions(), 0);
    assert_eq!(
        h.fetch(&request_id, OWNER_TOKEN).await.ok(200)["decision"],
        Value::Null
    );

    h.approve_with(&request_id, &artifact).await;
    assert_eq!(h.kms.encryptions(), 2);
    h.decide(
        &request_id,
        OWNER_TOKEN,
        json!({ "outcome": "approved", "artifact": "{}" }),
    )
    .await
    .failure(E::AlreadyDecided);
    assert_eq!(h.kms.encryptions(), 2);

    let expired = text(&h.create_request_with(&scope).await, "requestId").to_owned();
    h.clock.advance(300_000);
    h.decide(
        &expired,
        OWNER_TOKEN,
        json!({ "outcome": "approved", "artifact": "{}" }),
    )
    .await
    .failure(E::Expired);
    assert_eq!(h.kms.encryptions(), 2);
}

#[tokio::test]
async fn is_terminal_a_second_decide_fails_and_releases_no_second_code() {
    let h = harness();
    let request_id = h.create_request().await;
    let first = h.approve(&request_id).await;
    h.decide(
        &request_id,
        OWNER_TOKEN,
        json!({ "outcome": "approved", "artifact": "{\"grant\":\"second\"}" }),
    )
    .await
    .failure(E::AlreadyDecided);
    h.decide(&request_id, OWNER_TOKEN, json!({ "outcome": "rejected" }))
        .await
        .failure(E::AlreadyDecided);
    let consumed = h.consume(text(&first, "code")).await.ok(200).clone();
    assert_eq!(consumed["artifactId"], first["artifactId"]);
}

#[tokio::test]
async fn rejects_a_decision_from_another_subject_and_never_leaks_existence() {
    let h = harness();
    let request_id = h.create_request().await;
    h.fetch(&request_id, OTHER_OWNER_TOKEN)
        .await
        .failure(E::NotFound);
    h.decide(
        &request_id,
        OTHER_OWNER_TOKEN,
        json!({ "outcome": "approved", "artifact": "x" }),
    )
    .await
    .failure(E::NotFound);
    h.decide(
        &request_id,
        OTHER_OWNER_TOKEN,
        json!({ "outcome": "rejected" }),
    )
    .await
    .failure(E::NotFound);
    assert_eq!(
        h.fetch(&request_id, OWNER_TOKEN).await.ok(200)["decision"],
        Value::Null
    );
}

#[tokio::test]
async fn refuses_to_decide_an_expired_request() {
    let h = harness_with(|options| options.request_ttl_ms = Some(1_000));
    let request_id = h.create_request().await;
    h.clock.advance(1_000);
    assert_eq!(
        h.fetch(&request_id, OWNER_TOKEN).await.ok(200)["expired"],
        json!(true)
    );
    h.decide(
        &request_id,
        OWNER_TOKEN,
        json!({ "outcome": "approved", "artifact": "x" }),
    )
    .await
    .failure(E::Expired);
    h.decide(&request_id, OWNER_TOKEN, json!({ "outcome": "rejected" }))
        .await
        .failure(E::Expired);
}

#[tokio::test]
async fn rejects_a_decision_on_an_unknown_request() {
    let h = harness();
    h.decide(
        "unknown-request",
        OWNER_TOKEN,
        json!({ "outcome": "rejected" }),
    )
    .await
    .failure(E::NotFound);
}

#[tokio::test]
async fn consumes_exactly_once() {
    let h = harness();
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    h.consume(text(&decision, "code")).await.ok(200);
    h.consume(text(&decision, "code"))
        .await
        .failure(E::CodeAlreadyConsumed);
}

#[tokio::test]
async fn survives_concurrent_consumes_with_exactly_one_release() {
    let h = harness();
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    let code = text(&decision, "code");
    let (a, b, c) = tokio::join!(h.consume(code), h.consume(code), h.consume(code));
    let mut statuses = [a.status, b.status, c.status];
    statuses.sort();
    assert_eq!(statuses, [200, 409, 409]);
}

#[tokio::test]
async fn burns_the_code_and_voids_the_artifact_when_pkce_fails() {
    let h = harness();
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    let code = text(&decision, "code");
    h.consume_with(
        code,
        CLIENT_TOKEN,
        &format!("{}Z", &CODE_VERIFIER[..42]),
        REDIRECT_URI,
    )
    .await
    .failure(E::CodeInvalid);
    // The correct verifier no longer helps: a failed binding is not a retry.
    h.consume(code).await.failure(E::CodeAlreadyConsumed);
    h.claim(text(&decision, "artifactId"))
        .await
        .failure(E::ArtifactAlreadyClaimed);
}

#[tokio::test]
async fn burns_the_code_when_the_redirect_uri_does_not_match() {
    let h = harness();
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    let code = text(&decision, "code");
    h.consume_with(
        code,
        CLIENT_TOKEN,
        CODE_VERIFIER,
        "https://app.example/other",
    )
    .await
    .failure(E::CodeInvalid);
    h.consume(code).await.failure(E::CodeAlreadyConsumed);
}

#[tokio::test]
async fn refuses_an_expired_code_and_leaves_it_unconsumed() {
    let h = harness_with(|options| options.code_ttl_ms = Some(1_000));
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    h.clock.advance(1_000);
    h.consume(text(&decision, "code")).await.failure(E::Expired);
    h.consume(text(&decision, "code")).await.failure(E::Expired);
}

#[tokio::test]
async fn hides_a_code_bound_to_another_client() {
    let h = harness();
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    let code = text(&decision, "code");
    h.consume_with(code, OTHER_CLIENT_TOKEN, CODE_VERIFIER, REDIRECT_URI)
        .await
        .failure(E::CodeInvalid);
    h.consume(code).await.ok(200);
}

#[tokio::test]
async fn is_not_an_oracle_for_whether_a_guessed_code_was_correct() {
    let h = harness();
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    let code = text(&decision, "code");
    let guessed = h.consume("unknown-code").await;
    let foreign = h
        .consume_with(code, OTHER_CLIENT_TOKEN, CODE_VERIFIER, REDIRECT_URI)
        .await;
    let wrong_redirect = h
        .consume_with(
            code,
            CLIENT_TOKEN,
            CODE_VERIFIER,
            "https://app.example/other",
        )
        .await;
    let second_id = h.create_request().await;
    let second = h.approve(&second_id).await;
    let wrong_verifier = h
        .consume_with(
            text(&second, "code"),
            CLIENT_TOKEN,
            &format!("{}Z", &CODE_VERIFIER[..42]),
            REDIRECT_URI,
        )
        .await;
    for reply in [guessed, foreign, wrong_redirect, wrong_verifier] {
        reply.failure(E::CodeInvalid);
    }
}

#[tokio::test]
async fn claims_an_artifact_once_and_only_for_its_client() {
    let h = harness();
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    let artifact_id = text(&decision, "artifactId");
    h.claim_as(artifact_id, OTHER_CLIENT_TOKEN)
        .await
        .failure(E::NotFound);
    h.claim("unknown-artifact").await.failure(E::NotFound);
    h.claim(artifact_id).await.ok(200);
    h.claim(artifact_id)
        .await
        .failure(E::ArtifactAlreadyClaimed);
}

#[tokio::test]
async fn burns_the_artifact_when_the_kms_cannot_open_it_after_claim() {
    let h = harness();
    let request_id = h.create_request().await;
    let decision = h.approve(&request_id).await;
    let failing = harness_on(h.store.clone(), h.clock.clone(), |options| {
        options.kms = TestKms::new(KmsMode::Failing);
    });
    let artifact_id = text(&decision, "artifactId");
    failing.claim(artifact_id).await.failure(E::KmsUnavailable);
    h.claim(artifact_id)
        .await
        .failure(E::ArtifactAlreadyClaimed);
}

#[tokio::test]
async fn resume_re_reads_authorization_state_without_transitioning_anything() {
    let h = harness();
    let request_id = h.create_request().await;
    let resume = || {
        h.send(post(
            "/authorization/resume",
            Some(CLIENT_TOKEN),
            Some(json!({ "requestId": request_id })),
        ))
    };
    let before = resume().await.ok(200).clone();
    assert_eq!(before["decision"], Value::Null);
    assert_eq!(before["expired"], json!(false));
    let decision = h.approve(&request_id).await;
    let after = resume().await.ok(200).clone();
    assert_eq!(
        after["decision"],
        json!({ "outcome": "approved", "decidedAt": decision["decidedAt"] })
    );
    h.consume(text(&decision, "code")).await.ok(200);
}

#[tokio::test]
async fn resume_hides_an_unknown_request() {
    let h = harness();
    h.send(post(
        "/authorization/resume",
        Some(CLIENT_TOKEN),
        Some(json!({ "requestId": "unknown" })),
    ))
    .await
    .failure(E::NotFound);
}
