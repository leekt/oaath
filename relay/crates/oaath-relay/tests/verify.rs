//! Grant reference verification matrix against the real protocol: an active
//! exact revision authorizes; every mismatch, lifecycle denial, and unreadable
//! record fails closed with a typed code; verification is replay-safe and
//! mutates nothing (ported from `packages/server/test/verify.test.ts`).

mod support;

use axum::body::Body;
use axum::http::Request;
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::*;

fn assertion(grant_id: &str, overrides: Value) -> Value {
    let mut body = json!({
        "grantId": grant_id,
        "revision": 1,
        "subject": "subject-1",
        "clientId": "client-a",
        "organizationAudience": "org-1",
        "requiredCallsDigest": calls_digest(&live_policy()["calls"]),
    });
    for (key, value) in overrides.as_object().unwrap() {
        body[key] = value.clone();
    }
    body
}

/// `approvalArtifact`: decided at the test clock for the live scope.
fn approval_artifact(request_id: &str, overrides: Value) -> String {
    decision_artifact(&live_scope(), request_id, CLOCK_SECONDS, overrides)
}

async fn verify(h: &Harness, body: Value, token: Option<&str>) -> Reply {
    h.send(post("/grants/verify", token, Some(body))).await
}

async fn expect(h: &Harness, body: Value, expected: Value) {
    assert_eq!(*verify(h, body, Some(CLIENT_TOKEN)).await.ok(200), expected);
}

fn denied(code: &str) -> Value {
    json!({ "state": "denied", "code": code })
}

fn unknown(code: &str) -> Value {
    json!({ "state": "unknown", "code": code })
}

async fn approved_grant(h: &Harness) -> (String, Value) {
    let request_id = text(&h.create_request_with(&live_scope()).await, "requestId").to_owned();
    let decision = h
        .approve_with(&request_id, &approval_artifact(&request_id, json!({})))
        .await;
    (request_id, decision)
}

#[tokio::test]
async fn uses_the_narrower_approved_calls_policy_digest_and_expiry() {
    let h = harness();
    let request_id = text(&h.create_request_with(&live_scope()).await, "requestId").to_owned();
    let mut approved = live_policy();
    approved["calls"] = json!([call("1")]);
    approved["validUntil"] = json!(CLOCK_SECONDS + 30);
    approved["perChainOperationLimit"] = json!({ "count": 2, "intervalSeconds": null });
    h.approve_with(
        &request_id,
        &approval_artifact(&request_id, json!({ "approvedPolicy": approved })),
    )
    .await;
    expect(
        &h,
        assertion(&request_id, json!({})),
        denied("grant_calls_mismatch"),
    )
    .await;
    let exact = assertion(
        &request_id,
        json!({ "requiredCallsDigest": calls_digest(&approved["calls"]) }),
    );
    let first = verify(&h, exact.clone(), Some(CLIENT_TOKEN))
        .await
        .ok(200)
        .clone();
    assert_eq!(first["state"], json!("authorized"));
    assert_eq!(
        first["ref"]["policyDigest"],
        json!(policy_digest(&approved))
    );
    h.clock.advance(31_000);
    expect(&h, exact, denied("grant_expired")).await;
}

#[tokio::test]
async fn does_not_turn_an_approved_outcome_into_authority_without_a_valid_bound_approval() {
    let mut widened = live_policy();
    widened["calls"] = json!([call("101")]);
    for change in [
        None,
        Some(json!({ "requestId": "another-request" })),
        Some(json!({ "requestHash": format!("0x{}", "cc".repeat(32)) })),
        Some(json!({ "decidedAt": CLOCK_SECONDS + 1 })),
        Some(json!({ "approvedPolicy": widened })),
        Some(json!({ "kind": "reject" })),
    ] {
        let h = harness();
        let (grant_id, _) = approved_grant(&h).await;
        // Corrupt the durable read boundary after a valid admission. Invalid
        // approvals cannot be written through the decision endpoint.
        *h.kms.opened.lock().unwrap() = Some(match change {
            None => "{}".to_owned(),
            Some(change) => approval_artifact(&grant_id, change),
        });
        expect(
            &h,
            assertion(&grant_id, json!({})),
            unknown("grant_unreadable"),
        )
        .await;
    }
}

#[tokio::test]
async fn keeps_verification_read_only_through_a_kms_outage_claim_and_code_expiry() {
    let h = harness();
    let (grant_id, decision) = approved_grant(&h).await;
    let outage = harness_on(h.store.clone(), h.clock.clone(), |options| {
        options.kms = TestKms::new(KmsMode::Failing);
    });
    expect(
        &outage,
        assertion(&grant_id, json!({})),
        unknown("grant_unreadable"),
    )
    .await;
    let consumed = h.consume(text(&decision, "code")).await.ok(200).clone();
    h.claim(text(&consumed, "artifactId")).await.ok(200);
    h.clock.advance(61_000);
    let verified = verify(&h, assertion(&grant_id, json!({})), Some(CLIENT_TOKEN))
        .await
        .ok(200)
        .clone();
    assert_eq!(verified["state"], json!("authorized"));
    h.claim(text(&consumed, "artifactId"))
        .await
        .failure(E::ArtifactAlreadyClaimed);
}

#[tokio::test]
async fn authorizes_an_active_exact_revision_with_immutable_reference_evidence() {
    let h = harness();
    let (grant_id, _) = approved_grant(&h).await;
    expect(
        &h,
        assertion(&grant_id, json!({})),
        json!({
            "state": "authorized",
            "ref": {
                "version": "oaath.grant-reference/v1",
                "grantId": grant_id,
                "revision": 1,
                "subject": "subject-1",
                "clientId": "client-a",
                "organizationAudience": "org-1",
                "state": "active",
                "policyDigest": policy_digest(&live_policy()),
            },
        }),
    )
    .await;
}

#[tokio::test]
async fn is_replay_safe_and_does_not_mutate_the_grant() {
    let h = harness();
    let request_id = text(&h.create_request_with(&live_scope()).await, "requestId").to_owned();
    expect(
        &h,
        assertion(&request_id, json!({})),
        denied("grant_pending"),
    )
    .await;
    let decision = h
        .approve_with(&request_id, &approval_artifact(&request_id, json!({})))
        .await;
    let first = verify(&h, assertion(&request_id, json!({})), Some(CLIENT_TOKEN)).await;
    let second = verify(&h, assertion(&request_id, json!({})), Some(CLIENT_TOKEN)).await;
    assert_eq!(first.body, second.body);
    let consumed = h.consume(text(&decision, "code")).await.ok(200).clone();
    h.claim(text(&consumed, "artifactId")).await.ok(200);
}

#[tokio::test]
async fn denies_a_pending_rejected_revoked_or_expired_grant() {
    let h = harness();
    let pending = text(&h.create_request_with(&live_scope()).await, "requestId").to_owned();
    expect(&h, assertion(&pending, json!({})), denied("grant_pending")).await;

    let rejected = text(&h.create_request_with(&live_scope()).await, "requestId").to_owned();
    h.decide(&rejected, OWNER_TOKEN, json!({ "outcome": "rejected" }))
        .await
        .ok(200);
    expect(
        &h,
        assertion(&rejected, json!({})),
        denied("grant_rejected"),
    )
    .await;

    let (revoked, _) = approved_grant(&h).await;
    h.send(post(
        "/invalidations",
        Some(CLIENT_TOKEN),
        Some(json!({ "grantId": revoked, "capabilityHash": format!("0x{}", "aa".repeat(32)) })),
    ))
    .await
    .ok(200);
    expect(&h, assertion(&revoked, json!({})), denied("grant_revoked")).await;

    let (expired, _) = approved_grant(&h).await;
    h.clock.advance(601_000);
    expect(&h, assertion(&expired, json!({})), denied("grant_expired")).await;
}

#[tokio::test]
async fn denies_revision_binding_and_call_set_mismatches() {
    let h = harness();
    let (grant_id, _) = approved_grant(&h).await;
    for (overrides, code) in [
        (json!({ "revision": 2 }), "grant_revision_mismatch"),
        (json!({ "subject": "subject-2" }), "grant_subject_mismatch"),
        (json!({ "clientId": "client-b" }), "grant_client_mismatch"),
        (
            json!({ "organizationAudience": "org-2" }),
            "grant_audience_mismatch",
        ),
        (
            json!({ "requiredCallsDigest": calls_digest(&json!([call("1")])) }),
            "grant_calls_mismatch",
        ),
    ] {
        expect(&h, assertion(&grant_id, overrides), denied(code)).await;
    }
}

#[tokio::test]
async fn denies_every_audience_assertion_when_the_deployment_declared_none() {
    let h = harness();
    let created = h
        .send(post(
            "/authorization/requests",
            Some(NO_AUDIENCE_CLIENT_TOKEN),
            Some(json!({
                "redirectUri": REDIRECT_URI,
                "codeChallenge": code_challenge(),
                "requestedScope": live_scope(),
            })),
        ))
        .await
        .ok(201)
        .clone();
    let request_id = text(&created, "requestId");
    h.approve_with(request_id, &approval_artifact(request_id, json!({})))
        .await;
    expect(
        &h,
        assertion(request_id, json!({})),
        denied("grant_audience_mismatch"),
    )
    .await;
}

#[tokio::test]
async fn answers_unknown_for_an_absent_grant_and_for_another_clients_grant() {
    let h = harness();
    let (grant_id, _) = approved_grant(&h).await;
    expect(
        &h,
        assertion("no-such-grant", json!({})),
        unknown("grant_unknown"),
    )
    .await;
    assert_eq!(
        *verify(
            &h,
            assertion(&grant_id, json!({ "clientId": "client-b" })),
            Some(OTHER_CLIENT_TOKEN)
        )
        .await
        .ok(200),
        unknown("grant_unknown")
    );
}

#[tokio::test]
async fn answers_unknown_never_authorized_for_an_unreadable_stored_scope() {
    let h = harness();
    let unreadable = text(
        &h.create_request_with("{\"not\":\"a permission request\"}")
            .await,
        "requestId",
    )
    .to_owned();
    expect(
        &h,
        assertion(&unreadable, json!({})),
        unknown("grant_unreadable"),
    )
    .await;

    // A scope whose own application binding contradicts the authenticated
    // creator is contradictory evidence and fails closed the same way.
    let mut contradictory: Value = serde_json::from_str(&live_scope()).unwrap();
    contradictory["application"]["clientId"] = json!("client-b");
    let created = text(
        &h.create_request_with(&contradictory.to_string()).await,
        "requestId",
    )
    .to_owned();
    expect(
        &h,
        assertion(&created, json!({})),
        unknown("grant_unreadable"),
    )
    .await;
}

#[tokio::test]
async fn refuses_malformed_assertions_and_wrong_roles_at_the_wire() {
    let h = harness();
    let (grant_id, _) = approved_grant(&h).await;
    let mut missing = assertion(&grant_id, json!({}));
    missing
        .as_object_mut()
        .unwrap()
        .shift_remove("requiredCallsDigest");
    verify(&h, missing, Some(CLIENT_TOKEN))
        .await
        .failure(E::RequestInvalid);
    verify(
        &h,
        assertion(&grant_id, json!({ "revision": 0 })),
        Some(CLIENT_TOKEN),
    )
    .await
    .failure(E::RequestInvalid);
    verify(&h, assertion(&grant_id, json!({})), None)
        .await
        .failure(E::Unauthenticated);
    verify(&h, assertion(&grant_id, json!({})), Some(OWNER_TOKEN))
        .await
        .failure(E::Forbidden);
}

/// Sends raw JSON text, so a `-0` token reaches the relay unchanged.
fn raw_verify(body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/grants/verify")
        .header("authorization", format!("Bearer {CLIENT_TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn answers_negative_zero_exactly_as_the_typescript_relay() {
    let h = harness();
    let (grant_id, _) = approved_grant(&h).await;
    let body = assertion(&grant_id, json!({})).to_string();
    // `JSON.parse` keeps `-0` and the protocol refuses it as a revision, so
    // the TypeScript relay answers relay_request_invalid for every spelling.
    for negative_zero in ["-0", "-0.0", "-0e0"] {
        let tampered = body.replace("\"revision\":1", &format!("\"revision\":{negative_zero}"));
        assert_ne!(tampered, body);
        h.send(raw_verify(tampered))
            .await
            .failure(E::RequestInvalid);
    }
    // `1.0` is the safe integer 1 in JavaScript and verifies.
    let float = body.replace("\"revision\":1", "\"revision\":1.0");
    assert_eq!(
        h.send(raw_verify(float)).await.ok(200)["state"],
        json!("authorized")
    );
}
