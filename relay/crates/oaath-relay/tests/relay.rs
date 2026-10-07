//! Relay handler round-trips and wire failure projection
//! (ported from `packages/server/test/relay.test.ts`).

mod support;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::Request;
use oaath_relay::authentication::RelayCallerRole;
use oaath_relay::bootstrap::{
    BootstrapApplication, BootstrapChain, BootstrapConfiguration, BootstrapSelection,
    RelayBootstrapResolver,
};
use oaath_relay::error::{RelayErrorCode, RelayResult};
use oaath_relay::store::memory::MemoryRelayStore;
use oaath_relay::store::{RelayStore, RelayTransaction};
use oaath_relay::{Relay, records, registry};
use serde_json::{Value, json};
use support::*;

use RelayErrorCode as E;

#[tokio::test]
async fn snapshots_a_distinct_approving_device_while_keeping_the_requesting_member() {
    let routing = TestOwnerRouting::new(Some(("team-phone", "subject-2")));
    let h = harness_with(|options| options.owner_routing = routing.clone());
    let request_id = h.create_request().await;
    routing.set("team-phone", "subject-1");

    h.fetch(&request_id, OWNER_TOKEN).await.failure(E::NotFound);
    h.decide(&request_id, OWNER_TOKEN, json!({ "outcome": "rejected" }))
        .await
        .failure(E::NotFound);
    h.fetch(&request_id, OTHER_OWNER_TOKEN).await.ok(200);
    let decision = h
        .decide(
            &request_id,
            OTHER_OWNER_TOKEN,
            json!({ "outcome": "approved", "artifact": permission_artifact(&request_id) }),
        )
        .await
        .ok(200)
        .clone();
    h.consume(text(&decision, "code")).await.ok(200);
    h.claim(text(&decision, "artifactId")).await.ok(200);
    assert_eq!(routing.resolutions.load(Ordering::SeqCst), 1);
}

/// Counts `begin` calls on an inner store.
struct CountingStore {
    inner: MemoryRelayStore,
    begins: std::sync::atomic::AtomicUsize,
    ambiguous: bool,
}

struct AmbiguousTransaction(Box<dyn RelayTransaction>);

macro_rules! ambiguous_transaction {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {
        #[async_trait]
        impl RelayTransaction for AmbiguousTransaction {
            $(async fn $name(&mut self, $($arg: $ty),*) -> $out { self.0.$name($($arg),*).await })*

            /// The commit never proves itself: the transition is rolled back.
            async fn commit(self: Box<Self>) -> RelayResult<()> {
                self.0.rollback().await;
                Err(E::StateAmbiguous)
            }

            async fn rollback(self: Box<Self>) {
                self.0.rollback().await;
            }
        }
    };
}

ambiguous_transaction! {
    lock_authorization_request(id: &str) -> RelayResult<Option<records::AuthorizationRequestRecord>>;
    insert_authorization_request(r: &records::AuthorizationRequestRecord) -> RelayResult<bool>;
    lock_authorization_decision(id: &str) -> RelayResult<Option<records::AuthorizationDecisionRecord>>;
    insert_authorization_decision(r: &records::AuthorizationDecisionRecord) -> RelayResult<bool>;
    lock_authorization_code(id: &str) -> RelayResult<Option<records::AuthorizationCodeRecord>>;
    insert_authorization_code(r: &records::AuthorizationCodeRecord) -> RelayResult<bool>;
    consume_authorization_code(id: &str, at: u64) -> RelayResult<bool>;
    lock_capability_invalidation(id: &str) -> RelayResult<Option<records::CapabilityInvalidationRecord>>;
    insert_capability_invalidation(r: &records::CapabilityInvalidationRecord) -> RelayResult<bool>;
    lock_encrypted_artifact(id: &str) -> RelayResult<Option<records::EncryptedArtifactRecord>>;
    lock_encrypted_artifact_by_request_id(id: &str) -> RelayResult<Option<records::EncryptedArtifactRecord>>;
    insert_encrypted_artifact(r: &records::EncryptedArtifactRecord) -> RelayResult<bool>;
    claim_encrypted_artifact(id: &str, at: u64) -> RelayResult<bool>;
    lock_signer(id: &str) -> RelayResult<Option<registry::SignerRecord>>;
    lock_signer_by_profile_hash(hash: &str) -> RelayResult<Option<registry::SignerRecord>>;
    list_signers_by_authenticator(hash: &str) -> RelayResult<Vec<registry::SignerRecord>>;
    insert_signer(r: &registry::SignerRecord) -> RelayResult<bool>;
    list_signer_accounts(id: &str) -> RelayResult<Vec<(registry::AccountRecord, registry::AccountSignerRecord)>>;
    insert_account(r: &registry::AccountRecord) -> RelayResult<bool>;
    insert_account_signer(r: &registry::AccountSignerRecord) -> RelayResult<bool>;
}

#[async_trait]
impl RelayStore for CountingStore {
    async fn begin(&self) -> RelayResult<Box<dyn RelayTransaction>> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        let transaction = self.inner.begin().await?;
        Ok(if self.ambiguous {
            Box::new(AmbiguousTransaction(transaction))
        } else {
            transaction
        })
    }

    async fn close(&self) -> RelayResult<()> {
        self.inner.close().await
    }
}

fn counting_store(ambiguous: bool) -> Arc<CountingStore> {
    Arc::new(CountingStore {
        inner: MemoryRelayStore::new(),
        begins: Default::default(),
        ambiguous,
    })
}

fn create_body(scope: &str) -> Option<Value> {
    Some(json!({
        "redirectUri": REDIRECT_URI,
        "codeChallenge": code_challenge(),
        "requestedScope": scope,
    }))
}

#[tokio::test]
async fn creates_no_request_when_the_deployment_resolves_no_owner() {
    let store = counting_store(false);
    let h = harness_on(store.clone(), TestClock::new(), |options| {
        options.owner_routing = TestOwnerRouting::new(None);
    });
    h.send(post(
        "/authorization/requests",
        Some(CLIENT_TOKEN),
        create_body(&approvable_scope()),
    ))
    .await
    .failure(E::Forbidden);
    assert_eq!(store.begins.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn round_trips_create_fetch_approve_consume_and_claim() {
    let h = harness();
    let created = h.create_request_with(&approvable_scope()).await;
    let keys: Vec<&String> = created.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["requestId", "expiresAt", "matchCode"]);
    let request_id = text(&created, "requestId").to_owned();
    assert_eq!(request_id.len(), 43);
    assert_eq!(text(&created, "matchCode").len(), 8);
    assert_eq!(created["expiresAt"], json!(CLOCK_START + 300_000));

    let state = h.fetch(&request_id, OWNER_TOKEN).await.ok(200).clone();
    assert_eq!(
        state,
        json!({
            "requestId": request_id,
            "clientId": "client-a",
            "redirectUri": REDIRECT_URI,
            "requestedScope": approvable_scope(),
            "expiresAt": CLOCK_START + 300_000,
            "expired": false,
            "decision": null,
        })
    );

    let decision = h.approve(&request_id).await;
    let keys: Vec<&String> = decision.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "outcome",
            "decidedAt",
            "code",
            "artifactId",
            "redirectUri",
            "codeExpiresAt"
        ]
    );
    assert_eq!(decision["redirectUri"], json!(REDIRECT_URI));
    assert_eq!(text(&decision, "code").len(), 43);
    assert_eq!(decision["codeExpiresAt"], json!(CLOCK_START + 60_000));

    let consumed = h.consume(text(&decision, "code")).await.ok(200).clone();
    assert_eq!(
        consumed,
        json!({ "requestId": request_id, "artifactId": decision["artifactId"] })
    );
    let claimed = h.claim(text(&decision, "artifactId")).await.ok(200).clone();
    assert_eq!(
        claimed,
        json!({ "requestId": request_id, "artifact": permission_artifact(&request_id) })
    );
}

#[tokio::test]
async fn reports_a_rejected_decision_through_fetch_and_resume() {
    let h = harness();
    let request_id = h.create_request().await;
    let rejected = h
        .decide(&request_id, OWNER_TOKEN, json!({ "outcome": "rejected" }))
        .await
        .ok(200)
        .clone();
    assert_eq!(
        rejected,
        json!({ "outcome": "rejected", "decidedAt": CLOCK_START })
    );
    let resumed = h
        .send(post(
            "/authorization/resume",
            Some(CLIENT_TOKEN),
            Some(json!({ "requestId": request_id })),
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(
        resumed["decision"],
        json!({ "outcome": "rejected", "decidedAt": CLOCK_START })
    );
}

#[tokio::test]
async fn returns_only_the_error_code_for_ordinary_relay_failures() {
    let h = harness();
    let reply = h.fetch("unknown-id", OWNER_TOKEN).await;
    assert_eq!(reply.status, 404);
    assert_eq!(
        reply.body,
        json!({ "error": { "code": "relay_not_found" } })
    );
    assert_eq!(reply.headers["cache-control"], "no-store");
    assert_eq!(
        reply.headers["content-type"],
        "application/json; charset=utf-8"
    );
}

#[tokio::test]
async fn rejects_an_unknown_route() {
    let h = harness();
    for request in [
        get("/", Some(OWNER_TOKEN)),
        get("/authorization", Some(OWNER_TOKEN)),
        get("/authorization/requests/a/b/c", Some(OWNER_TOKEN)),
        post(
            "/authorization/codes/other",
            Some(CLIENT_TOKEN),
            Some(json!({})),
        ),
        post("/authorization/artifacts/a/burn", Some(CLIENT_TOKEN), None),
        post(
            "/authorization/requests/a/approve",
            Some(OWNER_TOKEN),
            Some(json!({})),
        ),
        // Later-stage surfaces answer as the unconfigured TypeScript relay does.
        get("/native/inbox", Some(OWNER_TOKEN)),
        post("/session-signers", Some(CLIENT_TOKEN), Some(json!({}))),
        get("/grants/grant-1/revocations/1", Some(CLIENT_TOKEN)),
        post(
            "/chains/1/reads",
            Some(CLIENT_TOKEN),
            Some(json!({ "request": {} })),
        ),
        post(
            "/chains/1/paymaster/data",
            Some(CLIENT_TOKEN),
            Some(json!({})),
        ),
        get("/chains/1", Some(CLIENT_TOKEN)),
        get("/bootstrap", Some(CLIENT_TOKEN)),
    ] {
        h.send(request).await.failure(E::NotFound);
    }
    h.send(get("/chains/1/reads", Some(CLIENT_TOKEN)))
        .await
        .failure(E::MethodNotAllowed);
}

#[tokio::test]
async fn rejects_a_wrong_method() {
    let h = harness();
    for request in [
        get("/authorization/requests", Some(CLIENT_TOKEN)),
        post(
            "/authorization/requests/some-id",
            Some(OWNER_TOKEN),
            Some(json!({})),
        ),
        get("/authorization/resume", Some(CLIENT_TOKEN)),
        get("/authorization/codes/consume", Some(CLIENT_TOKEN)),
        get("/authorization/artifacts/some-id/claim", Some(CLIENT_TOKEN)),
        get(
            "/authorization/requests/some-id/decision",
            Some(OWNER_TOKEN),
        ),
        get(
            "/authorization/requests/some-id/withdraw",
            Some(CLIENT_TOKEN),
        ),
        post("/bootstrap", Some(CLIENT_TOKEN), None),
        get("/invalidations", Some(CLIENT_TOKEN)),
        get("/grants/verify", Some(CLIENT_TOKEN)),
    ] {
        h.send(request).await.failure(E::MethodNotAllowed);
    }
}

#[tokio::test]
async fn rejects_a_non_canonical_path_identifier() {
    let h = harness();
    h.send(get(
        "/authorization/requests/not%20canonical",
        Some(OWNER_TOKEN),
    ))
    .await
    .failure(E::RequestInvalid);
    h.send(post(
        "/authorization/artifacts/not!canonical/claim",
        Some(CLIENT_TOKEN),
        None,
    ))
    .await
    .failure(E::RequestInvalid);
}

#[tokio::test]
async fn rejects_a_missing_or_unknown_credential_and_a_failing_port() {
    let h = harness();
    h.send(post("/authorization/requests", None, Some(json!({}))))
        .await
        .failure(E::Unauthenticated);
    h.send(post(
        "/authorization/requests",
        Some("unknown-token"),
        Some(json!({})),
    ))
    .await
    .failure(E::Unauthenticated);
    let failing = harness_with(|options| {
        options.authentication = Arc::new(TestAuthentication::Failing);
    });
    failing
        .send(post(
            "/authorization/requests",
            Some(CLIENT_TOKEN),
            Some(json!({})),
        ))
        .await
        .failure(E::Unauthenticated);
}

#[tokio::test]
async fn rejects_a_caller_in_the_wrong_role() {
    let h = harness();
    h.send(post(
        "/authorization/requests",
        Some(OWNER_TOKEN),
        Some(json!({})),
    ))
    .await
    .failure(E::Forbidden);
    h.send(get("/authorization/requests/some-id", Some(CLIENT_TOKEN)))
        .await
        .failure(E::Forbidden);
}

#[tokio::test]
async fn rejects_an_authentication_port_that_breaks_its_contract() {
    use RelayCallerRole::Client;
    let many: Vec<String> = (0..9).map(|index| format!("https://a/{index}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    for broken in [
        caller(Client, "", "s", &[], None),
        caller(Client, "c", "not canonical", &[], None),
        caller(Client, "c", "s", &many, None),
        caller(Client, "c", "s", &["a\u{1}b"], None),
        caller(Client, "c", "s", &[], Some("bad audience")),
    ] {
        let h = harness_with(|options| {
            options.authentication = Arc::new(TestAuthentication::Fixed(broken));
        });
        h.send(post(
            "/authorization/requests",
            Some(CLIENT_TOKEN),
            Some(json!({})),
        ))
        .await
        .failure(E::Internal);
    }
}

fn raw(path: &str, content_type: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {CLIENT_TOKEN}"));
    if let Some(content_type) = content_type {
        builder = builder.header("content-type", content_type);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

#[tokio::test]
async fn rejects_a_body_that_is_not_exact_json() {
    let h = harness();
    let path = "/authorization/requests";
    let valid = json!({
        "redirectUri": REDIRECT_URI,
        "codeChallenge": code_challenge(),
        "requestedScope": "{}",
    });
    let with = |key: &str, value: Value| {
        let mut body = valid.clone();
        body[key] = value;
        body
    };
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("codeChallenge");
    h.send(raw(path, None, "{}"))
        .await
        .failure(E::RequestInvalid);
    h.send(raw(path, Some("text/plain"), &valid.to_string()))
        .await
        .failure(E::RequestInvalid);
    h.send(raw(path, Some("application/json"), "{not json"))
        .await
        .failure(E::RequestInvalid);
    for body in [
        json!([valid]),
        json!(null),
        json!("text"),
        with("extra", json!(1)),
        missing,
        with("requestedScope", json!("")),
        with("requestedScope", json!("a\u{0}b")),
        with("requestedScope", json!(7)),
        with("codeChallenge", json!("short")),
        with("redirectUri", json!("x".repeat(2049))),
    ] {
        h.send(post(path, Some(CLIENT_TOKEN), Some(body)))
            .await
            .failure(E::RequestInvalid);
    }
    // Content type matching is a case-insensitive prefix, with parameters, and
    // a UTF-8 BOM is dropped exactly as `Request.text()` drops it.
    h.send(raw(
        path,
        Some("Application/JSON; charset=utf-8"),
        &format!(
            "\u{feff}{}",
            with("requestedScope", json!(approvable_scope()))
        ),
    ))
    .await
    .ok(201);
}

#[tokio::test]
async fn rejects_a_body_beyond_its_bound() {
    let h = harness_with(|options| options.max_body_bytes = Some(256));
    h.send(post(
        "/authorization/requests",
        Some(CLIENT_TOKEN),
        create_body(&"x".repeat(512)),
    ))
    .await
    .failure(E::RequestInvalid);
}

#[tokio::test]
async fn rejects_an_unsupported_decision_outcome_or_shape() {
    let h = harness();
    let request_id = h.create_request().await;
    for body in [
        json!({ "outcome": "maybe" }),
        json!({ "outcome": "approved" }),
        json!({ "outcome": "rejected", "artifact": "x" }),
        json!({ "outcome": "approved", "artifact": "" }),
    ] {
        h.decide(&request_id, OWNER_TOKEN, body)
            .await
            .failure(E::RequestInvalid);
    }
}

#[tokio::test]
async fn refuses_a_decision_body_that_names_a_subject_or_client() {
    let h = harness();
    let request_id = h.create_request().await;
    for body in [
        json!({ "outcome": "rejected", "subjectId": "subject-1" }),
        json!({ "outcome": "rejected", "subject": "subject-2" }),
        json!({ "outcome": "approved", "artifact": "x", "subjectId": "subject-2" }),
        json!({ "outcome": "approved", "artifact": "x", "clientId": "client-a" }),
    ] {
        h.decide(&request_id, OWNER_TOKEN, body)
            .await
            .failure(E::RequestInvalid);
    }
    let state = h.fetch(&request_id, OWNER_TOKEN).await;
    assert_eq!(state.ok(200)["decision"], Value::Null);
}

#[tokio::test]
async fn rejects_a_redirect_uri_the_deployment_did_not_register() {
    let h = harness();
    h.send(post(
        "/authorization/requests",
        Some(CLIENT_TOKEN),
        Some(json!({
            "redirectUri": "https://attacker.example/callback",
            "codeChallenge": code_challenge(),
            "requestedScope": "{}",
        })),
    ))
    .await
    .failure(E::Forbidden);
}

fn limiter(mode: LimiterMode) -> Arc<TestLimiter> {
    Arc::new(TestLimiter {
        mode,
        seen: Mutex::new(Vec::new()),
    })
}

#[tokio::test]
async fn projects_limiter_verdicts_after_authentication() {
    let limited = limiter(LimiterMode::Limited);
    let h = harness_with(|options| options.rate_limit = Some(limited.clone()));
    h.send(post(
        "/authorization/requests",
        Some(CLIENT_TOKEN),
        Some(json!({})),
    ))
    .await
    .failure(E::RateLimited);
    // Unauthenticated callers never reach the limiter.
    h.send(post("/authorization/requests", None, Some(json!({}))))
        .await
        .failure(E::Unauthenticated);
    assert_eq!(
        *limited.seen.lock().unwrap(),
        [("authorization.create".to_owned(), "client-a".to_owned())]
    );

    let failing = harness_with(|options| options.rate_limit = Some(limiter(LimiterMode::Failing)));
    failing
        .send(post(
            "/authorization/requests",
            Some(CLIENT_TOKEN),
            Some(json!({})),
        ))
        .await
        .failure(E::RateLimited);

    let allowed = harness_with(|options| options.rate_limit = Some(limiter(LimiterMode::Allowed)));
    allowed.create_request().await;
}

#[tokio::test]
async fn projects_an_unavailable_store_to_503() {
    let h = harness();
    h.store.close().await.unwrap();
    h.send(post(
        "/authorization/requests",
        Some(CLIENT_TOKEN),
        create_body("{}"),
    ))
    .await
    .failure(E::StoreUnavailable);
}

#[tokio::test]
async fn projects_an_unproven_commit_to_500_without_retrying() {
    let store = counting_store(true);
    let h = harness_on(store.clone(), TestClock::new(), |_| {});
    h.send(post(
        "/authorization/requests",
        Some(CLIENT_TOKEN),
        create_body("{}"),
    ))
    .await
    .failure(E::StateAmbiguous);
    assert_eq!(store.begins.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn projects_an_unavailable_or_leaking_kms_to_503() {
    for mode in [KmsMode::Failing, KmsMode::Leaking] {
        let h = harness_with(|options| options.kms = TestKms::new(mode));
        let request_id = h.create_request().await;
        h.decide(
            &request_id,
            OWNER_TOKEN,
            json!({ "outcome": "approved", "artifact": permission_artifact(&request_id) }),
        )
        .await
        .failure(E::KmsUnavailable);
        // Nothing was decided: sealing precedes the transaction.
        assert_eq!(
            h.fetch(&request_id, OWNER_TOKEN).await.ok(200)["decision"],
            Value::Null
        );
    }
}

#[tokio::test]
async fn rejects_handler_options_that_break_their_contract() {
    let build = |configure: fn(&mut oaath_relay::RelayOptions)| {
        let mut options = options(
            Arc::new(MemoryRelayStore::new()),
            TestClock::new(),
            TestKms::new(KmsMode::Reversible),
        );
        configure(&mut options);
        Relay::new(options).err()
    };
    assert_eq!(build(|_| {}), None);
    let invalid: [fn(&mut oaath_relay::RelayOptions); 4] = [
        |o| o.request_ttl_ms = Some(0),
        |o| o.request_ttl_ms = Some(86_400_001),
        // A code may never outlive the RFC 6749 ten-minute ceiling.
        |o| o.code_ttl_ms = Some(600_001),
        |o| o.max_body_bytes = Some(0),
    ];
    for configure in invalid {
        assert_eq!(build(configure), Some(E::Internal));
    }
}

#[tokio::test]
async fn rejects_an_unreadable_injected_clock() {
    let h = harness();
    h.clock.break_clock();
    h.send(post(
        "/authorization/requests",
        Some(CLIENT_TOKEN),
        create_body("{}"),
    ))
    .await
    .failure(E::Internal);
}

#[tokio::test]
async fn keeps_one_clients_authorization_invisible_to_another() {
    let h = harness();
    let request_id = h.create_request().await;
    h.send(post(
        "/authorization/resume",
        Some(OTHER_CLIENT_TOKEN),
        Some(json!({ "requestId": request_id })),
    ))
    .await
    .failure(E::NotFound);
}

#[tokio::test]
async fn releases_the_decided_code_to_exactly_the_creating_client() {
    let h = harness();
    let request_id = h.create_request().await;
    let path = format!("/authorization/requests/{request_id}/code");

    assert_eq!(
        *h.send(get(&path, Some(CLIENT_TOKEN))).await.ok(200),
        json!({ "outcome": "pending" })
    );
    h.send(get(&path, Some(OTHER_CLIENT_TOKEN)))
        .await
        .failure(E::NotFound);

    let approved = h.approve(&request_id).await;
    let picked = h.send(get(&path, Some(CLIENT_TOKEN))).await.ok(200).clone();
    assert_eq!(
        picked,
        json!({
            "outcome": "approved",
            "decidedAt": approved["decidedAt"],
            "code": approved["code"],
            "codeExpiresAt": approved["codeExpiresAt"],
        })
    );
    assert_eq!(
        *h.send(get(&path, Some(CLIENT_TOKEN))).await.ok(200),
        picked
    );

    h.clock.advance(120_000);
    h.send(get(&path, Some(CLIENT_TOKEN)))
        .await
        .failure(E::Expired);
}

#[tokio::test]
async fn reports_a_rejection_through_pickup_and_an_expired_pending_request() {
    let h = harness();
    let request_id = h.create_request().await;
    h.decide(&request_id, OWNER_TOKEN, json!({ "outcome": "rejected" }))
        .await
        .ok(200);
    let path = format!("/authorization/requests/{request_id}/code");
    assert_eq!(
        *h.send(get(&path, Some(CLIENT_TOKEN))).await.ok(200),
        json!({ "outcome": "rejected", "decidedAt": CLOCK_START })
    );

    let pending = h.create_request().await;
    h.clock.advance(300_000);
    h.send(get(
        &format!("/authorization/requests/{pending}/code"),
        Some(CLIENT_TOKEN),
    ))
    .await
    .failure(E::Expired);
}

#[tokio::test]
async fn withdraws_once_and_answers_the_committed_winner() {
    let h = harness();
    let request_id = h.create_request().await;
    let path = format!("/authorization/requests/{request_id}/withdraw");
    h.send(post(&path, Some(OTHER_CLIENT_TOKEN), Some(json!({}))))
        .await
        .failure(E::NotFound);
    h.send(post(
        &path,
        Some(CLIENT_TOKEN),
        Some(json!({ "reason": "x" })),
    ))
    .await
    .failure(E::RequestInvalid);
    let withdrawn = h
        .send(post(&path, Some(CLIENT_TOKEN), Some(json!({}))))
        .await
        .ok(200)
        .clone();
    assert_eq!(
        withdrawn,
        json!({ "requestId": request_id, "outcome": "withdrawn", "decidedAt": CLOCK_START })
    );
    h.clock.advance(1_000);
    assert_eq!(
        *h.send(post(&path, Some(CLIENT_TOKEN), Some(json!({}))))
            .await
            .ok(200),
        withdrawn
    );
    h.decide(&request_id, OWNER_TOKEN, json!({ "outcome": "rejected" }))
        .await
        .failure(E::AlreadyDecided);
    assert_eq!(
        *h.send(get(
            &format!("/authorization/requests/{request_id}/code"),
            Some(CLIENT_TOKEN)
        ))
        .await
        .ok(200),
        json!({ "outcome": "withdrawn", "decidedAt": CLOCK_START })
    );

    // An approval is never revoked by a later withdrawal.
    let approved_id = h.create_request().await;
    let approved = h.approve(&approved_id).await;
    assert_eq!(
        *h.send(post(
            &format!("/authorization/requests/{approved_id}/withdraw"),
            Some(CLIENT_TOKEN),
            Some(json!({})),
        ))
        .await
        .ok(200),
        json!({ "requestId": approved_id, "outcome": "approved", "decidedAt": approved["decidedAt"] })
    );
    let expired_id = h.create_request().await;
    h.clock.advance(300_000);
    assert_eq!(
        *h.send(post(
            &format!("/authorization/requests/{expired_id}/withdraw"),
            Some(CLIENT_TOKEN),
            Some(json!({})),
        ))
        .await
        .ok(200),
        json!({ "requestId": expired_id, "outcome": "expired", "decidedAt": null })
    );
}

#[tokio::test]
async fn records_invalidations_durably_and_idempotently() {
    let h = harness();
    let capability_hash = format!("0x{}", "ab".repeat(32));
    let body = json!({ "grantId": "grant-1", "capabilityHash": capability_hash });
    let first = h
        .send(post(
            "/invalidations",
            Some(CLIENT_TOKEN),
            Some(body.clone()),
        ))
        .await
        .ok(200)
        .clone();
    // The evidence hash is the TypeScript relay's exact digest.
    let expected = digest_text(&format!(
        "oaath-relay-invalidation:v1:client-a:grant-1:{capability_hash}:{CLOCK_START}"
    ));
    assert_eq!(
        first,
        json!({ "evidenceHash": expected, "invalidatedAt": CLOCK_SECONDS })
    );
    h.clock.advance(5_000);
    assert_eq!(
        *h.send(post(
            "/invalidations",
            Some(CLIENT_TOKEN),
            Some(body.clone())
        ))
        .await
        .ok(200),
        first
    );
    h.send(post("/invalidations", Some(OTHER_CLIENT_TOKEN), Some(body)))
        .await
        .failure(E::NotFound);
    for invalid in [
        json!({ "grantId": "grant-1" }),
        json!({ "grantId": "grant 1", "capabilityHash": capability_hash }),
        json!({ "grantId": "grant-1", "capabilityHash": format!("0x{}", "AB".repeat(32)) }),
        json!({ "grantId": "grant-1", "capabilityHash": capability_hash, "extra": true }),
    ] {
        h.send(post("/invalidations", Some(CLIENT_TOKEN), Some(invalid)))
            .await
            .failure(E::RequestInvalid);
    }
    h.send(post("/invalidations", Some(OWNER_TOKEN), Some(json!({}))))
        .await
        .failure(E::Forbidden);
}

fn digest_text(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("0x{}", hex::encode(Sha256::digest(value.as_bytes())))
}

struct SelectingResolver {
    callers: Mutex<Vec<String>>,
    chain_ids: Vec<u64>,
    assigned: bool,
}

#[async_trait]
impl RelayBootstrapResolver for SelectingResolver {
    async fn resolve(
        &self,
        caller: &oaath_relay::authentication::RelayCaller,
    ) -> RelayResult<Option<BootstrapSelection>> {
        self.callers
            .lock()
            .unwrap()
            .push(format!("{}:{}", caller.client_id, caller.subject));
        Ok(self.assigned.then(|| BootstrapSelection {
            application: BootstrapApplication {
                application_id: "app-a".into(),
                application_name: "OAAth Example".into(),
            },
            context: json!({
                "version": "oaath.workspace-account-context/v1",
                "workspaceId": if caller.client_id == "client-b" { "team-2" } else { "personal-1" },
                "workspaceKind": "personal",
                "accountId": "account-1",
            }),
            account: json!({
                "version": "oaath.kernel-account-profile/v1",
                "kind": "kernel",
                "accountIndex": "0",
                "kernelVersion": "0.4.0",
                "factoryRoute": "kernel_factory",
                "entryPoint": { "version": "0.9" },
                "ownerCredential": {
                    "version": "oaath.owner-credential-profile/v1",
                    "kind": "ecdsa",
                    "address": format!("0x{}", "11".repeat(20)),
                },
            }),
            owner_validator: Some(format!("0x{}", "22".repeat(20))),
            chain_ids: self.chain_ids.clone(),
        }))
    }
}

fn chain(chain_id: u64, hash: Option<String>) -> BootstrapChain {
    BootstrapChain {
        chain_id,
        enable_verification_gas_floor: None,
        usage: true,
        fee_payer: None,
        static_paymaster_configuration_hash: hash,
    }
}

fn bootstrap_harness(
    chain_ids: Vec<u64>,
    assigned: bool,
    chains: Vec<BootstrapChain>,
) -> (Harness, Arc<SelectingResolver>) {
    let resolver = Arc::new(SelectingResolver {
        callers: Mutex::new(Vec::new()),
        chain_ids,
        assigned,
    });
    let configured = resolver.clone();
    let h = harness_with(move |options| {
        options.bootstrap = Some(BootstrapConfiguration {
            resolver: configured,
            chains,
        });
    });
    (h, resolver)
}

#[tokio::test]
async fn serves_the_exact_versioned_bootstrap_document_to_a_client() {
    let hash = format!("0x{}", "44".repeat(32));
    let (h, resolver) = bootstrap_harness(
        vec![31_337],
        true,
        vec![chain(31_337, Some(hash.clone())), chain(31_338, None)],
    );
    let document = h
        .send(get("/bootstrap", Some(CLIENT_TOKEN)))
        .await
        .ok(200)
        .clone();
    // The protocol owns the served shape, key order included.
    let keys: Vec<&String> = document.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "version",
            "context",
            "application",
            "userHandle",
            "account",
            "ownerValidator",
            "chains",
            "sessionSigner"
        ]
    );
    assert_eq!(document["account"]["factoryRoute"], json!("kernel_factory"));
    assert_eq!(
        document,
        json!({
            "version": "oaath.service-bootstrap/v4",
            "application": {
                "applicationId": "app-a",
                "applicationName": "OAAth Example",
                "clientId": "client-a",
                "redirectUris": [REDIRECT_URI],
            },
            "userHandle": "subject-1",
            "context": {
                "version": "oaath.workspace-account-context/v1",
                "workspaceId": "personal-1",
                "workspaceKind": "personal",
                "accountId": "account-1",
            },
            "account": document["account"],
            "ownerValidator": format!("0x{}", "22".repeat(20)),
            "chains": [{
                "chainId": 31_337,
                "usage": true,
                "feePayer": null,
                "paymasterService": null,
                "staticPaymasterConfigurationHash": hash,
            }],
            "sessionSigner": { "mode": "frontend", "providerId": null },
        })
    );
    let other = h
        .send(get("/bootstrap", Some(OTHER_CLIENT_TOKEN)))
        .await
        .ok(200)
        .clone();
    assert_eq!(other["context"]["workspaceId"], json!("team-2"));
    assert_eq!(other["application"]["clientId"], json!("client-b"));
    assert_eq!(
        *resolver.callers.lock().unwrap(),
        ["client-a:subject-1", "client-b:subject-1"]
    );
    h.send(get("/bootstrap", Some(OWNER_TOKEN)))
        .await
        .failure(E::Forbidden);
    h.send(get("/bootstrap", None))
        .await
        .failure(E::Unauthenticated);
}

#[tokio::test]
async fn returns_no_context_for_an_unassigned_caller() {
    let (h, _) = bootstrap_harness(vec![31_337], false, vec![chain(31_337, None)]);
    h.send(get("/bootstrap", Some(CLIENT_TOKEN)))
        .await
        .failure(E::NotFound);
}

#[tokio::test]
async fn refuses_an_invalid_selected_chain_set() {
    for chain_ids in [vec![], vec![31_337, 31_337], vec![1]] {
        let (h, _) = bootstrap_harness(chain_ids, true, vec![chain(31_337, None)]);
        h.send(get("/bootstrap", Some(CLIENT_TOKEN)))
            .await
            .failure(E::Internal);
    }
}

#[tokio::test]
async fn refuses_to_construct_a_bootstrap_without_valid_chains() {
    for chains in [
        vec![],
        vec![chain(31_337, Some("0x01".into()))],
        vec![chain(31_337, None), chain(31_337, None)],
        vec![chain(0, None)],
    ] {
        let mut options = options(
            Arc::new(MemoryRelayStore::new()),
            TestClock::new(),
            TestKms::new(KmsMode::Reversible),
        );
        options.bootstrap = Some(BootstrapConfiguration {
            resolver: Arc::new(SelectingResolver {
                callers: Mutex::new(Vec::new()),
                chain_ids: vec![],
                assigned: true,
            }),
            chains,
        });
        assert_eq!(Relay::new(options).err(), Some(E::Internal));
    }
}
