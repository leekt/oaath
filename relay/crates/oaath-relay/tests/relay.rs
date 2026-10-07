//! The relay wire and the one-time code state machine, over the OAuth and
//! portal surfaces: route and body capture, failure projection, an
//! ambiguous commit, and a code that is released once, to its own client,
//! before it expires.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::Request;
use oaath_relay::error::{RelayErrorCode as E, RelayResult};
use oaath_relay::store::memory::MemoryRelayStore;
use oaath_relay::store::{RelayStore, RelayTransaction};
use oaath_relay::{Relay, link, oauth, policy, records, registry, session};
use serde_json::json;
use support::grant::{Root, root_key, sign_in};
use support::*;

fn form(path: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

#[track_caller]
fn oauth_error(reply: &Reply, status: u16, error: &str, code: E) {
    assert_eq!(reply.status, status, "body: {}", reply.body);
    assert_eq!(reply.body["error"], json!(error));
    assert_eq!(reply.body["error_code"], json!(code));
}

async fn client(h: &Harness) -> String {
    let reply = h
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Example dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    text(reply.ok(201), "client_id").to_owned()
}

/// A login transaction for `client_id`, approved by a fresh root: its code.
async fn approved_code(h: &Harness, client_id: &str) -> String {
    let challenge = code_challenge();
    let pushed = h
        .send(form(
            "/oauth/par",
            &[
                ("client_id", client_id),
                ("redirect_uri", REDIRECT_URI),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("scope", "openid"),
            ],
        ))
        .await;
    let id = text(pushed.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned();
    let (signer_id, cookie) = sign_in(h, &Root::Ecdsa(root_key())).await;
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&cookie),
            Some(json!({ "root_signer_id": signer_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    let decided = h
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            Some(&cookie),
            Some(json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] })),
        ))
        .await;
    url::Url::parse(text(decided.ok(200), "redirect"))
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned()
}

fn exchange(client_id: &str, code: &str, verifier: &str, redirect: &str) -> Request<Body> {
    form(
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect),
        ],
    )
}

#[tokio::test]
async fn burns_the_code_when_the_redirect_uri_does_not_match() {
    let h = harness();
    let client_id = client(&h).await;
    let code = approved_code(&h, &client_id).await;
    oauth_error(
        &h.send(exchange(
            &client_id,
            &code,
            CODE_VERIFIER,
            "https://app.example/other",
        ))
        .await,
        400,
        "invalid_grant",
        E::CodeInvalid,
    );
    oauth_error(
        &h.send(exchange(&client_id, &code, CODE_VERIFIER, REDIRECT_URI))
            .await,
        400,
        "invalid_grant",
        E::CodeAlreadyConsumed,
    );
}

#[tokio::test]
async fn hides_a_code_bound_to_another_client_without_burning_it() {
    let h = harness();
    let (owner, other) = (client(&h).await, client(&h).await);
    let code = approved_code(&h, &owner).await;
    oauth_error(
        &h.send(exchange(&other, &code, CODE_VERIFIER, REDIRECT_URI))
            .await,
        400,
        "invalid_grant",
        E::CodeInvalid,
    );
    // A guessed code reads exactly like another client's.
    oauth_error(
        &h.send(exchange(
            &owner,
            "guessed-code",
            CODE_VERIFIER,
            REDIRECT_URI,
        ))
        .await,
        400,
        "invalid_grant",
        E::CodeInvalid,
    );
    h.send(exchange(&owner, &code, CODE_VERIFIER, REDIRECT_URI))
        .await
        .ok(200);
}

#[tokio::test]
async fn refuses_an_expired_code() {
    let h = harness();
    let client_id = client(&h).await;
    let code = approved_code(&h, &client_id).await;
    h.clock.advance(60_000);
    oauth_error(
        &h.send(exchange(&client_id, &code, CODE_VERIFIER, REDIRECT_URI))
            .await,
        400,
        "invalid_grant",
        E::Expired,
    );
}

#[tokio::test]
async fn releases_exactly_one_of_concurrent_exchanges() {
    let h = harness();
    let client_id = client(&h).await;
    let code = approved_code(&h, &client_id).await;
    let (a, b, c) = tokio::join!(
        h.send(exchange(&client_id, &code, CODE_VERIFIER, REDIRECT_URI)),
        h.send(exchange(&client_id, &code, CODE_VERIFIER, REDIRECT_URI)),
        h.send(exchange(&client_id, &code, CODE_VERIFIER, REDIRECT_URI)),
    );
    let mut statuses = [a.status, b.status, c.status];
    statuses.sort();
    assert_eq!(statuses, [200, 400, 400]);
}

#[tokio::test]
async fn answers_only_structured_codes_for_routes_methods_and_paths() {
    let h = harness();
    for path in ["/", "/unknown", "/portal/unknown", "/oauth/unknown"] {
        let reply = h.send(get(path, None)).await;
        assert_eq!(reply.status, 404, "{path}");
    }
    h.send(get("/portal/signers", None))
        .await
        .failure(E::MethodNotAllowed);
    h.send(get("/portal/transactions/not%20canonical", None))
        .await
        .failure(E::RequestInvalid);
    oauth_error(
        &h.send(get("/oauth/par", None)).await,
        405,
        "invalid_request",
        E::MethodNotAllowed,
    );
}

fn raw(path: &str, content_type: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri(path);
    if let Some(content_type) = content_type {
        builder = builder.header("content-type", content_type);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

#[tokio::test]
async fn refuses_a_body_that_is_not_one_bounded_json_object() {
    let h = harness_with(|options| options.max_body_bytes = Some(64));
    for request in [
        raw("/portal/signers", None, "{}"),
        raw("/portal/signers", Some("text/plain"), "{}"),
        raw("/portal/signers", Some("application/json"), "[]"),
        raw("/portal/signers", Some("application/json"), "{"),
        raw(
            "/portal/signers",
            Some("application/json"),
            &format!("{{\"profile\":\"{}\"}}", "x".repeat(64)),
        ),
    ] {
        h.send(request).await.failure(E::RequestInvalid);
    }
}

#[tokio::test]
async fn projects_an_unavailable_kms_an_unreadable_clock_and_invalid_options() {
    let h = harness();
    let client_id = client(&h).await;
    let code = approved_code(&h, &client_id).await;
    // A clock that cannot be read stops every transition.
    h.clock.break_clock();
    oauth_error(
        &h.send(exchange(&client_id, &code, CODE_VERIFIER, REDIRECT_URI))
            .await,
        500,
        "server_error",
        E::Internal,
    );

    let failing = harness_on(
        Arc::new(MemoryRelayStore::new()),
        TestClock::new(),
        |options| options.kms = TestKms::new(KmsMode::Failing),
    );
    let client_id = client(&failing).await;
    let challenge = code_challenge();
    let pushed = failing
        .send(form(
            "/oauth/par",
            &[
                ("client_id", client_id.as_str()),
                ("redirect_uri", REDIRECT_URI),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("scope", "openid"),
            ],
        ))
        .await;
    let id = text(pushed.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned();
    let (signer_id, cookie) = sign_in(&failing, &Root::Ecdsa(root_key())).await;
    let account = failing
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&cookie),
            Some(json!({ "root_signer_id": signer_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    // The code cannot be sealed: nothing is decided.
    failing
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            Some(&cookie),
            Some(json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] })),
        ))
        .await
        .failure(E::KmsUnavailable);

    for configure in [
        |options: &mut oaath_relay::RelayOptions| options.code_ttl_ms = Some(600_001),
        |options: &mut oaath_relay::RelayOptions| options.request_ttl_ms = Some(0),
    ] {
        let mut options = options(
            Arc::new(MemoryRelayStore::new()),
            TestClock::new(),
            TestKms::new(KmsMode::Reversible),
        );
        configure(&mut options);
        assert!(Relay::new(options).is_err());
    }
}

/// A store whose commits never prove themselves: every transition rolls back
/// and reports `relay_state_ambiguous`.
struct AmbiguousStore {
    inner: MemoryRelayStore,
    begins: AtomicUsize,
}

struct AmbiguousTransaction(Box<dyn RelayTransaction>);

macro_rules! ambiguous_transaction {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {
        #[async_trait]
        impl RelayTransaction for AmbiguousTransaction {
            $(async fn $name(&mut self, $($arg: $ty),*) -> $out { self.0.$name($($arg),*).await })*

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
    lock_account(id: &str) -> RelayResult<Option<registry::AccountRecord>>;
    lock_account_by_address(address: &str) -> RelayResult<Option<registry::AccountRecord>>;
    lock_account_by_creation_key(root: &str, key: &str) -> RelayResult<Option<registry::AccountRecord>>;
    list_account_signers(id: &str) -> RelayResult<Vec<(registry::SignerRecord, registry::AccountSignerRecord)>>;
    delete_account_signers(account: &str, signer: &str) -> RelayResult<bool>;
    set_account_signer_status(account: &str, signer: &str, status: registry::MembershipStatus, at: u64) -> RelayResult<bool>;
    lock_pending_grant(id: &str) -> RelayResult<Option<oauth::pending::PendingGrantRecord>>;
    insert_pending_grant(r: &oauth::pending::PendingGrantRecord) -> RelayResult<bool>;
    decide_pending_grant(id: &str, o: oauth::pending::PendingOutcome, at: u64) -> RelayResult<bool>;
    list_pending_grants(id: &str) -> RelayResult<Vec<oauth::pending::PendingGrantRecord>>;
    lock_link_request(id: &str) -> RelayResult<Option<link::LinkRequestRecord>>;
    insert_link_request(r: &link::LinkRequestRecord) -> RelayResult<bool>;
    decide_link_request(id: &str, outcome: link::LinkOutcome, signature: Option<&str>, grant: Option<&str>, at: u64) -> RelayResult<bool>;
    list_policy_templates(id: &str) -> RelayResult<Vec<policy::PolicyTemplateRecord>>;
    lock_policy_template(id: &str) -> RelayResult<Option<policy::PolicyTemplateRecord>>;
    insert_policy_template(r: &policy::PolicyTemplateRecord) -> RelayResult<bool>;
    update_policy_template(r: &policy::PolicyTemplateRecord) -> RelayResult<bool>;
    delete_policy_template(id: &str) -> RelayResult<bool>;
    insert_account_import(r: &oaath_relay::account_import::AccountImportRecord) -> RelayResult<bool>;
    lock_account_import(id: &str) -> RelayResult<Option<oaath_relay::account_import::AccountImportRecord>>;
    remove_link_request(id: &str, at: u64) -> RelayResult<bool>;
    lock_oauth_client(id: &str) -> RelayResult<Option<oauth::records::OAuthClientRecord>>;
    insert_oauth_client(r: &oauth::records::OAuthClientRecord) -> RelayResult<bool>;
    lock_par(id: &str) -> RelayResult<Option<oauth::records::ParRecord>>;
    insert_par(r: &oauth::records::ParRecord) -> RelayResult<bool>;
    lock_access_token(hash: &str) -> RelayResult<Option<oauth::records::AccessTokenRecord>>;
    insert_access_token(r: &oauth::records::AccessTokenRecord) -> RelayResult<bool>;
    revoke_access_token(hash: &str, at: u64) -> RelayResult<bool>;
    lock_portal_challenge(nonce: &str) -> RelayResult<Option<session::PortalChallengeRecord>>;
    insert_portal_challenge(r: &session::PortalChallengeRecord) -> RelayResult<bool>;
    consume_portal_challenge(nonce: &str, at: u64) -> RelayResult<bool>;
    lock_portal_session(hash: &str) -> RelayResult<Option<session::PortalSessionRecord>>;
    insert_portal_session(r: &session::PortalSessionRecord) -> RelayResult<bool>;
    end_portal_session(hash: &str, at: u64) -> RelayResult<bool>;
}

#[async_trait]
impl RelayStore for AmbiguousStore {
    async fn begin(&self) -> RelayResult<Box<dyn RelayTransaction>> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(AmbiguousTransaction(self.inner.begin().await?)))
    }

    async fn close(&self) -> RelayResult<()> {
        self.inner.close().await
    }
}

#[tokio::test]
async fn projects_an_unproven_commit_to_500_without_retrying() {
    let store = Arc::new(AmbiguousStore {
        inner: MemoryRelayStore::new(),
        begins: AtomicUsize::new(0),
    });
    let h = harness_on(store.clone(), TestClock::new(), |_| {});
    let reply = h
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Example dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    oauth_error(&reply, 500, "server_error", E::StateAmbiguous);
    assert_eq!(store.begins.load(Ordering::SeqCst), 1);
    h.send(post(
        "/portal/signers",
        None,
        Some(json!({ "profile": Root::Ecdsa(root_key()).profile() })),
    ))
    .await
    .failure(E::StateAmbiguous);
    assert_eq!(store.begins.load(Ordering::SeqCst), 2);
}
