//! PostgreSQL store and process-restart proofs
//! (ported from `packages/server/test/{postgres,restart}.test.ts`).
//!
//! Every step recreates the pool, store, and relay, so the durable rows alone
//! decide what may still happen. Requires `OAATH_TEST_POSTGRES=1` and
//! `OAATH_TEST_POSTGRES_URL`; `relay/scripts/test-postgres.sh` provides both
//! with a throwaway cluster. Skipped otherwise.

mod support;

use std::sync::Arc;

use oaath_relay::error::RelayErrorCode as E;
use oaath_relay::registry::{
    ACCOUNT_SIGNER_RECORD_VERSION, AccountSignerRecord, MembershipRole, MembershipStatus,
};
use oaath_relay::store::RelayStore;
use oaath_relay::store::postgres::{PostgresRelayStore, create_relay_schema};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use support::*;

fn database() -> Option<String> {
    if std::env::var("OAATH_TEST_POSTGRES").as_deref() != Ok("1") {
        eprintln!("skipped: set OAATH_TEST_POSTGRES=1 (relay/scripts/test-postgres.sh)");
        return None;
    }
    Some(std::env::var("OAATH_TEST_POSTGRES_URL").expect("OAATH_TEST_POSTGRES_URL"))
}

/// One disposable schema per test, selected through `search_path`.
struct Fixture {
    url: String,
    schema: String,
}

impl Fixture {
    async fn create(url: String) -> Self {
        let schema = format!(
            "oaath_test_{}",
            oaath_relay::authorization::challenge::random_identifier()
                .to_ascii_lowercase()
                .replace(['-', '_'], "")
                .chars()
                .take(16)
                .collect::<String>()
        );
        let admin = PgPool::connect(&url).await.expect("admin pool");
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("schema");
        admin.close().await;
        let fixture = Self { url, schema };
        let pool = fixture.pool().await;
        create_relay_schema(&pool).await.expect("relay schema");
        pool.close().await;
        fixture
    }

    async fn pool(&self) -> PgPool {
        let options: PgConnectOptions = self.url.parse().expect("url");
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options.options([("search_path", self.schema.as_str())]))
            .await
            .expect("pool")
    }

    /// A fresh process: new pool, store, and relay over the same rows.
    async fn process(&self, clock: Arc<TestClock>) -> Harness {
        let store: Arc<dyn RelayStore> = Arc::new(PostgresRelayStore::owning(self.pool().await));
        harness_on(store, clock, |_| {})
    }
}

async fn shutdown(h: Harness) {
    h.store.close().await.unwrap();
}

#[tokio::test]
async fn refuses_to_create_the_schema_over_existing_objects() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let pool = fixture.pool().await;
    assert!(create_relay_schema(&pool).await.is_err());
    let version: String =
        sqlx::query_scalar("SELECT version FROM oaath_relay_schema_v1 WHERE schema_id = 'oaath'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(version, "oaath.relay-postgres-schema/v1");
    pool.close().await;
}

#[tokio::test]
async fn projects_an_unreachable_database_to_store_unavailable() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let pool = fixture.pool().await;
    let store: Arc<dyn RelayStore> = Arc::new(PostgresRelayStore::borrowing(pool.clone()));
    let h = harness_on(store, TestClock::new(), |_| {});
    pool.close().await;
    h.send(post(
        "/portal/signers",
        None,
        Some(json!({ "profile": ecdsa_profile() })),
    ))
    .await
    .failure(E::StoreUnavailable);
}

fn portal_request(
    method: &str,
    path: &str,
    body: Option<Value>,
) -> axum::http::Request<axum::body::Body> {
    portal_as(method, path, None, body)
}

fn portal_as(
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> axum::http::Request<axum::body::Body> {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string())),
        None => builder.body(axum::body::Body::empty()),
    }
    .unwrap()
}

fn ecdsa_profile() -> Value {
    json!({
        "version": "oaath.owner-credential-profile/v1",
        "kind": "ecdsa",
        "address": "0x1111111111111111111111111111111111111111",
    })
}

async fn register(h: &Harness, profile: Value) -> String {
    let reply = h
        .send(portal_request(
            "POST",
            "/portal/signers",
            Some(json!({ "profile": profile })),
        ))
        .await;
    text(reply.ok(200), "signer_id").to_owned()
}

/// Creates an account in the signer's own session (setup: the fixture signer
/// has no key; sign-in is proven below and in `session.rs`).
async fn create_account(h: &Harness, signer_id: &str) -> Reply {
    let cookie = h.session_for(signer_id).await;
    h.send(portal_as(
        "POST",
        "/portal/accounts",
        Some(&cookie),
        Some(json!({ "root_signer_id": signer_id, "creation_key": creation_key() })),
    ))
    .await
}

async fn signer_accounts(h: &Harness, signer_id: &str) -> Reply {
    let cookie = h.session_for(signer_id).await;
    h.send(portal_as(
        "GET",
        &format!("/portal/signers/{signer_id}/accounts"),
        Some(&cookie),
        None,
    ))
    .await
}

#[tokio::test]
async fn keeps_signers_and_accounts_across_restarts() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let first = fixture.process(clock.clone()).await;
    let signer = register(&first, ecdsa_profile()).await;
    let account = create_account(&first, &signer).await.ok(201).clone();
    shutdown(first).await;

    // A new process answers the same signer and allocates the next index.
    let second = fixture.process(clock.clone()).await;
    assert_eq!(register(&second, ecdsa_profile()).await, signer);
    clock.advance(1);
    let next = create_account(&second, &signer).await.ok(201).clone();
    assert_eq!(next["profile"]["accountIndex"], json!("1"));
    shutdown(second).await;

    let third = fixture.process(clock).await;
    let listed = signer_accounts(&third, &signer).await.ok(200).clone();
    let ids: Vec<&Value> = listed["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| &entry["account_id"])
        .collect();
    assert_eq!(ids, [&account["account_id"], &next["account_id"]]);
    assert_eq!(listed["accounts"][0]["address"], account["address"]);
    assert_eq!(listed["accounts"][0]["role"], json!("root"));
    shutdown(third).await;
}

#[tokio::test]
async fn allocates_distinct_indices_across_independent_connections() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let processes = [
        fixture.process(clock.clone()).await,
        fixture.process(clock.clone()).await,
        fixture.process(clock.clone()).await,
    ];
    // Concurrent registrations of one profile converge on one signer.
    let (a, b, c) = tokio::join!(
        register(&processes[0], ecdsa_profile()),
        register(&processes[1], ecdsa_profile()),
        register(&processes[2], ecdsa_profile()),
    );
    assert!(a == b && b == c);
    let (x, y, z) = tokio::join!(
        create_account(&processes[0], &a),
        create_account(&processes[1], &a),
        create_account(&processes[2], &a),
    );
    let mut indices: Vec<String> = [x, y, z]
        .iter()
        .map(|reply| {
            reply.ok(201)["profile"]["accountIndex"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    indices.sort();
    assert_eq!(indices, ["0", "1", "2"]);
    for process in processes {
        shutdown(process).await;
    }
}

#[tokio::test]
async fn refuses_a_second_root_and_a_membership_on_an_unknown_account() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let h = fixture.process(clock.clone()).await;
    let root = register(&h, ecdsa_profile()).await;
    let other = register(
        &h,
        json!({
            "version": "oaath.owner-credential-profile/v1",
            "kind": "ecdsa",
            "address": "0x2222222222222222222222222222222222222222",
        }),
    )
    .await;
    let account = create_account(&h, &root).await.ok(201).clone();
    shutdown(h).await;

    let membership =
        |account_id: &str, role: MembershipRole, request_id: Option<&str>| AccountSignerRecord {
            version: ACCOUNT_SIGNER_RECORD_VERSION,
            account_id: account_id.to_owned(),
            signer_id: other.clone(),
            role,
            request_id: request_id.map(str::to_owned),
            link_id: None,
            created_at: CLOCK_START,
            status: MembershipStatus::Active,
            suspended_at: None,
            restored_at: None,
        };
    let h = fixture.process(clock.clone()).await;
    let mut transaction = h.store.begin().await.unwrap();
    let account_id = text(&account, "account_id");
    assert!(
        !transaction
            .insert_account_signer(&membership(account_id, MembershipRole::Root, None))
            .await
            .unwrap()
    );
    assert!(
        !transaction
            .insert_account_signer(&membership("unknown-account", MembershipRole::Root, None))
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
    shutdown(h).await;

    // The partial unique index itself refuses a second root, without the
    // guarded insert.
    let pool = fixture.pool().await;
    let inserted = sqlx::query(
        "INSERT INTO oaath_account_signer_v1 \
         (account_id, signer_id, record_version, role, request_id, created_at, status) \
         VALUES ($1, $2, $3, 'root', NULL, 0, 'active')",
    )
    .bind(account_id)
    .bind(&other)
    .bind(ACCOUNT_SIGNER_RECORD_VERSION)
    .execute(&pool)
    .await;
    assert!(inserted.is_err());
    pool.close().await;
}

#[tokio::test]
async fn reads_a_tampered_account_address_or_validator_as_unreadable() {
    let Some(url) = database() else { return };
    for tamper in [
        format!(
            "UPDATE oaath_account_v1 SET address = '0x{}'",
            "99".repeat(20)
        ),
        "UPDATE oaath_account_v1 SET owner_validator = NULL".to_owned(),
        format!(
            "UPDATE oaath_account_v1 SET owner_validator = '0x{}'",
            "22".repeat(20)
        ),
    ] {
        let fixture = Fixture::create(url.clone()).await;
        let h = fixture.process(TestClock::new()).await;
        let signer = register(&h, ecdsa_profile()).await;
        create_account(&h, &signer).await.ok(201);
        let pool = fixture.pool().await;
        sqlx::raw_sql(&tamper).execute(&pool).await.unwrap();
        pool.close().await;
        signer_accounts(&h, &signer)
            .await
            .failure(E::RecordUnreadable);
        shutdown(h).await;
    }
}

#[tokio::test]
async fn recognises_a_passkey_by_credential_id_across_a_restart() {
    use base64::Engine;
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let credential_id = b"credential-1";
    let profile = json!({
        "version": "oaath.owner-credential-profile/v1",
        "kind": "webauthn",
        "publicKey": "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "authenticatorIdHash": format!(
            "0x{}",
            hex::encode(alloy_primitives::keccak256(credential_id))
        ),
    });
    let first = fixture.process(clock.clone()).await;
    let signer = register(&first, profile.clone()).await;
    shutdown(first).await;

    let second = fixture.process(clock).await;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id);
    let found = second
        .send(portal_request(
            "GET",
            &format!("/portal/signers/by-credential/{encoded}"),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(
        found,
        json!({ "signer_id": signer, "kind": "webauthn", "profile": profile })
    );
    shutdown(second).await;
}

fn oauth_form(path: &str, pairs: &[(&str, &str)]) -> axum::http::Request<axum::body::Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn redirect_code(reply: &Reply) -> String {
    url::Url::parse(text(reply.ok(200), "redirect"))
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned()
}

#[tokio::test]
async fn keeps_a_login_transaction_and_its_code_across_restarts() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();

    let first = fixture.process(clock.clone()).await;
    let client = first
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Example dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    let client_id = text(client.ok(201), "client_id").to_owned();
    let challenge = code_challenge();
    let pushed = first
        .send(oauth_form(
            "/oauth/par",
            &[
                ("client_id", &client_id),
                ("redirect_uri", REDIRECT_URI),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("scope", "openid"),
                ("state", "state-1"),
            ],
        ))
        .await;
    let id = text(pushed.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned();
    let signer = register(&first, ecdsa_profile()).await;
    let account = create_account(&first, &signer).await.ok(201).clone();
    shutdown(first).await;

    let second = fixture.process(clock.clone()).await;
    let read = second
        .send(portal_request(
            "GET",
            &format!("/portal/transactions/{id}"),
            None,
        ))
        .await;
    assert_eq!(read.ok(200)["client_id"], json!(client_id));
    let cookie = second.session_for(&signer).await;
    let decided = second
        .send(portal_as(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            Some(&cookie),
            Some(json!({ "outcome": "approved", "signer_id": signer, "account_id": account["account_id"] })),
        ))
        .await;
    let code = redirect_code(&decided);
    shutdown(second).await;

    let third = fixture.process(clock.clone()).await;
    let recovered = third
        .send(portal_request(
            "GET",
            &format!("/portal/transactions/{id}/redirect"),
            None,
        ))
        .await;
    assert_eq!(redirect_code(&recovered), code);
    let exchange = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id.as_str()),
        ("code", code.as_str()),
        ("code_verifier", CODE_VERIFIER),
        ("redirect_uri", REDIRECT_URI),
    ];
    let tokens = third.send(oauth_form("/oauth/token", &exchange)).await;
    assert!(tokens.ok(200)["id_token"].is_string());
    shutdown(third).await;

    let last = fixture.process(clock).await;
    let replay = last.send(oauth_form("/oauth/token", &exchange)).await;
    assert_eq!(replay.status, 400);
    assert_eq!(
        replay.body["error_code"],
        json!("relay_code_already_consumed")
    );
    shutdown(last).await;
}

#[tokio::test]
async fn keeps_a_grant_transaction_preparable_across_a_restart() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let first = fixture.process(clock.clone()).await;
    let client = first
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    let client_id = text(client.ok(201), "client_id").to_owned();
    let detail = json!([{
        "type": "oaath_grant",
        "signer": {
            "version": "oaath.operator-credential-profile/v1",
            "kind": "ecdsa",
            "address": format!("0x{}", "44".repeat(20)),
        },
        "policy": {
            "version": "oaath.grant-policy/v1",
            "calls": [{
                "target": format!("0x{}", "aa".repeat(20)),
                "selector": "0xa9059cbb",
                "valueLimit": "0",
                "argumentEquals": [],
            }],
            "validAfter": CLOCK_SECONDS,
            "validUntil": CLOCK_SECONDS + 3_600,
            "perChainOperationLimit": { "count": 10, "intervalSeconds": null },
        },
        "chains": [1],
        "expires_at": CLOCK_SECONDS + 7_200,
        "device_id": "device-1",
    }])
    .to_string();
    let challenge = code_challenge();
    let pushed = first
        .send(oauth_form(
            "/oauth/par",
            &[
                ("client_id", &client_id),
                ("redirect_uri", REDIRECT_URI),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("scope", "openid"),
                ("authorization_details", &detail),
            ],
        ))
        .await;
    let id = text(pushed.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned();
    let signer = register(&first, ecdsa_profile()).await;
    let account = create_account(&first, &signer).await.ok(201).clone();
    shutdown(first).await;

    let second = fixture.process(clock).await;
    let read = second
        .send(portal_request(
            "GET",
            &format!("/portal/transactions/{id}"),
            None,
        ))
        .await;
    assert_eq!(read.ok(200)["authorization_details"].to_string(), detail);
    let cookie = second.session_for(&signer).await;
    let prepared = second
        .send(portal_as(
            "POST",
            &format!("/portal/transactions/{id}/prepare"),
            Some(&cookie),
            Some(json!({ "signer_id": signer, "account_id": account["account_id"] })),
        ))
        .await;
    assert_eq!(
        prepared.ok(200)["signing_request"]["signer"]["account"],
        account["address"]
    );
    shutdown(second).await;
}

fn bearer(
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> axum::http::Request<axum::body::Body> {
    let builder = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string())),
        None => builder.body(axum::body::Body::empty()),
    }
    .unwrap()
}

#[tokio::test]
async fn keeps_a_root_approved_grant_and_its_token_across_restarts() {
    use support::grant::{Root, approval, detail, root_key, sign_in};
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let root = Root::Ecdsa(root_key());

    let first = fixture.process(clock.clone()).await;
    let client = first
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    let client_id = text(client.ok(201), "client_id").to_owned();
    let challenge = code_challenge();
    let details = json!([detail()]).to_string();
    let pushed = first
        .send(oauth_form(
            "/oauth/par",
            &[
                ("client_id", &client_id),
                ("redirect_uri", REDIRECT_URI),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("scope", "openid"),
                ("authorization_details", &details),
            ],
        ))
        .await;
    let id = text(pushed.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned();
    let (signer, cookie) = sign_in(&first, &root).await;
    let account = first
        .send(portal_as(
            "POST",
            "/portal/accounts",
            Some(&cookie),
            Some(json!({ "root_signer_id": signer, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    let selection = json!({ "signer_id": signer, "account_id": account["account_id"] });
    let prepared = first
        .send(portal_as(
            "POST",
            &format!("/portal/transactions/{id}/prepare"),
            Some(&cookie),
            Some(selection),
        ))
        .await
        .ok(200)
        .clone();
    let artifact = approval(&prepared, &root);
    let decided = first
        .send(portal_as(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            Some(&cookie),
            Some(json!({
                "outcome": "approved",
                "signer_id": signer,
                "account_id": account["account_id"],
                "artifact": artifact.to_string(),
            })),
        ))
        .await;
    let code = redirect_code(&decided);
    shutdown(first).await;

    let second = fixture.process(clock.clone()).await;
    let tokens = second
        .send(oauth_form(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", client_id.as_str()),
                ("code", code.as_str()),
                ("code_verifier", CODE_VERIFIER),
                ("redirect_uri", REDIRECT_URI),
            ],
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(tokens["authorization_details"][0]["grant_id"], json!(id));
    let access = text(&tokens, "access_token").to_owned();
    shutdown(second).await;

    let third = fixture.process(clock.clone()).await;
    let path = format!("/oauth/grants/{id}");
    let view = third.send(bearer("GET", &path, &access, None)).await;
    assert_eq!(view.ok(200)["status"], json!("approved"));
    third
        .send(bearer(
            "POST",
            &format!("{path}/invalidate"),
            &access,
            Some(json!({ "capability_hash": artifact["capabilityHash"] })),
        ))
        .await
        .ok(200);
    shutdown(third).await;

    let fourth = fixture.process(clock.clone()).await;
    let view = fourth.send(bearer("GET", &path, &access, None)).await;
    assert_eq!(view.ok(200)["status"], json!("invalidated"));
    fourth
        .send(oauth_form(
            "/oauth/revoke",
            &[
                ("token", access.as_str()),
                ("client_id", client_id.as_str()),
            ],
        ))
        .await
        .ok(200);
    shutdown(fourth).await;

    let last = fixture.process(clock).await;
    assert_eq!(
        last.send(bearer("GET", &path, &access, None)).await.status,
        401
    );
    shutdown(last).await;
}

async fn issue_challenge(h: &Harness, signer: &str) -> Value {
    h.send(portal_request(
        "POST",
        "/portal/sessions/challenge",
        Some(json!({ "signer_id": signer })),
    ))
    .await
    .ok(200)
    .clone()
}

async fn prove(h: &Harness, root: &support::grant::Root, signer: &str, issued: &Value) -> Reply {
    h.send(portal_request(
        "POST",
        "/portal/sessions",
        Some(json!({
            "signer_id": signer,
            "nonce": issued["nonce"],
            "signature": root.prove(issued),
        })),
    ))
    .await
}

async fn list_as(h: &Harness, signer: &str, cookie: &str) -> Reply {
    h.send(portal_as(
        "GET",
        &format!("/portal/signers/{signer}/accounts"),
        Some(cookie),
        None,
    ))
    .await
}

#[tokio::test]
async fn keeps_sessions_and_refuses_consumed_nonces_across_restarts() {
    use support::grant::{Root, sign_in};
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let root = Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x5a; 32]).unwrap());

    let first = fixture.process(clock.clone()).await;
    let (signer, cookie) = sign_in(&first, &root).await;
    let used = issue_challenge(&first, &signer).await;
    prove(&first, &root, &signer, &used).await.ok(200);
    let unused = issue_challenge(&first, &signer).await;
    shutdown(first).await;

    // A new process keeps the session and the nonce's consumption.
    let second = fixture.process(clock.clone()).await;
    list_as(&second, &signer, &cookie).await.ok(200);
    prove(&second, &root, &signer, &used)
        .await
        .failure(E::Unauthenticated);
    let fresh = prove(&second, &root, &signer, &unused).await;
    fresh.ok(200);
    let fresh = cookie_of(&fresh);
    second
        .send(portal_as("DELETE", "/portal/sessions", Some(&cookie), None))
        .await
        .ok(200);
    shutdown(second).await;

    // Sign-out and expiry are durable too.
    let third = fixture.process(clock.clone()).await;
    list_as(&third, &signer, &cookie)
        .await
        .failure(E::Unauthenticated);
    list_as(&third, &signer, &fresh).await.ok(200);
    clock.advance(oaath_relay::session::SESSION_TTL_MS);
    list_as(&third, &signer, &fresh)
        .await
        .failure(E::Unauthenticated);
    shutdown(third).await;
}

#[tokio::test]
async fn keeps_a_link_approval_single_use_and_its_removal_across_restarts() {
    use alloy_primitives::B256;
    use support::grant::{Root, root_key, sign_in};
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let root = Root::Ecdsa(root_key());
    let passkey = Root::WebAuthn(
        p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap(),
        b"second-device".to_vec(),
    );

    let h = fixture.process(clock.clone()).await;
    let (root_id, root_cookie) = sign_in(&h, &root).await;
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&root_cookie),
            Some(json!({ "root_signer_id": root_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    let account_id = text(&account, "account_id").to_owned();
    let (device_id, device_cookie) = sign_in(&h, &passkey).await;
    let link_id = text(
        h.send(portal_call(
            "POST",
            "/portal/links",
            Some(&device_cookie),
            Some(json!({
                "signer_id": device_id,
                "account": account["address"],
                "label": "Second device",
            })),
        ))
        .await
        .ok(201),
        "link_id",
    )
    .to_owned();
    shutdown(h).await;

    let link = |cookie: &str| {
        portal_call(
            "GET",
            &format!("/portal/links/{link_id}"),
            Some(cookie),
            None,
        )
    };
    let h = fixture.process(clock.clone()).await;
    let view = h.send(link(&root_cookie)).await.ok(200).clone();
    assert_eq!(view["status"], "pending");
    let digest: B256 = text(&view, "digest").parse().unwrap();
    let approval = json!({ "signature": format!("0x{}", hex::encode(root.sign(digest))) });
    let approve = || {
        portal_call(
            "POST",
            &format!("/portal/links/{link_id}/approve"),
            Some(&root_cookie),
            Some(approval.clone()),
        )
    };
    h.send(approve()).await.ok(200);
    shutdown(h).await;

    let accounts = || {
        portal_call(
            "GET",
            &format!("/portal/signers/{device_id}/accounts"),
            Some(&device_cookie),
            None,
        )
    };
    let h = fixture.process(clock.clone()).await;
    h.send(approve()).await.failure(E::AlreadyDecided);
    let mut approved = view.clone();
    approved["status"] = json!("approved");
    assert_eq!(h.send(link(&device_cookie)).await.ok(200), &approved);
    let listed = h.send(accounts()).await.ok(200).clone();
    assert_eq!(listed["accounts"][0]["account_id"], json!(account_id));
    assert_eq!(listed["accounts"][0]["role"], "permission");
    let status = |action: &str| {
        portal_call(
            "POST",
            &format!("/portal/accounts/{account_id}/members/{device_id}/{action}"),
            Some(&root_cookie),
            Some(json!({})),
        )
    };
    h.send(status("suspend")).await.ok(200);
    shutdown(h).await;

    // The suspension survives a restart, refuses a second suspension, and
    // restores once.
    let h = fixture.process(clock.clone()).await;
    assert_eq!(
        h.send(accounts()).await.ok(200)["accounts"][0]["status"],
        "suspended"
    );
    h.send(status("suspend")).await.failure(E::AlreadyDecided);
    h.send(status("restore")).await.ok(200);
    shutdown(h).await;
    let h = fixture.process(clock.clone()).await;
    assert_eq!(
        h.send(accounts()).await.ok(200)["accounts"][0]["status"],
        "active"
    );
    h.send(portal_call(
        "DELETE",
        &format!("/portal/accounts/{account_id}/members/{device_id}"),
        Some(&root_cookie),
        None,
    ))
    .await
    .ok(200);
    shutdown(h).await;

    let h = fixture.process(clock).await;
    assert_eq!(
        h.send(link(&root_cookie)).await.ok(200)["status"],
        "removed"
    );
    assert_eq!(h.send(accounts()).await.ok(200)["accounts"], json!([]));
    shutdown(h).await;
}

#[tokio::test]
async fn keeps_templates_and_a_template_approved_member_grant_across_restarts() {
    use support::grant::{Root, approval, root_key, sign_in};
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let root = Root::Ecdsa(root_key());
    let passkey = Root::WebAuthn(
        p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap(),
        b"second-device".to_vec(),
    );
    let template = json!({
        "name": "Payments",
        "lifetime_seconds": 3_600,
        "policy": {
            "calls": [{ "target": format!("0x{}", "aa".repeat(20)), "selector": "0xa9059cbb", "valueLimit": "0" }],
            "perChainOperationLimit": { "count": 3, "intervalSeconds": null },
        },
    });

    let h = fixture.process(clock.clone()).await;
    let (root_id, root_cookie) = sign_in(&h, &root).await;
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&root_cookie),
            Some(json!({ "root_signer_id": root_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    let policies = format!("/portal/accounts/{}/policies", text(&account, "account_id"));
    let created = h
        .send(portal_call(
            "POST",
            &policies,
            Some(&root_cookie),
            Some(template),
        ))
        .await
        .ok(201)
        .clone();
    let (member_id, member_cookie) = sign_in(&h, &passkey).await;
    let link_id = text(
        h.send(portal_call(
            "POST",
            "/portal/links",
            Some(&member_cookie),
            Some(
                json!({ "signer_id": member_id, "account": account["address"], "label": "Laptop" }),
            ),
        ))
        .await
        .ok(201),
        "link_id",
    )
    .to_owned();
    shutdown(h).await;

    let h = fixture.process(clock.clone()).await;
    let listed = h
        .send(portal_call("GET", &policies, Some(&root_cookie), None))
        .await
        .ok(200)
        .clone();
    assert_eq!(listed, json!({ "policies": [created] }));
    let selection = json!({ "template_id": created["template_id"] });
    let prepared = h
        .send(portal_call(
            "POST",
            &format!("/portal/links/{link_id}/prepare"),
            Some(&root_cookie),
            Some(selection),
        ))
        .await
        .ok(200)
        .clone();
    h.send(portal_call(
        "POST",
        &format!("/portal/links/{link_id}/approve"),
        Some(&root_cookie),
        Some(json!({
            "template_id": created["template_id"],
            "artifact": approval(&prepared, &root).to_string(),
        })),
    ))
    .await
    .ok(200);
    shutdown(h).await;

    let h = fixture.process(clock).await;
    let grant = h
        .send(portal_call(
            "GET",
            &format!("/portal/grants/{link_id}"),
            Some(&member_cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(grant["status"], "approved");
    assert_eq!(grant["permission_request"], prepared["permission_request"]);
    shutdown(h).await;
}

#[tokio::test]
async fn keeps_an_imported_account_and_refuses_its_second_import_across_restarts() {
    use alloy_primitives::{Address, B256};
    use oaath_relay::account_import::{AccountImport, import_digest};
    use support::grant::{Root, sign_in};
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let root = Root::P256(p256::ecdsa::SigningKey::from_slice(&[0x22; 32]).unwrap());
    let address = "0x00000000000000000000000000000000000000ab";
    let fingerprint = format!("0x{}", "22".repeat(32));

    let chain = support::chain::stub_chain(
        421_614,
        &[(
            address,
            support::chain::StubAccount::kernel(
                &oaath_protocol::identity::parse_owner_credential_profile(&root.profile()).unwrap(),
            ),
        )],
    )
    .await;
    let process = |clock: Arc<TestClock>| {
        let reader = chain.reader();
        async {
            let store: Arc<dyn RelayStore> =
                Arc::new(PostgresRelayStore::owning(fixture.pool().await));
            harness_on(store, clock, move |options| options.chain = Some(reader))
        }
    };
    let h = process(clock.clone()).await;
    let (signer_id, cookie) = sign_in(&h, &root).await;
    let digest = import_digest(&AccountImport {
        account: address.parse::<Address>().unwrap(),
        ownerProfileHash: oaath_protocol::identity::parse_owner_credential_profile(&root.profile())
            .unwrap()
            .hash(),
        inventoryFingerprint: fingerprint.parse::<B256>().unwrap(),
        issuedAt: CLOCK_SECONDS,
        nonce: "import-1".to_owned(),
    });
    let body = json!({
        "root_signer_id": signer_id,
        "address": address,
        "inventory_fingerprint": fingerprint,
        "issued_at": CLOCK_SECONDS,
        "nonce": "import-1",
        "signature": format!("0x{}", hex::encode(root.sign(digest))),
    });
    let import = || {
        portal_call(
            "POST",
            "/portal/accounts/import",
            Some(&cookie),
            Some(body.clone()),
        )
    };
    let imported = h.send(import()).await.ok(201).clone();
    shutdown(h).await;

    let h = process(clock).await;
    h.send(import()).await.failure(E::AlreadyDecided);
    let accounts = h
        .send(portal_call(
            "GET",
            &format!("/portal/signers/{signer_id}/accounts"),
            Some(&cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(accounts["accounts"][0]["profile"], imported["profile"]);
    let mut transaction = h.store.begin().await.unwrap();
    let evidence = transaction
        .lock_account_import(text(&imported, "account_id"))
        .await
        .unwrap()
        .unwrap();
    transaction.rollback().await;
    assert_eq!(evidence.inventory_fingerprint, fingerprint);
    shutdown(h).await;
}

/// A registered client's approved login code, decided by a fresh root.
async fn login_code(h: &Harness) -> (String, String, String) {
    let client = h
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Example dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    let client_id = text(client.ok(201), "client_id").to_owned();
    let challenge = code_challenge();
    let pushed = h
        .send(oauth_form(
            "/oauth/par",
            &[
                ("client_id", &client_id),
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
    let signer = register(h, ecdsa_profile()).await;
    let account = create_account(h, &signer).await.ok(201).clone();
    let cookie = h.session_for(&signer).await;
    let decided = h
        .send(portal_as(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            Some(&cookie),
            Some(json!({ "outcome": "approved", "signer_id": signer, "account_id": account["account_id"] })),
        ))
        .await;
    (client_id, id, redirect_code(&decided))
}

fn exchange(client_id: &str, code: &str) -> axum::http::Request<axum::body::Body> {
    oauth_form(
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("code_verifier", CODE_VERIFIER),
            ("redirect_uri", REDIRECT_URI),
        ],
    )
}

#[tokio::test]
async fn releases_exactly_one_token_exchange_across_independent_connections() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let first = fixture.process(clock.clone()).await;
    let second = fixture.process(clock.clone()).await;
    let third = fixture.process(clock).await;
    let (client_id, _, code) = login_code(&first).await;
    let (a, b, c) = tokio::join!(
        first.send(exchange(&client_id, &code)),
        second.send(exchange(&client_id, &code)),
        third.send(exchange(&client_id, &code)),
    );
    let mut statuses = [a.status, b.status, c.status];
    statuses.sort();
    assert_eq!(statuses, [200, 400, 400]);
    shutdown(first).await;
    shutdown(second).await;
    shutdown(third).await;
}

#[tokio::test]
async fn reads_a_row_of_another_record_version_as_unreadable() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let h = fixture.process(clock).await;
    let (client_id, request_id, code) = login_code(&h).await;
    let pool = fixture.pool().await;
    sqlx::query(
        "UPDATE oaath_relay_authorization_request_v1 SET record_version = $2 WHERE request_id = $1",
    )
    .bind(&request_id)
    .bind("oaath.authorization-request-record/v0")
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    let refused = h.send(exchange(&client_id, &code)).await;
    assert_eq!(refused.status, 500);
    assert_eq!(refused.body["error_code"], json!("relay_record_unreadable"));
    shutdown(h).await;
}

#[tokio::test]
async fn creates_one_account_for_concurrent_retries_of_one_key() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let first = fixture.process(clock.clone()).await;
    let second = fixture.process(clock.clone()).await;
    let signer = register(&first, ecdsa_profile()).await;
    let cookie = first.session_for(&signer).await;
    let create = || {
        portal_as(
            "POST",
            "/portal/accounts",
            Some(&cookie),
            Some(json!({ "root_signer_id": signer, "creation_key": "key-1" })),
        )
    };
    let (a, b) = tokio::join!(first.send(create()), second.send(create()));
    assert_eq!(a.ok(201), b.ok(201));
    let listed = signer_accounts(&first, &signer).await.ok(200).clone();
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 1);
    shutdown(first).await;
    shutdown(second).await;
}

#[tokio::test]
async fn keeps_a_member_grant_request_pending_across_restarts() {
    use support::grant::{Root, approval, detail, link_member, root_key, sign_in};
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let root = Root::Ecdsa(root_key());
    let member = Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x55; 32]).unwrap());
    let token = |client_id: &str, code: &str| {
        oauth_form(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", code),
                ("code_verifier", CODE_VERIFIER),
                ("redirect_uri", REDIRECT_URI),
            ],
        )
    };

    let h = fixture.process(clock.clone()).await;
    let (root_id, root_cookie) = sign_in(&h, &root).await;
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&root_cookie),
            Some(json!({ "root_signer_id": root_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    let (member_id, member_cookie) = sign_in(&h, &member).await;
    link_member(
        &h,
        text(&account, "address"),
        (&member_id, &member_cookie),
        (&root, &root_cookie),
    )
    .await;
    let client = h
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    let client_id = text(client.ok(201), "client_id").to_owned();
    let challenge = code_challenge();
    let details = json!([detail()]).to_string();
    let pushed = h
        .send(oauth_form(
            "/oauth/par",
            &[
                ("client_id", &client_id),
                ("redirect_uri", REDIRECT_URI),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("scope", "openid"),
                ("authorization_details", &details),
            ],
        ))
        .await;
    let id = text(pushed.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned();
    let code = redirect_code(
        &h.send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            Some(&member_cookie),
            Some(json!({
                "outcome": "request_approval",
                "signer_id": member_id,
                "account_id": account["account_id"],
            })),
        ))
        .await,
    );
    shutdown(h).await;

    let h = fixture.process(clock.clone()).await;
    let pending = h.send(token(&client_id, &code)).await;
    assert_eq!(pending.body["error"], json!("authorization_pending"));
    let path = format!("/portal/requests/{id}");
    let prepared = h
        .send(portal_call(
            "POST",
            &format!("{path}/prepare"),
            Some(&root_cookie),
            Some(json!({})),
        ))
        .await
        .ok(200)
        .clone();
    h.send(portal_call(
        "POST",
        &format!("{path}/approve"),
        Some(&root_cookie),
        Some(json!({ "artifact": approval(&prepared, &root).to_string() })),
    ))
    .await
    .ok(200);
    shutdown(h).await;

    let h = fixture.process(clock).await;
    let tokens = h.send(token(&client_id, &code)).await.ok(200).clone();
    assert_eq!(tokens["authorization_details"][0]["grant_id"], json!(id));
    let again = h.send(token(&client_id, &code)).await;
    assert_eq!(again.body["error"], json!("invalid_grant"));
    shutdown(h).await;
}
