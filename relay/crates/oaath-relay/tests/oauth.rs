//! OAuth 2.0 / OpenID Connect login over the memory store: client
//! registration, PAR, the portal decision, redirect recovery, and the PKCE
//! token exchange, with the id_token verified by a stock JWT library against
//! the published JWKS.

mod support;

use axum::body::Body;
use axum::http::Request;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::*;
use url::Url;

const STATE: &str = "state-1";
const NONCE: &str = "nonce-1";

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

async fn register_client(h: &Harness) -> String {
    let reply = h
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Example dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    let body = reply.ok(201);
    assert_eq!(body["redirect_uris"], json!([REDIRECT_URI]));
    assert_eq!(body["token_endpoint_auth_method"], json!("none"));
    text(body, "client_id").to_owned()
}

fn par_pairs<'a>(client_id: &'a str, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("response_type", "code"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("scope", "openid"),
        ("state", STATE),
        ("nonce", NONCE),
    ]
}

/// Registers a client and pushes a login request; answers the client id and
/// the transaction id carried by the request_uri.
async fn push(h: &Harness) -> (String, String) {
    let client_id = register_client(h).await;
    let challenge = code_challenge();
    let reply = h
        .send(form("/oauth/par", &par_pairs(&client_id, &challenge)))
        .await;
    let body = reply.ok(201);
    assert_eq!(body["expires_in"], json!(300));
    let id = text(body, "request_uri")
        .strip_prefix("urn:ietf:params:oauth:request_uri:")
        .unwrap()
        .to_owned();
    (client_id, id)
}

/// A registered ECDSA signer and its first account.
async fn signer_and_account(h: &Harness, address: &str) -> (String, Value) {
    let profile = json!({
        "version": "oaath.owner-credential-profile/v1",
        "kind": "ecdsa",
        "address": address,
    });
    let signer = h
        .send(post(
            "/portal/signers",
            None,
            Some(json!({ "profile": profile })),
        ))
        .await;
    let signer_id = text(signer.ok(200), "signer_id").to_owned();
    let account = h
        .send(post(
            "/portal/accounts",
            None,
            Some(json!({ "root_signer_id": signer_id })),
        ))
        .await
        .ok(201)
        .clone();
    (signer_id, account)
}

async fn decide(h: &Harness, id: &str, body: Value) -> Reply {
    h.send(post(
        &format!("/portal/transactions/{id}/decision"),
        None,
        Some(body),
    ))
    .await
}

fn query(redirect: &str) -> Vec<(String, String)> {
    Url::parse(redirect)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

async fn token(h: &Harness, client_id: &str, code: &str, verifier: &str) -> Reply {
    h.send(form(
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", REDIRECT_URI),
        ],
    ))
    .await
}

/// PAR, an approved decision, and its code.
async fn approved_code(h: &Harness) -> (String, String, String, Value, String) {
    let (client_id, id) = push(h).await;
    let (signer_id, account) =
        signer_and_account(h, "0x1111111111111111111111111111111111111111").await;
    let reply = decide(
        h,
        &id,
        json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] }),
    )
    .await;
    let redirect = text(reply.ok(200), "redirect").to_owned();
    let code = query(&redirect)
        .into_iter()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1;
    (client_id, id, signer_id, account, code)
}

#[tokio::test]
async fn logs_in_and_issues_a_verifiable_id_token() {
    let h = harness();
    let discovery = h
        .send(get("/.well-known/openid-configuration", None))
        .await
        .ok(200)
        .clone();
    assert_eq!(discovery["issuer"], json!(ISSUER));
    assert_eq!(discovery["jwks_uri"], json!(format!("{ISSUER}/oauth/jwks")));

    let (client_id, id) = push(&h).await;
    let (signer_id, account) =
        signer_and_account(&h, "0x1111111111111111111111111111111111111111").await;
    let transaction = h
        .send(get(&format!("/portal/transactions/{id}"), None))
        .await
        .ok(200)
        .clone();
    assert_eq!(
        transaction,
        json!({
            "transaction_id": id,
            "client_id": client_id,
            "client_name": "Example dapp",
            "redirect_origin": "https://app.example",
            "authorization_details": [],
            "expires_at": CLOCK_SECONDS + 300,
        })
    );

    let decided = decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] }),
    )
    .await
    .ok(200)
    .clone();
    let redirect = text(&decided, "redirect");
    assert!(redirect.starts_with(&format!("{REDIRECT_URI}?code=")));
    let params = query(redirect);
    let keys: Vec<&str> = params.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(keys, ["code", "state", "iss"]);
    assert_eq!(params[1].1, STATE);
    assert_eq!(params[2].1, ISSUER);

    let response = token(&h, &client_id, &params[0].1, CODE_VERIFIER)
        .await
        .ok(200)
        .clone();
    assert_eq!(response["token_type"], json!("Bearer"));
    assert_eq!(response["scope"], json!("openid"));
    assert_eq!(text(&response, "access_token").len(), 43);

    // A stock JWT library, with only the published JWKS.
    let jwks: JwkSet =
        serde_json::from_value(h.send(get("/oauth/jwks", None)).await.ok(200).clone()).unwrap();
    let id_token = text(&response, "id_token");
    let header = jsonwebtoken::decode_header(id_token).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some(ID_TOKEN_KID));
    let key = DecodingKey::from_jwk(jwks.find(ID_TOKEN_KID).unwrap()).unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[&client_id]);
    validation.set_issuer(&[ISSUER]);
    // The test clock is in 2023; expiry is checked against it below.
    validation.validate_exp = false;
    let claims = decode::<Value>(id_token, &key, &validation).unwrap().claims;
    assert_eq!(claims["sub"], account["address"]);
    assert_eq!(claims["aud"], json!(client_id));
    assert_eq!(claims["azp"], json!(client_id));
    assert_eq!(claims["nonce"], json!(NONCE));
    assert_eq!(claims["verified"], json!(false));
    assert_eq!(claims["iat"], json!(CLOCK_SECONDS));
    assert_eq!(claims["exp"], json!(CLOCK_SECONDS + 600));
    assert_eq!(claims["oaath_account"], account["profile"]);
    assert_eq!(claims["signer"]["id"], json!(signer_id));
    assert_eq!(claims["signer"]["kind"], json!("ecdsa"));
    assert_eq!(
        claims["signer"]["profile"],
        account["profile"]["ownerCredential"]
    );

    // Another key's JWKS never verifies it.
    use p256::pkcs8::EncodePrivateKey;
    let other_pem = p256::SecretKey::from_slice(&[8u8; 32])
        .unwrap()
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let other =
        oaath_relay::oauth::id_token::IdTokenKey::from_pkcs8_pem(Some(ID_TOKEN_KID), &other_pem)
            .unwrap();
    let other: JwkSet = serde_json::from_value(other.jwks().clone()).unwrap();
    let other = DecodingKey::from_jwk(&other.keys[0]).unwrap();
    assert!(decode::<Value>(id_token, &other, &validation).is_err());
}

#[tokio::test]
async fn burns_the_code_on_a_wrong_verifier_and_refuses_a_second_exchange() {
    let h = harness();
    let (client_id, _, _, _, code) = approved_code(&h).await;
    let wrong = format!("{}Z", &CODE_VERIFIER[..42]);
    oauth_error(
        &token(&h, &client_id, &code, &wrong).await,
        400,
        "invalid_grant",
        E::CodeInvalid,
    );
    oauth_error(
        &token(&h, &client_id, &code, CODE_VERIFIER).await,
        400,
        "invalid_grant",
        E::CodeAlreadyConsumed,
    );

    let (client_id, _, _, _, code) = approved_code(&h).await;
    token(&h, &client_id, &code, CODE_VERIFIER).await.ok(200);
    oauth_error(
        &token(&h, &client_id, &code, CODE_VERIFIER).await,
        400,
        "invalid_grant",
        E::CodeAlreadyConsumed,
    );
    oauth_error(
        &token(&h, "unknown-client", &code, CODE_VERIFIER).await,
        401,
        "invalid_client",
        E::NotFound,
    );
}

#[tokio::test]
async fn recovers_the_same_code_after_a_lost_decision_reply() {
    let h = harness();
    let (client_id, id, signer_id, account, code) = approved_code(&h).await;
    let recovered = h
        .send(get(&format!("/portal/transactions/{id}/redirect"), None))
        .await
        .ok(200)
        .clone();
    assert_eq!(query(text(&recovered, "redirect"))[0].1, code);
    decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] }),
    )
    .await
    .failure(E::AlreadyDecided);
    token(&h, &client_id, &code, CODE_VERIFIER).await.ok(200);
}

#[tokio::test]
async fn refuses_an_expired_transaction() {
    let h = harness();
    let (_, id) = push(&h).await;
    let (signer_id, account) =
        signer_and_account(&h, "0x1111111111111111111111111111111111111111").await;
    h.clock.advance(300_000);
    h.send(get(&format!("/portal/transactions/{id}"), None))
        .await
        .failure(E::Expired);
    decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] }),
    )
    .await
    .failure(E::Expired);
    h.send(get(&format!("/portal/transactions/{id}/redirect"), None))
        .await
        .failure(E::Expired);
}

#[tokio::test]
async fn refuses_a_signer_that_is_not_a_member_of_the_account() {
    let h = harness();
    let (_, id) = push(&h).await;
    let (_, account) = signer_and_account(&h, "0x1111111111111111111111111111111111111111").await;
    let (stranger, _) = signer_and_account(&h, "0x2222222222222222222222222222222222222222").await;
    decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": stranger, "account_id": account["account_id"] }),
    )
    .await
    .failure(E::Forbidden);
    // A refused decision decided nothing.
    h.send(get(&format!("/portal/transactions/{id}/redirect"), None))
        .await
        .failure(E::NotFound);
}

#[tokio::test]
async fn cancels_with_access_denied_and_no_code() {
    let h = harness();
    let (_, id) = push(&h).await;
    let reply = decide(&h, &id, json!({ "outcome": "cancelled" })).await;
    let redirect = text(reply.ok(200), "redirect").to_owned();
    assert_eq!(
        query(&redirect),
        [
            ("error".to_owned(), "access_denied".to_owned()),
            ("state".to_owned(), STATE.to_owned()),
            ("iss".to_owned(), ISSUER.to_owned()),
        ]
    );
    let recovered = h
        .send(get(&format!("/portal/transactions/{id}/redirect"), None))
        .await;
    assert_eq!(recovered.ok(200)["redirect"], json!(redirect));
    for body in [
        json!({ "outcome": "cancelled", "signer_id": "a" }),
        json!({ "outcome": "approved", "signer_id": "a" }),
        json!({ "outcome": "approve" }),
    ] {
        decide(&h, &id, body).await.failure(E::RequestInvalid);
    }
    decide(&h, &id, json!({ "outcome": "cancelled" }))
        .await
        .failure(E::AlreadyDecided);
}

#[tokio::test]
async fn refuses_malformed_registrations_and_pushed_requests() {
    let h = harness();
    for (body, error) in [
        (
            json!({ "client_name": "x", "redirect_uris": ["http://app.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "client_name": "x", "redirect_uris": [] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "client_name": "x", "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "private_key_jwt" }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [REDIRECT_URI] }),
            "invalid_client_metadata",
        ),
    ] {
        oauth_error(
            &h.send(post("/oauth/clients", None, Some(body))).await,
            400,
            error,
            E::RequestInvalid,
        );
    }

    let client_id = register_client(&h).await;
    let challenge = code_challenge();
    let with = |key: &'static str, value: &'static str| {
        let mut pairs = par_pairs(&client_id, &challenge);
        pairs.retain(|(name, _)| *name != key);
        pairs.push((key, value));
        pairs
    };
    let cases = [
        (
            with("redirect_uri", "https://attacker.example/callback"),
            400,
            "invalid_request",
            E::Forbidden,
        ),
        (
            with("scope", "profile"),
            400,
            "invalid_scope",
            E::RequestInvalid,
        ),
        (
            with("code_challenge_method", "plain"),
            400,
            "invalid_request",
            E::RequestInvalid,
        ),
        (
            with("response_type", "token"),
            400,
            "unsupported_response_type",
            E::RequestInvalid,
        ),
        (
            with("client_id", "unknown-client"),
            401,
            "invalid_client",
            E::NotFound,
        ),
        (
            with("authorization_details", "[]"),
            400,
            "invalid_authorization_details",
            E::RequestInvalid,
        ),
    ];
    for (pairs, status, error, code) in cases {
        oauth_error(
            &h.send(form("/oauth/par", &pairs)).await,
            status,
            error,
            code,
        );
    }
    let mut repeated = par_pairs(&client_id, &challenge);
    repeated.push(("state", "again"));
    oauth_error(
        &h.send(form("/oauth/par", &repeated)).await,
        400,
        "invalid_request",
        E::RequestInvalid,
    );
}

#[tokio::test]
async fn composes_the_production_relay_without_a_dev_config() {
    use std::sync::Arc;
    let kms = TestKms::new(KmsMode::Reversible);
    let clock = TestClock::new();
    let store: Arc<dyn oaath_relay::store::RelayStore> =
        Arc::new(oaath_relay::store::memory::MemoryRelayStore::new());
    let options = oaath_relay::config::compose(
        store.clone(),
        kms.clone(),
        clock.clone(),
        Some(oaath_relay::oauth::OAuthConfiguration {
            issuer: ISSUER.to_owned(),
            key: oaath_relay::oauth::id_token::IdTokenKey::from_pkcs8_pem(None, &id_token_pem())
                .unwrap(),
        }),
        None,
    );
    let h = Harness {
        relay: Arc::new(oaath_relay::Relay::new(options).unwrap()),
        store,
        clock,
        kms,
    };
    // The legacy, caller-authenticated routes refuse with 401.
    for request in [
        post(
            "/authorization/requests",
            Some(CLIENT_TOKEN),
            Some(json!({})),
        ),
        get("/authorization/requests/some-id", Some(OWNER_TOKEN)),
        get("/bootstrap", Some(CLIENT_TOKEN)),
        post("/grants/verify", Some(CLIENT_TOKEN), Some(json!({}))),
        post("/invalidations", Some(CLIENT_TOKEN), Some(json!({}))),
    ] {
        h.send(request).await.failure(E::Unauthenticated);
    }
    // The login flow needs no caller.
    let (client_id, _, _, _, code) = approved_code(&h).await;
    token(&h, &client_id, &code, CODE_VERIFIER).await.ok(200);
}
