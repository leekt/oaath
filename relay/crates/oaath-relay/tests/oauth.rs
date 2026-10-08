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
use support::grant;
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

/// A signed-in ECDSA signer (key `[seed; 32]`), its first account, and its
/// session cookie.
async fn signer_and_account(h: &Harness, seed: u8) -> (String, Value, String) {
    let root = grant::Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap());
    let (signer_id, cookie) = grant::sign_in(h, &root).await;
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
    (signer_id, account, cookie)
}

async fn decide(h: &Harness, id: &str, body: Value, cookie: Option<&str>) -> Reply {
    h.send(portal_call(
        "POST",
        &format!("/portal/transactions/{id}/decision"),
        cookie,
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
async fn approved_code(h: &Harness) -> (String, String, String, Value, String, String) {
    let (client_id, id) = push(h).await;
    let (signer_id, account, cookie) = signer_and_account(h, 0x11).await;
    let reply = decide(
        h,
        &id,
        json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] }),
        Some(&cookie),
    )
    .await;
    let redirect = text(reply.ok(200), "redirect").to_owned();
    let code = query(&redirect)
        .into_iter()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1;
    (client_id, id, signer_id, account, code, cookie)
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
    let (signer_id, account, cookie) = signer_and_account(&h, 0x11).await;
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
            "bound": null,
        })
    );

    let decided = decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] }),
        Some(&cookie),
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
    assert_eq!(claims["verified"], json!(true));
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
    let (client_id, _, _, _, code, _) = approved_code(&h).await;
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

    let (client_id, _, _, _, code, _) = approved_code(&h).await;
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
    let (client_id, id, signer_id, account, code, cookie) = approved_code(&h).await;
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
        Some(&cookie),
    )
    .await
    .failure(E::AlreadyDecided);
    token(&h, &client_id, &code, CODE_VERIFIER).await.ok(200);
}

#[tokio::test]
async fn refuses_an_expired_transaction() {
    let h = harness();
    let (_, id) = push(&h).await;
    let (signer_id, account, cookie) = signer_and_account(&h, 0x11).await;
    h.clock.advance(300_000);
    h.send(get(&format!("/portal/transactions/{id}"), None))
        .await
        .failure(E::Expired);
    decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] }),
        Some(&cookie),
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
    let (_, account, _) = signer_and_account(&h, 0x11).await;
    let (stranger, _, cookie) = signer_and_account(&h, 0x22).await;
    decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": stranger, "account_id": account["account_id"] }),
        Some(&cookie),
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
    let reply = decide(&h, &id, json!({ "outcome": "cancelled" }), None).await;
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
        decide(&h, &id, body, None).await.failure(E::RequestInvalid);
    }
    decide(&h, &id, json!({ "outcome": "cancelled" }), None)
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
async fn answers_not_found_for_the_retired_service_routes() {
    let h = harness();
    for request in [
        post("/authorization/requests", Some("token"), Some(json!({}))),
        get("/authorization/requests/some-id", Some("token")),
        post(
            "/authorization/requests/some-id/decision",
            Some("token"),
            Some(json!({})),
        ),
        post(
            "/authorization/codes/consume",
            Some("token"),
            Some(json!({})),
        ),
        post(
            "/authorization/artifacts/some-id/claim",
            Some("token"),
            None,
        ),
        post("/authorization/resume", Some("token"), Some(json!({}))),
        get("/bootstrap", Some("token")),
        post("/grants/verify", Some("token"), Some(json!({}))),
        post("/invalidations", Some("token"), Some(json!({}))),
        get("/session-signers", None),
        get("/chains/1/operations", None),
        get("/native/devices", None),
        post("/grants/g/revocations/1", None, Some(json!({}))),
    ] {
        h.send(request).await.failure(E::NotFound);
    }
    // The login flow needs no caller.
    let (client_id, _, _, _, code, _) = approved_code(&h).await;
    token(&h, &client_id, &code, CODE_VERIFIER).await.ok(200);
}

async fn member_status(
    h: &Harness,
    account: &Value,
    signer_id: &str,
    action: &str,
    cookie: &str,
) -> Reply {
    h.send(portal_call(
        "POST",
        &format!(
            "/portal/accounts/{}/members/{signer_id}/{action}",
            text(account, "account_id")
        ),
        Some(cookie),
        Some(json!({})),
    ))
    .await
}

async fn login(h: &Harness, signer_id: &str, account: &Value, cookie: &str) -> Reply {
    let (_, id) = push(h).await;
    decide(
        h,
        &id,
        json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] }),
        Some(cookie),
    )
    .await
}

/// The verified claims of the id_token a login decision's code redeems for.
async fn claims_after(h: &Harness, client_id: &str, decided: &Reply) -> Value {
    let redirect = text(decided.ok(200), "redirect").to_owned();
    let code = query(&redirect)
        .into_iter()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1;
    let response = token(h, client_id, &code, CODE_VERIFIER)
        .await
        .ok(200)
        .clone();
    let jwks: JwkSet =
        serde_json::from_value(h.send(get("/oauth/jwks", None)).await.ok(200).clone()).unwrap();
    let key = DecodingKey::from_jwk(jwks.find(ID_TOKEN_KID).unwrap()).unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[client_id]);
    validation.validate_exp = false;
    decode::<Value>(text(&response, "id_token"), &key, &validation)
        .unwrap()
        .claims
}

#[tokio::test]
async fn a_suspended_member_cannot_log_in_until_restored_and_the_claim_lists_active_accounts() {
    let h = harness();
    // Two accounts with their roots; a passkey member of both, which also owns
    // an account of its own.
    let root = grant::Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x11; 32]).unwrap());
    let (root_id, account, root_cookie) = signer_and_account(&h, 0x11).await;
    h.clock.advance(1);
    let other_root = grant::Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x12; 32]).unwrap());
    let (_, other, other_cookie) = signer_and_account(&h, 0x12).await;
    let passkey = grant::Root::WebAuthn(
        p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap(),
        b"member".to_vec(),
    );
    let (member_id, member_cookie) = grant::sign_in(&h, &passkey).await;
    h.clock.advance(1);
    let own = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&member_cookie),
            Some(json!({ "root_signer_id": member_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    for (address, root, cookie) in [
        (&account, &root, root_cookie.as_str()),
        (&other, &other_root, other_cookie.as_str()),
    ] {
        grant::link_member(
            &h,
            text(address, "address"),
            (&member_id, &member_cookie),
            (root, cookie),
        )
        .await;
    }

    // Active: it logs in as the account, and the claim lists all three.
    let (client_id, id) = push(&h).await;
    let decided = decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": member_id, "account_id": account["account_id"] }),
        Some(&member_cookie),
    )
    .await;
    let claims = claims_after(&h, &client_id, &decided).await;
    assert_eq!(claims["sub"], account["address"]);
    assert_eq!(
        claims["oaath_accounts"],
        json!([
            { "address": account["address"], "role": "permission", "status": "active" },
            { "address": other["address"], "role": "permission", "status": "active" },
            { "address": own["address"], "role": "root", "status": "active" },
        ])
    );

    // A code released before the suspension no longer redeems.
    let (early_client, early) = push(&h).await;
    let pending = decide(
        &h,
        &early,
        json!({ "outcome": "approved", "signer_id": member_id, "account_id": account["account_id"] }),
        Some(&member_cookie),
    )
    .await;
    let pending_code = query(text(pending.ok(200), "redirect"))
        .into_iter()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1;

    // Only the account's root suspends, never the root, and only once.
    member_status(&h, &account, &member_id, "suspend", &member_cookie)
        .await
        .failure(E::Forbidden);
    member_status(&h, &account, &member_id, "suspend", &other_cookie)
        .await
        .failure(E::Forbidden);
    member_status(&h, &account, &root_id, "suspend", &root_cookie)
        .await
        .failure(E::RequestInvalid);
    assert_eq!(
        member_status(&h, &account, &member_id, "suspend", &root_cookie)
            .await
            .ok(200),
        &json!({ "signer_id": member_id, "status": "suspended" })
    );
    member_status(&h, &account, &member_id, "suspend", &root_cookie)
        .await
        .failure(E::AlreadyDecided);
    member_status(&h, &other, &member_id, "restore", &other_cookie)
        .await
        .failure(E::AlreadyDecided);

    login(&h, &member_id, &account, &member_cookie)
        .await
        .failure(E::MembershipSuspended);
    oauth_error(
        &token(&h, &early_client, &pending_code, CODE_VERIFIER).await,
        400,
        "invalid_grant",
        E::MembershipSuspended,
    );
    // Its other memberships are unaffected; the claim omits the suspended one.
    let (client_id, id) = push(&h).await;
    let decided = decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": member_id, "account_id": other["account_id"] }),
        Some(&member_cookie),
    )
    .await;
    let claims = claims_after(&h, &client_id, &decided).await;
    assert_eq!(claims["sub"], other["address"]);
    assert_eq!(
        claims["oaath_accounts"],
        json!([
            { "address": other["address"], "role": "permission", "status": "active" },
            { "address": own["address"], "role": "root", "status": "active" },
        ])
    );
    let listed = h
        .send(portal_call(
            "GET",
            &format!("/portal/signers/{member_id}/accounts"),
            Some(&member_cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(listed["accounts"][0]["status"], json!("suspended"));

    // Restored, it logs in again.
    h.clock.advance(1);
    assert_eq!(
        member_status(&h, &account, &member_id, "restore", &root_cookie)
            .await
            .ok(200)["status"],
        json!("active")
    );
    let members = h
        .send(portal_call(
            "GET",
            &format!("/portal/accounts/{}/members", text(&account, "account_id")),
            Some(&root_cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(members["members"][1]["status"], json!("active"));
    assert_eq!(members["members"][1]["suspended_at"], json!(CLOCK_SECONDS));
    let (client_id, id) = push(&h).await;
    let decided = decide(
        &h,
        &id,
        json!({ "outcome": "approved", "signer_id": member_id, "account_id": account["account_id"] }),
        Some(&member_cookie),
    )
    .await;
    assert_eq!(
        claims_after(&h, &client_id, &decided).await["oaath_accounts"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}
