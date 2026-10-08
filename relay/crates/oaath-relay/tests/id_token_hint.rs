//! A PAR `id_token_hint` binds the login's signer and account to a grant
//! request: the portal reads the binding, and the bound root prepares and
//! decides with its signature alone. A hint that is not the relay's own live
//! id_token for this client is refused with a structured code.

mod support;

use axum::body::Body;
use axum::http::Request;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oaath_relay::error::RelayErrorCode as E;
use oaath_relay::oauth::id_token::IdTokenKey;
use serde_json::{Value, json};
use support::grant::*;
use support::*;

fn form(pairs: &[(&str, &str)]) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    Request::builder()
        .method("POST")
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

async fn client(h: &Harness) -> String {
    let reply = h
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    text(reply.ok(201), "client_id").to_owned()
}

async fn par(h: &Harness, client_id: &str, details: Option<&Value>, hint: Option<&str>) -> Reply {
    let challenge = code_challenge();
    let details = details.map(Value::to_string);
    let mut pairs = vec![
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("response_type", "code"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "openid"),
    ];
    if let Some(details) = &details {
        pairs.push(("authorization_details", details));
    }
    if let Some(hint) = hint {
        pairs.push(("id_token_hint", hint));
    }
    h.send(form(&pairs)).await
}

fn transaction_id(reply: &Reply) -> String {
    text(reply.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned()
}

fn code_of(reply: &Reply) -> String {
    url::Url::parse(text(reply.ok(200), "redirect"))
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned()
}

async fn token(h: &Harness, client_id: &str, code: &str) -> Value {
    h.send(
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("grant_type", "authorization_code"),
                        ("client_id", client_id),
                        ("code", code),
                        ("code_verifier", CODE_VERIFIER),
                        ("redirect_uri", REDIRECT_URI),
                    ])
                    .finish(),
            ))
            .unwrap(),
    )
    .await
    .ok(200)
    .clone()
}

/// A root with an account, logged in to `client_id`: its signer id, account,
/// and the login's id_token.
async fn logged_in(h: &Harness, client_id: &str, root: &Root) -> (String, Value, String) {
    let (signer_id, cookie) = sign_in(h, root).await;
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
    let id = transaction_id(&par(h, client_id, None, None).await);
    let decided = h
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            Some(&cookie),
            Some(json!({
                "outcome": "approved",
                "signer_id": signer_id,
                "account_id": account["account_id"],
            })),
        ))
        .await;
    let tokens = token(h, client_id, &code_of(&decided)).await;
    // Sign out: the bound request below must not lean on this session.
    h.send(portal_call(
        "DELETE",
        "/portal/sessions",
        Some(&cookie),
        None,
    ))
    .await;
    (signer_id, account, text(&tokens, "id_token").to_owned())
}

fn hint_refused(reply: &Reply) {
    assert_eq!(reply.status, 400, "body: {}", reply.body);
    assert_eq!(reply.body["error"], json!("invalid_request"));
    assert_eq!(reply.body["error_code"], json!(E::IdTokenHintInvalid));
}

#[tokio::test]
async fn a_hint_binds_the_request_and_the_bound_root_signs_without_a_session() {
    let h = harness();
    let client_id = client(&h).await;
    let root = Root::Ecdsa(root_key());
    let (signer_id, account, id_token) = logged_in(&h, &client_id, &root).await;

    let id = transaction_id(&par(&h, &client_id, Some(&json!([detail()])), Some(&id_token)).await);
    let transaction = h
        .send(get(&format!("/portal/transactions/{id}"), None))
        .await
        .ok(200)
        .clone();
    assert_eq!(
        transaction["bound"],
        json!({
            "signer_id": signer_id,
            "account": {
                "account_id": account["account_id"],
                "address": account["address"],
                "role": "root",
                "status": "active",
                "profile": account["profile"],
            },
        })
    );

    // No cookie: the binding lets the bound root prepare and decide.
    let selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
    let prepared = h
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/prepare"),
            None,
            Some(selection),
        ))
        .await
        .ok(200)
        .clone();
    let artifact = approval(&prepared, &root);
    let decided = h
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            None,
            Some(json!({
                "outcome": "approved",
                "signer_id": signer_id,
                "account_id": account["account_id"],
                "artifact": artifact.to_string(),
            })),
        ))
        .await;
    let tokens = token(&h, &client_id, &code_of(&decided)).await;
    assert_eq!(
        tokens["authorization_details"][0]["permission_request"],
        prepared["permission_request"]
    );

    // The binding grants no session: a member's request still needs one.
    let other =
        transaction_id(&par(&h, &client_id, Some(&json!([detail()])), Some(&id_token)).await);
    h.send(portal_call(
        "POST",
        &format!("/portal/transactions/{other}/decision"),
        None,
        Some(json!({
            "outcome": "request_approval",
            "signer_id": signer_id,
            "account_id": account["account_id"],
        })),
    ))
    .await
    .failure(E::Unauthenticated);
}

#[tokio::test]
async fn refuses_a_foreign_audience_expired_or_foreign_key_hint() {
    let h = harness();
    let client_id = client(&h).await;
    let (_, _, id_token) = logged_in(&h, &client_id, &Root::Ecdsa(root_key())).await;
    let details = json!([detail()]);

    // Another client's PAR.
    let other_client = client(&h).await;
    hint_refused(&par(&h, &other_client, Some(&details), Some(&id_token)).await);

    // The same claims under another key that claims the relay's kid.
    let payload = id_token.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    use p256::pkcs8::EncodePrivateKey;
    let pem = p256::SecretKey::from_slice(&[9u8; 32])
        .unwrap()
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let forged = IdTokenKey::from_pkcs8_pem(Some(ID_TOKEN_KID), &pem)
        .unwrap()
        .sign(&claims)
        .unwrap();
    hint_refused(&par(&h, &client_id, Some(&details), Some(&forged)).await);
    hint_refused(&par(&h, &client_id, Some(&details), Some("not-a-token")).await);

    // Past the bounded hint age; the same token was accepted just before it.
    h.clock.advance(3_600_000 - 1_000);
    par(&h, &client_id, Some(&details), Some(&id_token))
        .await
        .ok(201);
    h.clock.advance(1_000);
    hint_refused(&par(&h, &client_id, Some(&details), Some(&id_token)).await);
}

#[tokio::test]
async fn without_a_hint_nothing_is_bound_and_prepare_still_needs_a_session() {
    let h = harness();
    let client_id = client(&h).await;
    let (signer_id, account, _) = logged_in(&h, &client_id, &Root::Ecdsa(root_key())).await;
    let id = transaction_id(&par(&h, &client_id, Some(&json!([detail()])), None).await);
    let transaction = h
        .send(get(&format!("/portal/transactions/{id}"), None))
        .await
        .ok(200)
        .clone();
    assert_eq!(transaction["bound"], Value::Null);
    let selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
    h.send(portal_call(
        "POST",
        &format!("/portal/transactions/{id}/prepare"),
        None,
        Some(selection),
    ))
    .await
    .failure(E::Unauthenticated);
}
