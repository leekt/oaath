//! `oaath_operation` authorization details: a dapp PARs one exact owner
//! operation for a registry account, the account's root signs its
//! UserOperation hash in the portal, and the token releases the signed
//! operation once. The requests and signatures are the SDK's own
//! (`relay/fixtures/kernel-approval/portal-root-owner-operations.json`).

mod support;

use std::fs;
use std::path::PathBuf;

use alloy_primitives::B256;
use axum::body::Body;
use axum::http::Request;
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::grant::{Root, webauthn_assertion};
use support::*;
use url::Url;

/// The fixtures' relying party: their WebAuthn assertions name this issuer.
const FIXTURE_ISSUER: &str = "https://oaath.taek.tech";

fn fixtures() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kernel-approval/portal-root-owner-operations.json");
    serde_json::from_str(&fs::read_to_string(path).expect("run bun run fixtures:protocol")).unwrap()
}

fn case(name: &str) -> Value {
    fixtures()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no fixture {name}"))["signed"]
        .clone()
}

/// The SDK fixtures' deterministic roots (`portalRoot(kind, label)`).
fn fixture_root(kind: &str, label: &str) -> Root {
    let scalar = |label: &str| Sha256::digest(format!("oaath-portal-root:{label}").as_bytes());
    let name = format!("{kind}:{label}");
    match kind {
        "ecdsa" => Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&scalar(&name)).unwrap()),
        "p256" => Root::P256(p256::ecdsa::SigningKey::from_slice(&scalar(&name)).unwrap()),
        _ => Root::WebAuthn(
            p256::ecdsa::SigningKey::from_slice(&scalar(&name)).unwrap(),
            scalar(&format!("{name}:credential"))[..16].to_vec(),
        ),
    }
}

fn harness() -> Harness {
    harness_with(|options| {
        options.oauth.as_mut().unwrap().issuer = FIXTURE_ISSUER.to_owned();
    })
}

/// Registers `root`, proves it for this issuer, and answers its signer id and
/// session cookie.
async fn sign_in(h: &Harness, root: &Root) -> (String, String) {
    let signer_id = h
        .send(portal_call(
            "POST",
            "/portal/signers",
            None,
            Some(json!({ "profile": root.profile() })),
        ))
        .await
        .ok(200)["signer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let challenge = h
        .send(portal_call(
            "POST",
            "/portal/sessions/challenge",
            None,
            Some(json!({ "signer_id": signer_id })),
        ))
        .await
        .ok(200)
        .clone();
    let signature = match root {
        Root::WebAuthn(key, _) => {
            let nonce: B256 = challenge["nonce"].as_str().unwrap().parse().unwrap();
            format!(
                "0x{}",
                hex::encode(webauthn_assertion(
                    key,
                    nonce,
                    "oaath.taek.tech",
                    FIXTURE_ISSUER
                ))
            )
        }
        _ => root.prove(&challenge),
    };
    let reply = h
        .send(portal_call(
            "POST",
            "/portal/sessions",
            None,
            Some(json!({ "signer_id": signer_id, "nonce": challenge["nonce"], "signature": signature })),
        ))
        .await;
    reply.ok(200);
    (signer_id, cookie_of(&reply))
}

/// A signed-in root and its registry account (index 0).
async fn root_account(h: &Harness, root: &Root) -> (String, String, Value) {
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
    (signer_id, cookie, account)
}

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

async fn client(h: &Harness) -> String {
    let reply = h
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Keyline", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    text(reply.ok(201), "client_id").to_owned()
}

async fn par(h: &Harness, client_id: &str, request: &Value) -> Reply {
    let challenge = code_challenge();
    let details = json!([{ "type": "oaath_operation", "request": request }]).to_string();
    h.send(form(
        "/oauth/par",
        &[
            ("client_id", client_id),
            ("redirect_uri", REDIRECT_URI),
            ("response_type", "code"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("scope", "openid"),
            ("authorization_details", details.as_str()),
        ],
    ))
    .await
}

fn transaction_id(reply: &Reply) -> String {
    text(reply.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned()
}

async fn decide(
    h: &Harness,
    id: &str,
    signer: &str,
    account: &Value,
    signature: &Value,
    cookie: &str,
) -> Reply {
    h.send(portal_call(
        "POST",
        &format!("/portal/transactions/{id}/decision"),
        Some(cookie),
        Some(json!({
            "outcome": "approved",
            "signer_id": signer,
            "account_id": account["account_id"],
            "artifact": signature,
        })),
    ))
    .await
}

fn code_of(reply: &Reply) -> String {
    let redirect = text(reply.ok(200), "redirect");
    Url::parse(redirect)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned()
}

async fn token(h: &Harness, client_id: &str, code: &str) -> Reply {
    h.send(form(
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("code_verifier", CODE_VERIFIER),
            ("redirect_uri", REDIRECT_URI),
        ],
    ))
    .await
}

#[tokio::test]
async fn each_root_kind_approves_and_the_token_releases_the_signed_operation_once() {
    for kind in ["ecdsa", "p256", "webauthn"] {
        let h = harness();
        let root = fixture_root(kind, "root");
        let (signer_id, cookie, account) = root_account(&h, &root).await;
        let signed = case(&format!("{kind} root: valid, deploys the account"));
        assert_eq!(
            account["address"], signed["request"]["userOperation"]["sender"],
            "{kind}: the registry derives the fixture's account"
        );
        let client_id = client(&h).await;
        let id = transaction_id(&par(&h, &client_id, &signed["request"]).await);
        let shown = h
            .send(get(&format!("/portal/transactions/{id}"), None))
            .await
            .ok(200)
            .clone();
        assert_eq!(
            shown["authorization_details"],
            json!([{ "type": "oaath_operation", "request": signed["request"] }])
        );

        let decided = decide(&h, &id, &signer_id, &account, &signed["signature"], &cookie).await;
        let code = code_of(&decided);
        // A replayed decision is refused, even with the same signature.
        decide(&h, &id, &signer_id, &account, &signed["signature"], &cookie)
            .await
            .failure(E::AlreadyDecided);

        let released = token(&h, &client_id, &code).await.ok(200).clone();
        assert_eq!(
            released["authorization_details"],
            json!([{ "type": "oaath_operation", "signed": signed }]),
            "{kind}"
        );
        assert_eq!(token(&h, &client_id, &code).await.status, 400);
    }
}

#[tokio::test]
async fn refuses_operations_for_accounts_outside_the_registry_or_its_derivation() {
    let h = harness();
    let root = fixture_root("ecdsa", "root");
    root_account(&h, &root).await;
    let client_id = client(&h).await;
    for name in [
        // Index 1 of the same root: a real account, but not in the registry.
        "ecdsa root: another account of the same root",
        "ecdsa root: sender is not the derived account",
        "ecdsa root: factory data deploys another account",
        "ecdsa root: another EntryPoint",
        "ecdsa root: operation altered without its hash",
        "ecdsa root: nonce outside root validation",
    ] {
        let reply = par(&h, &client_id, &case(name)["request"]).await;
        assert_eq!(reply.status, 400, "{name}");
        assert_eq!(
            reply.body["error"],
            json!("invalid_authorization_details"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn refuses_a_tampered_operation_another_signature_and_a_non_root_signer() {
    let h = harness();
    let root = fixture_root("ecdsa", "root");
    let (signer_id, cookie, account) = root_account(&h, &root).await;
    let client_id = client(&h).await;

    // The value was raised after signing: the request is well formed and bound,
    // so the PAR is accepted, but the root's signature is over another hash.
    let tampered = case("ecdsa root: call value altered");
    let id = transaction_id(&par(&h, &client_id, &tampered["request"]).await);
    decide(
        &h,
        &id,
        &signer_id,
        &account,
        &tampered["signature"],
        &cookie,
    )
    .await
    .failure(E::RequestInvalid);

    let valid = case("ecdsa root: valid, deploys the account");
    let id = transaction_id(&par(&h, &client_id, &valid["request"]).await);
    let other = case("ecdsa root: signed by another key of the same kind");
    decide(&h, &id, &signer_id, &account, &other["signature"], &cookie)
        .await
        .failure(E::RequestInvalid);
    decide(&h, &id, &signer_id, &account, &json!("0xzz"), &cookie)
        .await
        .failure(E::RequestInvalid);

    // Another signer, even signed in, is not this account's root.
    let (stranger, stranger_cookie) = sign_in(&h, &fixture_root("ecdsa", "other")).await;
    decide(
        &h,
        &id,
        &stranger,
        &account,
        &valid["signature"],
        &stranger_cookie,
    )
    .await
    .failure(E::Forbidden);
    // A plain login decision cannot approve an operation.
    h.send(portal_call(
        "POST",
        &format!("/portal/transactions/{id}/decision"),
        Some(&cookie),
        Some(json!({ "outcome": "approved", "signer_id": signer_id, "account_id": account["account_id"] })),
    ))
    .await
    .failure(E::RequestInvalid);
    // The root still approves the untouched request.
    code_of(&decide(&h, &id, &signer_id, &account, &valid["signature"], &cookie).await);
}
