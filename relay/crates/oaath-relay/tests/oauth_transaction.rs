//! Owner transactions over the memory store: a dapp pushes one exact plain
//! transaction, the signer whose wallet sends it reports the hash in the
//! portal, and the token releases `{request, transaction_hash}` once.

mod support;

use axum::body::Body;
use axum::http::Request;
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::grant::{Root, address_of, root_key, sign_in};
use support::*;
use url::Url;

const HASH: &str = "0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";

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

fn request_for(from: &str, to: Option<&str>) -> Value {
    json!({
        "version": "oaath.owner-transaction-request/v1",
        "chainId": 8453,
        "from": from,
        "to": to,
        "value": "1000000000000000000",
        "data": "0x6080",
        // Chain metadata round-trips through the PAR record and the token.
        "chain": {
            "name": "Example Chain",
            "nativeCurrency": { "name": "Ether", "symbol": "ETH", "decimals": 18 },
            "rpcUrls": ["https://rpc.example.org/"],
        },
    })
}

async fn client(h: &Harness) -> String {
    text(
        h.send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Orchestra", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await
        .ok(201),
        "client_id",
    )
    .to_owned()
}

async fn push(h: &Harness, client_id: &str, request: &Value, extra: &[(&str, &str)]) -> Reply {
    let challenge = code_challenge();
    let details = json!([{ "type": "oaath_transaction", "request": request }]).to_string();
    let mut pairs = vec![
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("response_type", "code"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", "openid"),
        ("authorization_details", details.as_str()),
    ];
    pairs.extend_from_slice(extra);
    h.send(form("/oauth/par", &pairs)).await
}

fn id_of(reply: &Reply) -> String {
    text(reply.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned()
}

/// A signed-in ECDSA signer, its account, and its session cookie.
async fn signer(h: &Harness, root: &Root) -> (String, Value, String) {
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

fn approved(signer_id: &str, account: &Value, artifact: &str) -> Value {
    json!({
        "outcome": "approved",
        "signer_id": signer_id,
        "account_id": account["account_id"],
        "artifact": artifact,
    })
}

#[tokio::test]
async fn releases_the_hash_the_sending_wallet_reported_once() {
    let h = harness();
    let key = root_key();
    let root = Root::Ecdsa(key.clone());
    let (signer_id, account, cookie) = signer(&h, &root).await;
    let client_id = client(&h).await;
    // A contract creation with value, from the signer's own address.
    let request = request_for(&address_of(&key), None);
    let id = id_of(&push(&h, &client_id, &request, &[]).await);
    let transaction = h
        .send(get(&format!("/portal/transactions/{id}"), None))
        .await
        .ok(200)
        .clone();
    assert_eq!(
        transaction["authorization_details"],
        json!([{ "type": "oaath_transaction", "request": request }])
    );

    let redirect = text(
        decide(&h, &id, approved(&signer_id, &account, HASH), Some(&cookie))
            .await
            .ok(200),
        "redirect",
    )
    .to_owned();
    let code = Url::parse(&redirect)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let tokens = h
        .send(form(
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
    assert_eq!(
        tokens["authorization_details"],
        json!([{ "type": "oaath_transaction", "request": request, "transaction_hash": HASH }])
    );
    // One decision per request.
    decide(&h, &id, approved(&signer_id, &account, HASH), Some(&cookie))
        .await
        .failure(E::AlreadyDecided);
}

#[tokio::test]
async fn refuses_another_signer_a_malformed_hash_and_a_sessionless_decision() {
    let h = harness();
    let key = root_key();
    let (signer_id, account, cookie) = signer(&h, &Root::Ecdsa(key.clone())).await;
    let client_id = client(&h).await;
    let to = format!("0x{}", "22".repeat(20));
    let request = request_for(&address_of(&key), Some(&to));

    // A signer other than `from` never decides it.
    let other = Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x55; 32]).unwrap());
    let (other_id, other_account, other_cookie) = signer(&h, &other).await;
    let id = id_of(&push(&h, &client_id, &request, &[]).await);
    decide(
        &h,
        &id,
        approved(&other_id, &other_account, HASH),
        Some(&other_cookie),
    )
    .await
    .failure(E::Forbidden);
    // A malformed hash is refused before anything is written.
    for artifact in ["0x1234", &HASH.to_uppercase(), &HASH[2..]] {
        decide(
            &h,
            &id,
            approved(&signer_id, &account, artifact),
            Some(&cookie),
        )
        .await
        .failure(E::RequestInvalid);
    }
    // A login_hint binds the signer, but a hash proves nothing: a session is required.
    let hint = format!("{signer_id}@{}", text(&account, "address"));
    let bound = id_of(&push(&h, &client_id, &request, &[("login_hint", hint.as_str())]).await);
    decide(&h, &bound, approved(&signer_id, &account, HASH), None)
        .await
        .failure(E::Unauthenticated);
}
