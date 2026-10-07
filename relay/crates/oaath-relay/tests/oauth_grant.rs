//! `oaath_grant` authorization details: PAR capture, the portal transaction
//! view, and `prepare`, ending in a root-signed approval the verifier admits.

mod support;

use alloy_primitives::{B256, keccak256};
use axum::body::Body;
use axum::http::Request;
use k256::ecdsa::SigningKey;
use oaath_protocol::capture::parse_json;
use oaath_protocol::permission::parse_permission_request;
use oaath_relay::error::RelayErrorCode as E;
use oaath_relay::grant::approval::{capability_hash, verify_grant_approval};
use oaath_relay::grant::signature::RelyingParty;
use serde_json::{Value, json};
use support::*;

fn root_key() -> SigningKey {
    SigningKey::from_slice(&[0x11; 32]).unwrap()
}

fn address_of(key: &SigningKey) -> String {
    let point = key.verifying_key().to_encoded_point(false);
    format!(
        "0x{}",
        hex::encode(&keccak256(&point.as_bytes()[1..])[12..])
    )
}

fn policy(value_limit: &str) -> Value {
    json!({
        "version": "oaath.grant-policy/v2",
        "calls": [
            { "target": format!("0x{}", "aa".repeat(20)), "selector": "0xa9059cbb", "valueLimit": "0", "argumentEquals": [] },
            { "target": format!("0x{}", "bb".repeat(20)), "selector": "0x12345678", "valueLimit": value_limit, "argumentEquals": [] },
        ],
        "validAfter": CLOCK_SECONDS,
        "validUntil": CLOCK_SECONDS + 3_600,
        "perChainOperationLimit": { "count": 10, "intervalSeconds": null },
    })
}

fn detail() -> Value {
    json!({
        "type": "oaath_grant",
        "signer": {
            "version": "oaath.operator-credential-profile/v1",
            "kind": "ecdsa",
            "address": format!("0x{}", "44".repeat(20)),
        },
        "policy": policy("1000"),
        "chains": [8453, 1],
        "expires_at": CLOCK_SECONDS + 7_200,
        "device_id": "device-1",
    })
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
            Some(json!({ "client_name": "Dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await;
    text(reply.ok(201), "client_id").to_owned()
}

async fn par(h: &Harness, client_id: &str, details: Option<&Value>) -> Reply {
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
    h.send(form("/oauth/par", &pairs)).await
}

fn transaction_id(reply: &Reply) -> String {
    text(reply.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned()
}

/// A registered root signer for `key` and its first account.
async fn root_account(h: &Harness, address: &str) -> (String, Value) {
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

async fn prepare(h: &Harness, id: &str, body: Value) -> Reply {
    h.send(post(
        &format!("/portal/transactions/{id}/prepare"),
        None,
        Some(body),
    ))
    .await
}

#[tokio::test]
async fn captures_a_grant_detail_and_shows_it_to_the_portal() {
    let h = harness();
    let client_id = client(&h).await;
    let id = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    let transaction = h
        .send(get(&format!("/portal/transactions/{id}"), None))
        .await
        .ok(200)
        .clone();
    assert_eq!(transaction["authorization_details"], json!([detail()]));
}

#[tokio::test]
async fn refuses_details_it_cannot_compose_or_enforce() {
    let h = harness();
    let client_id = client(&h).await;
    let with = |key: &str, value: Value| {
        let mut detail = detail();
        detail[key] = value;
        json!([detail])
    };
    let mut constrained = policy("1000");
    constrained["calls"][0]["argumentEquals"] =
        json!([{ "index": 0, "value": format!("0x{}", "00".repeat(32)) }]);
    for details in [
        json!([]),
        json!([detail(), detail()]),
        json!(detail()),
        with("type", json!("openid_credential")),
        with("chains", json!([])),
        with("chains", json!([1, 1])),
        with("device_id", json!("not canonical")),
        // The grant must outlive its policy.
        with("expires_at", json!(CLOCK_SECONDS + 60)),
        // No reviewed Kernel profile enforces argument constraints.
        with("policy", constrained),
        with(
            "signer",
            json!({ "version": "oaath.operator-credential-profile/v1", "kind": "p256", "publicKey": "0x04" }),
        ),
    ] {
        let reply = par(&h, &client_id, Some(&details)).await;
        assert_eq!(reply.status, 400, "{details}");
        assert_eq!(reply.body["error"], json!("invalid_authorization_details"));
    }
}

#[tokio::test]
async fn prepares_what_the_root_signs_and_admits_its_signature() {
    let h = harness();
    let client_id = client(&h).await;
    let id = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    let key = root_key();
    let (signer_id, account) = root_account(&h, &address_of(&key)).await;
    let selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
    let prepared = prepare(&h, &id, selection.clone()).await.ok(200).clone();

    let request = &prepared["permission_request"];
    assert_eq!(request["requestId"], json!(id));
    assert_eq!(request["logicalAccount"], account["profile"]);
    assert_eq!(request["context"]["accountId"], account["address"]);
    assert_eq!(request["application"]["clientId"], json!(client_id));
    assert_eq!(
        request["application"]["origin"],
        json!("https://app.example")
    );
    assert_eq!(request["requestedAt"], json!(CLOCK_SECONDS));
    assert_eq!(prepared["approved_policy"], request["policy"]);
    let signing = &prepared["signing_request"];
    assert_eq!(signing["purpose"], json!("kernel-enable"));
    assert_eq!(signing["signer"]["account"], account["address"]);
    // Deterministic: preparing again composes the same request.
    assert_eq!(*prepare(&h, &id, selection).await.ok(200), prepared);

    // The root signs the prepared digest; the verifier admits the artifact.
    let digest: B256 = signing["expectedDigest"].as_str().unwrap().parse().unwrap();
    let (signature, recovery) = key.sign_prehash_recoverable(&digest.0).unwrap();
    let enable = [signature.to_bytes().to_vec(), vec![27 + recovery.to_byte()]].concat();
    let message = &signing["typedData"]["message"];
    let packages: Vec<Value> = message["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|install| {
            let mut install = install.clone();
            install["moduleType"] = json!(
                install["moduleType"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            );
            install
        })
        .collect();
    let artifact = json!({
        "version": "oaath.permission-decision/v1",
        "kind": "approve",
        "requestId": id,
        "requestHash": prepared["request_hash"],
        "decidedAt": CLOCK_SECONDS,
        "approvedPolicy": prepared["approved_policy"],
        "capabilityHash": format!("{:#x}", capability_hash(digest, &enable)),
        "installApproval": {
            "version": "oaath.kernel.all-chain-approval/v1",
            "account": account["address"],
            "installNonce": message["nonce"],
            "packages": packages,
            "digest": signing["expectedDigest"],
            "enableSignature": format!("0x{}", hex::encode(&enable)),
        },
    });
    let request = parse_permission_request(&parse_json(&request.to_string()).unwrap()).unwrap();
    let relying_party = RelyingParty {
        rp_id: "oaath.test",
        origin: ISSUER,
    };
    let verify = |artifact: &Value, account: &str| {
        verify_grant_approval(
            &request,
            account,
            &artifact.to_string(),
            CLOCK_START,
            &relying_party,
        )
    };
    verify(&artifact, text(&account, "address")).unwrap();
    assert!(verify(&artifact, &format!("0x{}", "ce".repeat(20))).is_err());
}

#[tokio::test]
async fn narrows_but_never_widens_and_refuses_a_non_root() {
    let h = harness();
    let client_id = client(&h).await;
    let id = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    let (signer_id, account) = root_account(&h, &address_of(&root_key())).await;
    let selection = |policy: Option<Value>| {
        let mut body = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
        if let Some(policy) = policy {
            body["approved_policy"] = policy;
        }
        body
    };
    let full = prepare(&h, &id, selection(None)).await.ok(200).clone();
    let narrowed = prepare(&h, &id, selection(Some(policy("1"))))
        .await
        .ok(200)
        .clone();
    assert_eq!(narrowed["approved_policy"], policy("1"));
    assert_eq!(narrowed["permission_request"], full["permission_request"]);
    assert_ne!(narrowed["signing_request"], full["signing_request"]);
    prepare(&h, &id, selection(Some(policy("1001"))))
        .await
        .failure(E::RequestInvalid);

    // Another signer's account, an unknown account, a stray field.
    let (other_signer, other_account) =
        root_account(&h, "0x2222222222222222222222222222222222222222").await;
    prepare(
        &h,
        &id,
        json!({ "signer_id": other_signer, "account_id": account["account_id"] }),
    )
    .await
    .failure(E::Forbidden);
    prepare(
        &h,
        &id,
        json!({ "signer_id": signer_id, "account_id": other_account["account_id"] }),
    )
    .await
    .failure(E::Forbidden);
    prepare(
        &h,
        &id,
        json!({ "signer_id": signer_id, "account_id": account["account_id"], "x": 1 }),
    )
    .await
    .failure(E::RequestInvalid);
}

#[tokio::test]
async fn keeps_login_and_grant_transactions_apart() {
    let h = harness();
    let client_id = client(&h).await;
    let (signer_id, account) = root_account(&h, &address_of(&root_key())).await;
    let selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
    // A login transaction has nothing to prepare.
    let login = transaction_id(&par(&h, &client_id, None).await);
    prepare(&h, &login, selection.clone())
        .await
        .failure(E::RequestInvalid);
    // A grant is never approved as a bare login; it can still be cancelled.
    let grant = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    let decide = |body: Value| {
        h.send(post(
            &format!("/portal/transactions/{grant}/decision"),
            None,
            Some(body),
        ))
    };
    let mut approved = selection.clone();
    approved["outcome"] = json!("approved");
    decide(approved).await.failure(E::RequestInvalid);
    decide(json!({ "outcome": "cancelled" })).await.ok(200);
    prepare(&h, &grant, selection.clone())
        .await
        .failure(E::AlreadyDecided);
    // An expired grant is refused.
    let late = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    h.clock.advance(300_000);
    prepare(&h, &late, selection).await.failure(E::Expired);
}
