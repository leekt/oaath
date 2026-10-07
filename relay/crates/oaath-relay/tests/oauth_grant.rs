//! `oaath_grant` authorization details: PAR capture, the portal transaction
//! view, and `prepare`, ending in a root-signed approval the verifier admits.

mod support;

use alloy_primitives::B256;
use axum::body::Body;
use axum::http::Request;
use k256::ecdsa::SigningKey;
use oaath_protocol::capture::parse_json;
use oaath_protocol::permission::parse_permission_request;
use oaath_relay::error::RelayErrorCode as E;
use oaath_relay::grant::approval::{capability_hash, verify_grant_approval};
use oaath_relay::grant::signature::RelyingParty;
use serde_json::{Value, json};
use support::grant::*;
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

async fn prepare(h: &Harness, id: &str, body: Value, cookie: &str) -> Reply {
    h.send(portal_call(
        "POST",
        &format!("/portal/transactions/{id}/prepare"),
        Some(cookie),
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
    let (signer_id, account, cookie) = register_root(&h, &Root::Ecdsa(key.clone())).await;
    let selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
    let prepared = prepare(&h, &id, selection.clone(), &cookie)
        .await
        .ok(200)
        .clone();

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
    assert_eq!(
        *prepare(&h, &id, selection, &cookie).await.ok(200),
        prepared
    );

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
    let (signer_id, account, cookie) = register_root(&h, &Root::Ecdsa(root_key())).await;
    let selection = |policy: Option<Value>| {
        let mut body = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
        if let Some(policy) = policy {
            body["approved_policy"] = policy;
        }
        body
    };
    let full = prepare(&h, &id, selection(None), &cookie)
        .await
        .ok(200)
        .clone();
    let narrowed = prepare(&h, &id, selection(Some(policy("1"))), &cookie)
        .await
        .ok(200)
        .clone();
    assert_eq!(narrowed["approved_policy"], policy("1"));
    assert_eq!(narrowed["permission_request"], full["permission_request"]);
    assert_ne!(narrowed["signing_request"], full["signing_request"]);
    prepare(&h, &id, selection(Some(policy("1001"))), &cookie)
        .await
        .failure(E::RequestInvalid);

    // Another signer's account, an unknown account, a stray field.
    let other = Root::Ecdsa(SigningKey::from_slice(&[0x22; 32]).unwrap());
    let (other_signer, other_account, other_cookie) = register_root(&h, &other).await;
    prepare(
        &h,
        &id,
        json!({ "signer_id": other_signer, "account_id": account["account_id"] }),
        &other_cookie,
    )
    .await
    .failure(E::Forbidden);
    prepare(
        &h,
        &id,
        json!({ "signer_id": signer_id, "account_id": other_account["account_id"] }),
        &cookie,
    )
    .await
    .failure(E::Forbidden);
    prepare(
        &h,
        &id,
        json!({ "signer_id": signer_id, "account_id": account["account_id"], "x": 1 }),
        &cookie,
    )
    .await
    .failure(E::RequestInvalid);
}

#[tokio::test]
async fn keeps_login_and_grant_transactions_apart() {
    let h = harness();
    let client_id = client(&h).await;
    let (signer_id, account, cookie) = register_root(&h, &Root::Ecdsa(root_key())).await;
    let selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
    // A login transaction has nothing to prepare.
    let login = transaction_id(&par(&h, &client_id, None).await);
    prepare(&h, &login, selection.clone(), &cookie)
        .await
        .failure(E::RequestInvalid);
    // A grant is never approved as a bare login; it can still be cancelled.
    let grant = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    let decide = |body: Value| {
        h.send(portal_call(
            "POST",
            &format!("/portal/transactions/{grant}/decision"),
            Some(&cookie),
            Some(body),
        ))
    };
    let mut approved = selection.clone();
    approved["outcome"] = json!("approved");
    decide(approved).await.failure(E::RequestInvalid);
    decide(json!({ "outcome": "cancelled" })).await.ok(200);
    prepare(&h, &grant, selection.clone(), &cookie)
        .await
        .failure(E::AlreadyDecided);
    // An expired grant is refused.
    let late = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    h.clock.advance(300_000);
    prepare(&h, &late, selection, &cookie)
        .await
        .failure(E::Expired);
}

/// A signed-in root, its first account, and its session cookie.
async fn register_root(h: &Harness, root: &Root) -> (String, Value, String) {
    let (signer_id, cookie) = sign_in(h, root).await;
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&cookie),
            Some(json!({ "root_signer_id": signer_id })),
        ))
        .await
        .ok(201)
        .clone();
    (signer_id, account, cookie)
}

async fn decide_grant(
    h: &Harness,
    id: &str,
    signer_id: &str,
    account: &Value,
    artifact: &Value,
    cookie: &str,
) -> Reply {
    h.send(portal_call(
        "POST",
        &format!("/portal/transactions/{id}/decision"),
        Some(cookie),
        Some(json!({
            "outcome": "approved",
            "signer_id": signer_id,
            "account_id": account["account_id"],
            "artifact": artifact.to_string(),
        })),
    ))
    .await
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

fn bearer_get(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn bearer_post(path: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// One approved grant through the whole flow: PAR, prepare, root signature,
/// decision, token.
async fn approved_grant(h: &Harness, root: &Root) -> (String, String, Value, Value, Value) {
    let client_id = client(h).await;
    let id = transaction_id(&par(h, &client_id, Some(&json!([detail()]))).await);
    let (signer_id, account, cookie) = register_root(h, root).await;
    let prepared = prepare(
        h,
        &id,
        json!({ "signer_id": signer_id, "account_id": account["account_id"] }),
        &cookie,
    )
    .await
    .ok(200)
    .clone();
    let artifact = approval(&prepared, root);
    let code = code_of(&decide_grant(h, &id, &signer_id, &account, &artifact, &cookie).await);
    let tokens = token(h, &client_id, &code).await.ok(200).clone();
    (id, client_id, prepared, artifact, tokens)
}

#[tokio::test]
async fn releases_a_root_approved_grant_for_every_root_kind() {
    for root in [
        Root::Ecdsa(root_key()),
        Root::P256(p256::ecdsa::SigningKey::from_slice(&[0x22; 32]).unwrap()),
        Root::WebAuthn(
            p256::ecdsa::SigningKey::from_slice(&[0x33; 32]).unwrap(),
            b"credential-1".to_vec(),
        ),
    ] {
        let h = harness();
        let (id, _, prepared, artifact, tokens) = approved_grant(&h, &root).await;
        let mut decision = artifact.clone();
        let enable = decision
            .as_object_mut()
            .unwrap()
            .shift_remove("installApproval")
            .unwrap();
        assert_eq!(
            tokens["authorization_details"],
            json!([{
                "type": "oaath_grant",
                "grant_id": id,
                "permission_request": prepared["permission_request"],
                "decision": decision,
                "enable": enable,
            }])
        );
        let view = h
            .send(bearer_get(
                &format!("/oauth/grants/{id}"),
                text(&tokens, "access_token"),
            ))
            .await
            .ok(200)
            .clone();
        assert_eq!(
            view,
            json!({
                "grant_id": id,
                "status": "approved",
                "permission_request": prepared["permission_request"],
                "decision": decision,
                "enable": enable,
            })
        );
    }
}

#[tokio::test]
async fn lists_the_dapp_signer_under_the_account_as_a_permission_signer() {
    let h = harness();
    let (_, _, _, _, _) = approved_grant(&h, &Root::Ecdsa(root_key())).await;
    let dapp = h
        .send(post(
            "/portal/signers",
            None,
            Some(json!({ "profile": {
                "version": "oaath.owner-credential-profile/v1",
                "kind": "ecdsa",
                "address": format!("0x{}", "44".repeat(20)),
            } })),
        ))
        .await;
    let dapp_id = text(dapp.ok(200), "signer_id").to_owned();
    let cookie = h.session_for(&dapp_id).await;
    let accounts = h
        .send(portal_call(
            "GET",
            &format!("/portal/signers/{dapp_id}/accounts"),
            Some(&cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(accounts["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(accounts["accounts"][0]["role"], json!("permission"));
}

#[tokio::test]
async fn refuses_an_approval_the_root_did_not_sign_for_this_grant() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let client_id = client(&h).await;
    let id = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    let (signer_id, account, cookie) = register_root(&h, &root).await;
    let selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
    let prepared = prepare(&h, &id, selection, &cookie).await.ok(200).clone();
    let artifact = approval(&prepared, &root);

    let mut tampered = Vec::new();
    // Another key's signature.
    tampered.push(approval(
        &prepared,
        &Root::Ecdsa(SigningKey::from_slice(&[0x66; 32]).unwrap()),
    ));
    // A tampered capability hash.
    let mut capability = artifact.clone();
    capability["capabilityHash"] = json!(format!("0x{}", "ab".repeat(32)));
    tampered.push(capability);
    // A widened policy.
    let mut widened = artifact.clone();
    widened["approvedPolicy"]["calls"][1]["valueLimit"] = json!("1001");
    tampered.push(widened);
    // The install approval names another account.
    let mut other_account = artifact.clone();
    other_account["installApproval"]["account"] = json!(format!("0x{}", "ce".repeat(20)));
    tampered.push(other_account);
    for artifact in &tampered {
        decide_grant(&h, &id, &signer_id, &account, artifact, &cookie)
            .await
            .failure(E::RequestInvalid);
    }
    // A non-root signer of the account may not approve.
    let (stranger, _, stranger_cookie) = register_root(
        &h,
        &Root::Ecdsa(SigningKey::from_slice(&[0x77; 32]).unwrap()),
    )
    .await;
    decide_grant(&h, &id, &stranger, &account, &artifact, &stranger_cookie)
        .await
        .failure(E::Forbidden);
    // Nor may another signer's session decide in the root's name.
    decide_grant(&h, &id, &signer_id, &account, &artifact, &stranger_cookie)
        .await
        .failure(E::Forbidden);

    // The genuine approval decides once; a replay refuses.
    let code = code_of(&decide_grant(&h, &id, &signer_id, &account, &artifact, &cookie).await);
    decide_grant(&h, &id, &signer_id, &account, &artifact, &cookie)
        .await
        .failure(E::AlreadyDecided);
    // The redirect recovers the same code.
    let recovered = h
        .send(get(&format!("/portal/transactions/{id}/redirect"), None))
        .await;
    assert_eq!(code_of(&recovered), code);
    // The same artifact replayed onto another grant transaction refuses.
    let other = transaction_id(&par(&h, &client_id, Some(&json!([detail()]))).await);
    decide_grant(&h, &other, &signer_id, &account, &artifact, &cookie)
        .await
        .failure(E::RequestInvalid);
}

#[tokio::test]
async fn invalidates_off_chain_and_revokes_the_access_token() {
    let h = harness();
    let (id, client_id, _, artifact, tokens) = approved_grant(&h, &Root::Ecdsa(root_key())).await;
    let access = text(&tokens, "access_token").to_owned();
    let invalidate = |token: &str, hash: Value| {
        h.send(bearer_post(
            &format!("/oauth/grants/{id}/invalidate"),
            token,
            json!({ "capability_hash": hash }),
        ))
    };
    let wrong = invalidate(&access, json!(format!("0x{}", "ab".repeat(32)))).await;
    assert_eq!(
        (wrong.status, wrong.body["error"].clone()),
        (400, json!("invalid_request"))
    );
    let unknown = invalidate("unknown-token", artifact["capabilityHash"].clone()).await;
    assert_eq!(
        (unknown.status, unknown.body["error"].clone()),
        (401, json!("invalid_token"))
    );
    let evidence = invalidate(&access, artifact["capabilityHash"].clone())
        .await
        .ok(200)
        .clone();
    assert!(evidence["evidenceHash"].is_string());
    let view = h
        .send(bearer_get(&format!("/oauth/grants/{id}"), &access))
        .await;
    assert_eq!(view.ok(200)["status"], json!("invalidated"));

    // RFC 7009: another client cannot revoke it; its own client can.
    let revoke = |client: &str| {
        h.send(form(
            "/oauth/revoke",
            &[("token", access.as_str()), ("client_id", client)],
        ))
    };
    assert_eq!(*revoke("another-client").await.ok(200), json!({}));
    h.send(bearer_get(&format!("/oauth/grants/{id}"), &access))
        .await
        .ok(200);
    assert_eq!(*revoke(&client_id).await.ok(200), json!({}));
    let refused = h
        .send(bearer_get(&format!("/oauth/grants/{id}"), &access))
        .await;
    assert_eq!(
        (refused.status, refused.body["error"].clone()),
        (401, json!("invalid_token"))
    );
    // Revoking an unknown token is still a success.
    let unknown = h
        .send(form(
            "/oauth/revoke",
            &[("token", "unknown"), ("client_id", client_id.as_str())],
        ))
        .await;
    unknown.ok(200);
    // A token reads only its own grant.
    let (other_id, _, _, _, _) = approved_grant(&h, &Root::Ecdsa(root_key())).await;
    let foreign = h
        .send(bearer_get(&format!("/oauth/grants/{other_id}"), &access))
        .await;
    assert_eq!(foreign.status, 401);
}
