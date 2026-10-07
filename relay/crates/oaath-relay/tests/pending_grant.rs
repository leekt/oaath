//! A member's `oaath_grant` waits for its account root: the dapp gets a code
//! at once, `/oauth/token` answers `authorization_pending` until the root
//! approves (the grant is released once) or rejects (`access_denied`).

mod support;

use axum::body::Body;
use axum::http::Request;
use k256::ecdsa::SigningKey;
use oaath_relay::error::RelayErrorCode as E;
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

fn assert_oauth_error(reply: &Reply, error: &str) {
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert_eq!(reply.body["error"], json!(error), "{}", reply.body);
}

struct Pending {
    client_id: String,
    request_id: String,
    code: String,
    account: Value,
    root: Root,
    root_cookie: String,
    root_id: String,
    member_id: String,
    member_cookie: String,
}

/// A root's account with a linked member that asks the root to approve a
/// dapp's grant request.
async fn member_request(h: &Harness) -> Pending {
    let root = Root::Ecdsa(root_key());
    let (root_id, root_cookie) = sign_in(h, &root).await;
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
    let member = Root::Ecdsa(SigningKey::from_slice(&[0x55; 32]).unwrap());
    let (member_id, member_cookie) = sign_in(h, &member).await;
    link_member(
        h,
        text(&account, "address"),
        (&member_id, &member_cookie),
        (&root, &root_cookie),
    )
    .await;

    let client_id = text(
        h.send(post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Dapp", "redirect_uris": [REDIRECT_URI] })),
        ))
        .await
        .ok(201),
        "client_id",
    )
    .to_owned();
    let (request_id, decided) = ask(h, &client_id, &member_cookie, &member_id, &account).await;
    let code = code_in(&decided);
    Pending {
        client_id,
        request_id,
        code,
        account,
        root,
        root_cookie,
        root_id,
        member_id,
        member_cookie,
    }
}

async fn call(h: &Harness, method: &str, path: &str, cookie: &str, body: Option<Value>) -> Reply {
    h.send(portal_call(method, path, Some(cookie), body)).await
}

async fn approve(h: &Harness, p: &Pending, cookie: &str) -> Reply {
    let path = format!("/portal/requests/{}", p.request_id);
    let prepared = call(
        h,
        "POST",
        &format!("{path}/prepare"),
        cookie,
        Some(json!({})),
    )
    .await;
    if prepared.status != 200 {
        return prepared;
    }
    let artifact = approval(&prepared.body, &p.root);
    call(
        h,
        "POST",
        &format!("{path}/approve"),
        cookie,
        Some(json!({ "artifact": artifact.to_string() })),
    )
    .await
}

#[tokio::test]
async fn the_dapp_waits_for_the_root_and_gets_the_grant_once() {
    let h = harness();
    let p = member_request(&h).await;
    assert_oauth_error(
        &token(&h, &p.client_id, &p.code).await,
        "authorization_pending",
    );

    // The root's queue shows the request; the member reads its own.
    let account_id = text(&p.account, "account_id");
    let queue = call(
        &h,
        "GET",
        &format!("/portal/accounts/{account_id}/requests"),
        &p.root_cookie,
        None,
    )
    .await
    .ok(200)
    .clone();
    let view = &queue["requests"][0];
    assert_eq!(queue["requests"].as_array().unwrap().len(), 1);
    assert_eq!(view["request_id"], json!(p.request_id));
    assert_eq!(view["status"], json!("pending"));
    assert_eq!(view["client_name"], json!("Dapp"));
    assert_eq!(view["member"]["signer_id"], json!(p.member_id));
    assert_eq!(
        view["permission_request"]["operatorCredential"],
        detail()["signer"]
    );
    let path = format!("/portal/requests/{}", p.request_id);
    call(&h, "GET", &path, &p.member_cookie, None).await.ok(200);

    // Polling past the PAR's own lifetime keeps the request pending.
    h.clock.advance(600_000);
    assert_oauth_error(
        &token(&h, &p.client_id, &p.code).await,
        "authorization_pending",
    );

    let approved = approve(&h, &p, &p.root_cookie).await.ok(200).clone();
    assert_eq!(approved["status"], json!("approved"));
    let tokens = token(&h, &p.client_id, &p.code).await.ok(200).clone();
    assert_eq!(
        tokens["authorization_details"][0]["grant_id"],
        json!(p.request_id)
    );
    // One-time: a second exchange is refused, and so is a second decision.
    assert_oauth_error(&token(&h, &p.client_id, &p.code).await, "invalid_grant");
    call(
        &h,
        "POST",
        &format!("{path}/reject"),
        &p.root_cookie,
        Some(json!({})),
    )
    .await
    .failure(E::AlreadyDecided);

    // The dapp signer joins the account as a permission signer for this grant.
    let members = call(
        &h,
        "GET",
        &format!("/portal/accounts/{account_id}/members"),
        &p.root_cookie,
        None,
    )
    .await
    .ok(200)
    .clone();
    assert!(
        members["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["grant_id"] == json!(p.request_id))
    );
}

#[tokio::test]
async fn a_rejection_denies_the_exchange() {
    let h = harness();
    let p = member_request(&h).await;
    let path = format!("/portal/requests/{}/reject", p.request_id);
    let rejected = call(&h, "POST", &path, &p.root_cookie, Some(json!({})))
        .await
        .ok(200)
        .clone();
    assert_eq!(rejected["status"], json!("rejected"));
    assert_oauth_error(&token(&h, &p.client_id, &p.code).await, "access_denied");
    // The code burned: the denial is final.
    assert_oauth_error(&token(&h, &p.client_id, &p.code).await, "invalid_grant");
}

#[tokio::test]
async fn only_the_root_decides_and_only_before_expiry() {
    let h = harness();
    let p = member_request(&h).await;
    let path = format!("/portal/requests/{}", p.request_id);
    approve(&h, &p, &p.member_cookie)
        .await
        .failure(E::Forbidden);
    call(
        &h,
        "POST",
        &format!("{path}/reject"),
        &p.member_cookie,
        Some(json!({})),
    )
    .await
    .failure(E::Forbidden);
    let account_id = text(&p.account, "account_id");
    call(
        &h,
        "GET",
        &format!("/portal/accounts/{account_id}/requests"),
        &p.member_cookie,
        None,
    )
    .await
    .failure(E::Forbidden);
    let stranger = Root::Ecdsa(SigningKey::from_slice(&[0x66; 32]).unwrap());
    let (_, stranger_cookie) = sign_in(&h, &stranger).await;
    call(&h, "GET", &path, &stranger_cookie, None)
        .await
        .failure(E::Forbidden);
    let response = h.send(portal_call("GET", &path, None, None)).await;
    assert_eq!(response.status, 401);

    // The grant request expires at its PAR's grant expiry.
    h.clock.advance(7_201_000);
    let (_, root_cookie) = sign_in(&h, &p.root).await;
    approve(&h, &p, &root_cookie).await.failure(E::Expired);
    let view = call(&h, "GET", &path, &root_cookie, None)
        .await
        .ok(200)
        .clone();
    assert_eq!(view["status"], json!("expired"));
    assert_oauth_error(&token(&h, &p.client_id, &p.code).await, "invalid_grant");
}

#[tokio::test]
async fn suspending_the_member_rejects_its_requests_and_invalidates_its_grants() {
    let h = harness();
    let first = member_request(&h).await;
    approve(&h, &first, &first.root_cookie).await.ok(200);
    let tokens = token(&h, &first.client_id, &first.code)
        .await
        .ok(200)
        .clone();

    // A second request by the same member, still undecided.
    let second = code_in(
        &ask(
            &h,
            &first.client_id,
            &first.member_cookie,
            &first.member_id,
            &first.account,
        )
        .await
        .1,
    );
    let account_id = text(&first.account, "account_id");
    call(
        &h,
        "POST",
        &format!(
            "/portal/accounts/{account_id}/members/{}/suspend",
            first.member_id
        ),
        &first.root_cookie,
        Some(json!({})),
    )
    .await
    .ok(200);
    assert_oauth_error(&token(&h, &first.client_id, &second).await, "access_denied");
    let grant = h
        .send(
            Request::builder()
                .uri(format!("/oauth/grants/{}", first.request_id))
                .header(
                    "authorization",
                    format!("Bearer {}", text(&tokens, "access_token")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_ne!(grant.body["status"], json!("approved"), "{}", grant.body);
}

/// A new PAR for the client, decided by `signer_id` as `request_approval`.
async fn ask(
    h: &Harness,
    client_id: &str,
    cookie: &str,
    signer_id: &str,
    account: &Value,
) -> (String, Reply) {
    let challenge = code_challenge();
    let details = json!([detail()]).to_string();
    let par = h
        .send(form(
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
        .await;
    let request_id = text(par.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned();
    let decided = h
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{request_id}/decision"),
            Some(cookie),
            Some(json!({
                "outcome": "request_approval",
                "signer_id": signer_id,
                "account_id": account["account_id"],
            })),
        ))
        .await;
    (request_id, decided)
}

fn code_in(reply: &Reply) -> String {
    url::Url::parse(text(reply.ok(200), "redirect"))
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned()
}

#[tokio::test]
async fn a_root_cannot_queue_a_request_for_itself() {
    let h = harness();
    let p = member_request(&h).await;
    ask(&h, &p.client_id, &p.root_cookie, &p.root_id, &p.account)
        .await
        .1
        .failure(E::RequestInvalid);
}
