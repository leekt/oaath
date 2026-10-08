//! On-chain revocation of an invalidated grant, against a loopback chain and
//! bundler stand-in: the root signs the exact uninstall once, the relay
//! submits it once (or hands it to an opted-in dapp), and observation never
//! resubmits.

mod support;

use alloy_primitives::B256;
use k256::ecdsa::SigningKey;
use oaath_relay::error::RelayErrorCode as E;
use oaath_relay::revocation::MAX_BUNDLER_REQUESTS;
use serde_json::{Value, json};
use support::grant::*;
use support::revocation::*;
use support::*;

#[tokio::test]
async fn the_root_signs_the_exact_uninstall_once_and_the_relay_submits_it_once() {
    let (url, shared) = stub(Send::Accept).await;
    let h = harness_with(configure(&url));
    let granted = template_grant(&h).await;
    // An active grant is not revocable on chain: it must be invalidated first.
    status(&h, &granted).await.failure(E::RequestInvalid);
    suspend(&h, &granted).await;
    assert_eq!(
        status(&h, &granted).await.ok(200)["status"],
        "pending_signature"
    );

    let prepared = prepare(&h, &granted).await.ok(200).clone();
    let request = prepared["request"].clone();
    assert_eq!(prepared["status"], "pending_signature");
    assert_eq!(
        request["userOperation"]["sender"],
        granted.account["address"]
    );
    assert_eq!(request["userOperation"]["factory"], Value::Null);
    // The root validator's revocation lane, at the chain's sequence.
    assert_eq!(
        request["userOperation"]["nonce"],
        json!(((1u128 << 64) + 3).to_string())
    );
    // Policies in reverse, then the signer: one uninstall per package.
    assert_eq!(
        request["calls"].as_array().unwrap().len(),
        prepared["packages"].as_array().unwrap().len()
    );

    // Another signer's signature is refused, and nothing is sent.
    let mut other = Granted {
        root: Root::Ecdsa(SigningKey::from_slice(&[0x77; 32]).unwrap()),
        ..granted
    };
    sign(&h, &other, &request).await.failure(E::RequestInvalid);
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 0);
    other.root = Root::Ecdsa(root_key());
    let granted = other;

    let signed = sign(&h, &granted, &request).await.ok(200).clone();
    assert_eq!(signed["status"], "submitted");
    assert_eq!(signed["user_operation_hash"], request["userOperationHash"]);
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 1);
    // Signed once: a second signature and a re-preparation are refused.
    sign(&h, &granted, &request)
        .await
        .failure(E::AlreadyDecided);
    prepare(&h, &granted).await.failure(E::AlreadyDecided);

    // Polling observes by hash only; then the receipt lands, then finality.
    assert_eq!(status(&h, &granted).await.ok(200)["status"], "submitted");
    shared.lock().unwrap().receipt = Some(receipt(&request, true));
    shared.lock().unwrap().installed = false;
    let observed = status(&h, &granted).await.ok(200).clone();
    assert_eq!(observed["status"], "finalized");
    assert_eq!(
        observed["transaction_hash"],
        json!(format!("0x{}", "ef".repeat(32)))
    );
    status(&h, &granted).await.ok(200);
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 1);
    assert_eq!(calls(&shared, "eth_getUserOperationReceipt"), 2);
}

#[tokio::test]
async fn a_permission_that_is_not_installed_needs_nothing_submitted() {
    let (url, shared) = stub(Send::Accept).await;
    shared.lock().unwrap().installed = false;
    let h = harness_with(configure(&url));
    let granted = template_grant(&h).await;
    suspend(&h, &granted).await;
    assert_eq!(
        status(&h, &granted).await.ok(200)["status"],
        "not_installed"
    );
    let prepared = prepare(&h, &granted).await.ok(200).clone();
    assert_eq!(prepared["status"], "not_installed");
    assert_eq!(prepared["request"], Value::Null);
    // An undeployed account holds no permission either.
    shared.lock().unwrap().deployed = false;
    assert_eq!(
        status(&h, &granted).await.ok(200)["status"],
        "not_installed"
    );
    let bundled: usize = [
        "pimlico_getUserOperationGasPrice",
        "eth_estimateUserOperationGas",
    ]
    .iter()
    .map(|method| calls(&shared, method))
    .sum();
    assert_eq!(bundled, 0);
}

#[tokio::test]
async fn a_submission_timeout_never_resubmits() {
    let (url, shared) = stub(Send::Hang).await;
    let h = harness_with(configure(&url));
    let granted = template_grant(&h).await;
    suspend(&h, &granted).await;
    let request = prepare(&h, &granted).await.ok(200)["request"].clone();
    // The bundler never answers: the submission stays unknown, not failed.
    assert_eq!(
        sign(&h, &granted, &request).await.ok(200)["status"],
        "submitted"
    );
    for _ in 0..3 {
        assert_eq!(status(&h, &granted).await.ok(200)["status"], "submitted");
    }
    sign(&h, &granted, &request)
        .await
        .failure(E::AlreadyDecided);
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 1);
    // The receipt is found by hash; nothing was sent twice.
    shared.lock().unwrap().receipt = Some(receipt(&request, true));
    assert_eq!(status(&h, &granted).await.ok(200)["status"], "included");
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 1);
}

#[tokio::test]
async fn a_bundler_rejection_fails_without_retry_and_the_budget_bounds_polling() {
    let (url, shared) = stub(Send::Reject).await;
    let h = harness_with(configure(&url));
    let granted = template_grant(&h).await;
    suspend(&h, &granted).await;
    let request = prepare(&h, &granted).await.ok(200)["request"].clone();
    assert_eq!(
        sign(&h, &granted, &request).await.ok(200)["status"],
        "failed"
    );
    assert_eq!(status(&h, &granted).await.ok(200)["status"], "failed");
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 1);
    assert_eq!(calls(&shared, "eth_getUserOperationReceipt"), 0);

    // An accepted submission polls receipts only within the budget.
    let (url, shared) = stub(Send::Accept).await;
    let h = harness_with(configure(&url));
    let granted = template_grant(&h).await;
    suspend(&h, &granted).await;
    let request = prepare(&h, &granted).await.ok(200)["request"].clone();
    sign(&h, &granted, &request).await.ok(200);
    for _ in 0..MAX_BUNDLER_REQUESTS + 5 {
        status(&h, &granted).await.ok(200);
    }
    let spent: usize = shared
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|(method, _)| !method.starts_with("eth_") || method.contains("UserOperation"))
        .map(|(_, count)| *count)
        .sum();
    assert_eq!(spent as u64, MAX_BUNDLER_REQUESTS);
}

#[tokio::test]
async fn only_the_root_reads_or_signs_a_revocation() {
    let (url, _) = stub(Send::Accept).await;
    let h = harness_with(configure(&url));
    let granted = template_grant(&h).await;
    suspend(&h, &granted).await;
    let stranger = Root::Ecdsa(SigningKey::from_slice(&[0x66; 32]).unwrap());
    let (_, stranger_cookie) = sign_in(&h, &stranger).await;
    h.send(portal_call(
        "GET",
        &format!("/portal/grants/{}/revocation", granted.grant_id),
        Some(&stranger_cookie),
        None,
    ))
    .await
    .failure(E::Forbidden);
    h.send(portal_call(
        "POST",
        &format!("/portal/grants/{}/revocation/prepare", granted.grant_id),
        Some(&stranger_cookie),
        Some(json!({ "estimation_signature": "0x11" })),
    ))
    .await
    .failure(E::Forbidden);
    let response = h
        .send(portal_call(
            "GET",
            &format!("/portal/grants/{}/revocation", granted.grant_id),
            None,
            None,
        ))
        .await;
    assert_eq!(response.status, 401);
}

#[tokio::test]
async fn an_opted_in_dapp_receives_the_signed_uninstall_and_the_relay_never_submits() {
    let (url, shared) = stub(Send::Accept).await;
    let h = harness_with(configure(&url));
    // A dapp that registered revocation_delivery "dapp" holds a root-approved grant.
    let root = Root::Ecdsa(root_key());
    let (root_id, cookie) = sign_in(&h, &root).await;
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&cookie),
            Some(json!({ "root_signer_id": root_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    let registered = h
        .send(post(
            "/oauth/clients",
            None,
            Some(json!({
                "client_name": "Dapp",
                "redirect_uris": [REDIRECT_URI],
                "revocation_delivery": "dapp",
            })),
        ))
        .await
        .ok(201)
        .clone();
    assert_eq!(registered["revocation_delivery"], "dapp");
    let client_id = text(&registered, "client_id").to_owned();
    let grant_id = dapp_grant(&h, &client_id, &root, &root_id, &account, &cookie).await;
    // The root removes the dapp's signer: the grant is invalidated off chain.
    let members = h
        .send(portal_call(
            "GET",
            &format!("/portal/accounts/{}/members", text(&account, "account_id")),
            Some(&cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    let dapp_signer = members["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["grant_id"] == json!(grant_id))
        .unwrap()["signer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    h.send(portal_call(
        "DELETE",
        &format!(
            "/portal/accounts/{}/members/{dapp_signer}",
            text(&account, "account_id")
        ),
        Some(&cookie),
        None,
    ))
    .await
    .ok(200);

    let granted = Granted {
        root,
        cookie,
        account,
        member_id: dapp_signer,
        grant_id: grant_id.clone(),
    };
    let dapp_path = format!("/oauth/grants/{grant_id}/revocation");
    let before = h.send(get(&dapp_path, None)).await.ok(200).clone();
    assert_eq!(before["signed_operation"], Value::Null);
    let request = prepare(&h, &granted).await.ok(200)["request"].clone();
    let signed = sign(&h, &granted, &request).await.ok(200).clone();
    assert_eq!(signed["status"], "delivered");
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 0);
    let delivered = h.send(get(&dapp_path, None)).await.ok(200).clone();
    assert_eq!(delivered["status"], "delivered");
    assert_eq!(delivered["signed_operation"]["request"], request);
    assert_eq!(
        delivered["signed_operation"]["version"],
        "oaath.signed-owner-operation/v1"
    );
    assert_eq!(signed["relay_submits"], false);
    // The dapp submits it; the relay observes the receipt by hash.
    shared.lock().unwrap().receipt = Some(receipt(&request, true));
    assert_eq!(status(&h, &granted).await.ok(200)["status"], "included");
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 0);
}

/// A dapp's root-approved grant on `account`, through PAR, prepare, the
/// root's signature and the decision; answers the grant id.
async fn dapp_grant(
    h: &Harness,
    client_id: &str,
    root: &Root,
    root_id: &str,
    account: &Value,
    cookie: &str,
) -> String {
    let challenge = code_challenge();
    let details = json!([detail()]).to_string();
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("client_id", client_id),
            ("redirect_uri", REDIRECT_URI),
            ("response_type", "code"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("scope", "openid"),
            ("authorization_details", details.as_str()),
        ])
        .finish();
    let pushed = h
        .send(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/par")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await;
    let id = text(pushed.ok(201), "request_uri")
        .rsplit(':')
        .next()
        .unwrap()
        .to_owned();
    let selection = json!({ "signer_id": root_id, "account_id": account["account_id"] });
    let prepared = h
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/prepare"),
            Some(cookie),
            Some(selection),
        ))
        .await
        .ok(200)
        .clone();
    h.send(portal_call(
        "POST",
        &format!("/portal/transactions/{id}/decision"),
        Some(cookie),
        Some(json!({
            "outcome": "approved",
            "signer_id": root_id,
            "account_id": account["account_id"],
            "artifact": approval(&prepared, root).to_string(),
        })),
    ))
    .await
    .ok(200);
    id
}

#[tokio::test]
async fn the_root_may_submit_an_opted_in_dapps_revocation_from_oaath() {
    let (url, shared) = stub(Send::Accept).await;
    let h = harness_with(configure(&url));
    let root = Root::Ecdsa(root_key());
    let (root_id, cookie) = sign_in(&h, &root).await;
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&cookie),
            Some(json!({ "root_signer_id": root_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    let client_id = text(
        h.send(post(
            "/oauth/clients",
            None,
            Some(json!({
                "client_name": "Dapp",
                "redirect_uris": [REDIRECT_URI],
                "revocation_delivery": "dapp",
            })),
        ))
        .await
        .ok(201),
        "client_id",
    )
    .to_owned();
    let grant_id = dapp_grant(&h, &client_id, &root, &root_id, &account, &cookie).await;
    let account_id = text(&account, "account_id").to_owned();
    let members = h
        .send(portal_call(
            "GET",
            &format!("/portal/accounts/{account_id}/members"),
            Some(&cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    let dapp_signer = members["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["grant_id"] == json!(grant_id))
        .unwrap()["signer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    h.send(portal_call(
        "DELETE",
        &format!("/portal/accounts/{account_id}/members/{dapp_signer}"),
        Some(&cookie),
        None,
    ))
    .await
    .ok(200);
    let granted = Granted {
        root,
        cookie,
        account,
        member_id: dapp_signer,
        grant_id: grant_id.clone(),
    };
    let request = prepare(&h, &granted).await.ok(200)["request"].clone();
    let digest: B256 = request["userOperationHash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let signature = format!("0x{}", hex::encode(granted.root.sign(digest)));
    let path = format!("/portal/grants/{grant_id}/revocation/sign");
    // Anything but a boolean choice is refused.
    h.send(portal_call(
        "POST",
        &path,
        Some(&granted.cookie),
        Some(json!({ "signature": signature, "submit_from_oaath": "yes" })),
    ))
    .await
    .failure(E::RequestInvalid);
    let signed = h
        .send(portal_call(
            "POST",
            &path,
            Some(&granted.cookie),
            Some(json!({ "signature": signature, "submit_from_oaath": true })),
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(signed["status"], "submitted");
    assert_eq!(signed["relay_submits"], true);
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 1);
    // The dapp still reads the signed operation; the relay never sends it again.
    let delivered = h
        .send(get(&format!("/oauth/grants/{grant_id}/revocation"), None))
        .await
        .ok(200)
        .clone();
    assert_eq!(delivered["status"], "submitted");
    assert_eq!(delivered["signed_operation"]["request"], request);
    shared.lock().unwrap().receipt = Some(receipt(&request, true));
    assert_eq!(status(&h, &granted).await.ok(200)["status"], "included");
    assert_eq!(calls(&shared, "eth_sendUserOperation"), 1);
}
