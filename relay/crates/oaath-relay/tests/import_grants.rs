//! Grants on an imported (existing) Kernel v4 account: the relay composes,
//! prepares and verifies them offline exactly as for a derived account, with
//! the existing-account profile as the logical account and its address as the
//! install's account. A dapp oaath_grant, a template on a link, and a later
//! assignment each approve with the root's one enable signature.

mod support;

use alloy_primitives::{Address, B256};
use axum::body::Body;
use axum::http::Request;
use oaath_protocol::identity::{
    KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION, parse_owner_credential_profile,
};
use oaath_relay::account_import::{AccountImport, import_digest};
use serde_json::{Value, json};
use support::chain::{StubAccount, stub_chain};
use support::grant::{Root, approval, detail, link_member, root_key, sign_in};
use support::*;

const IMPORTED: &str = "0x00000000000000000000000000000000000000ab";

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

/// A relay whose chain shows `root`'s Kernel account at IMPORTED, the root
/// signed in, and the account imported.
async fn imported(root: &Root) -> (Harness, support::chain::StubChain, String, String, Value) {
    let owner = parse_owner_credential_profile(&root.profile()).unwrap();
    let chain = stub_chain(421_614, &[(IMPORTED, StubAccount::kernel(&owner))]).await;
    let reader = chain.reader();
    let h = harness_with(move |options| options.chain = Some(reader));
    let (signer_id, cookie) = sign_in(&h, root).await;
    let fingerprint = format!("0x{}", "22".repeat(32));
    let digest = import_digest(&AccountImport {
        account: IMPORTED.parse::<Address>().unwrap(),
        ownerProfileHash: owner.hash(),
        inventoryFingerprint: fingerprint.parse::<B256>().unwrap(),
        issuedAt: CLOCK_SECONDS,
        nonce: "import-1".to_owned(),
    });
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts/import",
            Some(&cookie),
            Some(json!({
                "root_signer_id": signer_id,
                "address": IMPORTED,
                "inventory_fingerprint": fingerprint,
                "issued_at": CLOCK_SECONDS,
                "nonce": "import-1",
                "signature": format!("0x{}", hex::encode(root.sign(digest))),
            })),
        ))
        .await
        .ok(201)
        .clone();
    (h, chain, signer_id, cookie, account)
}

fn assert_existing_install(prepared: &Value, root: &Root) {
    let request = &prepared["permission_request"];
    assert_eq!(
        request["logicalAccount"]["version"],
        json!(KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION)
    );
    assert_eq!(request["logicalAccount"]["address"], IMPORTED);
    assert_eq!(request["logicalAccount"]["ownerCredential"], root.profile());
    let signing = &prepared["signing_request"];
    assert_eq!(signing["signer"]["account"], IMPORTED);
    assert_eq!(
        signing["typedData"]["domain"]["verifyingContract"],
        IMPORTED
    );
}

#[tokio::test]
async fn a_dapp_grant_on_an_imported_account_prepares_verifies_and_releases() {
    for root in [
        Root::Ecdsa(root_key()),
        Root::WebAuthn(
            p256::ecdsa::SigningKey::from_slice(&[0x33; 32]).unwrap(),
            b"root-credential".to_vec(),
        ),
    ] {
        let (h, chain, signer_id, cookie, account) = imported(&root).await;
        let reads = chain.calls();
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
        let challenge = code_challenge();
        let details = json!([detail()]).to_string();
        let pushed = h
            .send(form(
                "/oauth/par",
                &[
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", REDIRECT_URI),
                    ("response_type", "code"),
                    ("code_challenge", challenge.as_str()),
                    ("code_challenge_method", "S256"),
                    ("scope", "openid"),
                    ("authorization_details", details.as_str()),
                ],
            ))
            .await;
        let id = text(pushed.ok(201), "request_uri")
            .rsplit(':')
            .next()
            .unwrap()
            .to_owned();
        let selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
        let prepared = h
            .send(portal_call(
                "POST",
                &format!("/portal/transactions/{id}/prepare"),
                Some(&cookie),
                Some(selection),
            ))
            .await
            .ok(200)
            .clone();
        assert_existing_install(&prepared, &root);
        let artifact = approval(&prepared, &root);
        let decided = h
            .send(portal_call(
                "POST",
                &format!("/portal/transactions/{id}/decision"),
                Some(&cookie),
                Some(json!({
                    "outcome": "approved",
                    "signer_id": signer_id,
                    "account_id": account["account_id"],
                    "artifact": artifact.to_string(),
                })),
            ))
            .await;
        let code = url::Url::parse(text(decided.ok(200), "redirect"))
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
        let grant = &tokens["authorization_details"][0];
        assert_eq!(grant["enable"]["account"], IMPORTED);
        assert_eq!(grant["permission_request"], prepared["permission_request"]);
        // Preparing and verifying the grant read no chain: the import proved it.
        assert_eq!(chain.calls(), reads);
    }
}

#[tokio::test]
async fn a_template_on_a_link_and_a_later_assignment_approve_on_an_imported_account() {
    let root = Root::Ecdsa(root_key());
    let (h, _chain, _signer_id, cookie, account) = imported(&root).await;
    let account_id = text(&account, "account_id").to_owned();
    let template_id = text(
        h.send(portal_call(
            "POST",
            &format!("/portal/accounts/{account_id}/policies"),
            Some(&cookie),
            Some(json!({
                "name": "Payments",
                "lifetime_seconds": 86_400,
                "policy": {
                    "calls": [{ "target": format!("0x{}", "aa".repeat(20)), "selector": "0xa9059cbb", "valueLimit": "0" }],
                    "perChainOperationLimit": { "count": 5, "intervalSeconds": 86_400 },
                },
            })),
        ))
        .await
        .ok(201),
        "template_id",
    )
    .to_owned();

    // A link approved with the template.
    let passkey = Root::WebAuthn(
        p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap(),
        b"member".to_vec(),
    );
    let (member_id, member_cookie) = sign_in(&h, &passkey).await;
    let link_id = text(
        h.send(portal_call(
            "POST",
            "/portal/links",
            Some(&member_cookie),
            Some(json!({ "signer_id": member_id, "account": IMPORTED, "label": "Laptop" })),
        ))
        .await
        .ok(201),
        "link_id",
    )
    .to_owned();
    let selection = json!({ "template_id": template_id });
    let prepared = h
        .send(portal_call(
            "POST",
            &format!("/portal/links/{link_id}/prepare"),
            Some(&cookie),
            Some(selection.clone()),
        ))
        .await
        .ok(200)
        .clone();
    assert_existing_install(&prepared, &root);
    h.send(portal_call(
        "POST",
        &format!("/portal/links/{link_id}/approve"),
        Some(&cookie),
        Some(json!({ "template_id": template_id, "artifact": approval(&prepared, &root).to_string() })),
    ))
    .await
    .ok(200);
    let grant = |id: String| {
        portal_call(
            "GET",
            &format!("/portal/grants/{id}"),
            Some(&member_cookie),
            None,
        )
    };
    assert_eq!(
        h.send(grant(link_id.clone())).await.ok(200)["status"],
        "approved"
    );

    // A later assignment to a login-only member, with a fresh signature.
    let other = Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x55; 32]).unwrap());
    let (other_id, other_cookie) = sign_in(&h, &other).await;
    link_member(&h, IMPORTED, (&other_id, &other_cookie), (&root, &cookie)).await;
    let grants = format!("/portal/accounts/{account_id}/members/{other_id}/grants");
    let prepared = h
        .send(portal_call(
            "POST",
            &format!("{grants}/prepare"),
            Some(&cookie),
            Some(selection),
        ))
        .await
        .ok(200)
        .clone();
    assert_existing_install(&prepared, &root);
    let request = &prepared["permission_request"];
    let mut artifact = approval(&prepared, &root);
    artifact["decidedAt"] = request["requestedAt"].clone();
    let assigned = h
        .send(portal_call(
            "POST",
            &grants,
            Some(&cookie),
            Some(json!({
                "template_id": template_id,
                "request_id": request["requestId"],
                "requested_at": request["requestedAt"],
                "artifact": artifact.to_string(),
            })),
        ))
        .await
        .ok(201)
        .clone();
    let view = h
        .send(portal_call(
            "GET",
            &format!("/portal/grants/{}", text(&assigned, "grant_id")),
            Some(&other_cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(view["status"], "approved");
}
