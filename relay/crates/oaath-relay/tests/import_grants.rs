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
use oaath_protocol::permission::parse_permission_request;
use oaath_relay::account_import::{AccountImport, import_digest};
use oaath_relay::error::RelayErrorCode;
use oaath_relay::grant::approval::{V33_APPROVAL_VERSION, v33_capability_hash};
use oaath_relay::grant::grant_packages;
use serde_json::{Value, json};
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

/// A relay with no chain, the root signed in, and its Kernel v4 account
/// imported at IMPORTED.
async fn imported(root: &Root) -> (Harness, String, String, Value) {
    let (h, signer_id, cookie, response) = import_as(root, "0.4.0").await;
    (h, signer_id, cookie, response.ok(201).clone())
}

/// Signs `root` in on a relay with no chain and asks to import IMPORTED as a
/// Kernel `kernel_version` account.
async fn import_as(root: &Root, kernel_version: &str) -> (Harness, String, String, Reply) {
    let owner = parse_owner_credential_profile(&root.profile()).unwrap();
    let h = harness();
    let (signer_id, cookie) = sign_in(&h, root).await;
    let fingerprint = format!("0x{}", "22".repeat(32));
    let digest = import_digest(&AccountImport {
        account: IMPORTED.parse::<Address>().unwrap(),
        kernelVersion: kernel_version.to_owned(),
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
                "kernel_version": kernel_version,
                "inventory_fingerprint": fingerprint,
                "issued_at": CLOCK_SECONDS,
                "nonce": "import-1",
                "signature": format!("0x{}", hex::encode(root.sign(digest))),
            })),
        ))
        .await;
    (h, signer_id, cookie, account)
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

/// A registered dapp's PAR for `detail()`: its client id and the request id.
async fn pushed_par(h: &Harness) -> (String, String) {
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
    (client_id, id)
}

/// A dapp's PAR for `detail()`, prepared and decided by the account's root
/// with `approve`, and exchanged for tokens.
async fn dapp_grant(
    h: &Harness,
    signer_id: &str,
    cookie: &str,
    account: &Value,
    root: &Root,
    enable_nonce: Option<&str>,
    approve: impl Fn(&Value) -> Value,
) -> (Value, Value) {
    let cookie = Some(cookie);
    let (client_id, id) = pushed_par(h).await;
    let mut selection = json!({ "signer_id": signer_id, "account_id": account["account_id"] });
    if let Some(nonce) = enable_nonce {
        selection["enable_nonce"] = json!(nonce);
    }
    let prepared = h
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/prepare"),
            cookie,
            Some(selection),
        ))
        .await
        .ok(200)
        .clone();
    assert_existing_install(&prepared, root);
    let artifact = approve(&prepared);
    let decided = h
        .send(portal_call(
            "POST",
            &format!("/portal/transactions/{id}/decision"),
            cookie,
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
    (prepared, tokens)
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
        let (h, signer_id, cookie, account) = imported(&root).await;
        let (prepared, tokens) =
            dapp_grant(&h, &signer_id, &cookie, &account, &root, None, |prepared| {
                approval(prepared, &root)
            })
            .await;
        let grant = &tokens["authorization_details"][0];
        assert_eq!(grant["enable"]["account"], IMPORTED);
        assert_eq!(grant["permission_request"], prepared["permission_request"]);
    }
}

#[tokio::test]
async fn a_template_on_a_link_and_a_later_assignment_approve_on_an_imported_account() {
    let root = Root::Ecdsa(root_key());
    let (h, _signer_id, cookie, account) = imported(&root).await;
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

/// The SDK's `oaath.kernel.v33-permission-approval/v1` decision over a
/// prepared v3.3 enable, signed by `root`.
fn v33_approval(prepared: &Value, root: &Root) -> Value {
    let signing = &prepared["signing_request"];
    let digest: B256 = signing["expectedDigest"].as_str().unwrap().parse().unwrap();
    let enable = root.sign(digest);
    let request = parse_permission_request(&prepared["permission_request"]).unwrap();
    let packages: Vec<Value> = grant_packages(&request.operator_credential, &request.policy)
        .unwrap()
        .iter()
        .map(|install| {
            json!({
                "moduleType": install.module_type,
                "module": install.module,
                "moduleData": install.module_data,
                "internalData": install.internal_data,
            })
        })
        .collect();
    json!({
        "version": "oaath.permission-decision/v1",
        "kind": "approve",
        "requestId": request.request_id,
        "requestHash": prepared["request_hash"],
        "decidedAt": CLOCK_SECONDS,
        "approvedPolicy": prepared["approved_policy"],
        "capabilityHash": format!("{:#x}", v33_capability_hash(digest, &enable)),
        "installApproval": {
            "version": V33_APPROVAL_VERSION,
            "chainScope": "all",
            "account": signing["signer"]["account"],
            "nonce": signing["replay"]["nonce"],
            "permissionId": &packages[0]["internalData"],
            "packages": packages,
            "digest": signing["expectedDigest"],
            "enableSignature": format!("0x{}", hex::encode(&enable)),
        },
    })
}

#[tokio::test]
async fn a_dapp_grant_on_an_imported_kernel_v33_account_prepares_verifies_and_releases() {
    let root = Root::Ecdsa(root_key());
    let (h, signer_id, cookie, imported) = import_as(&root, "0.3.3").await;
    let account = imported.ok(201).clone();
    assert_eq!(account["profile"]["kernelVersion"], "0.3.3");
    assert_eq!(account["profile"]["entryPoint"]["version"], "0.7");
    // The portal read Kernel's enable nonce and sends it with the prepare.
    let (prepared, tokens) = dapp_grant(
        &h,
        &signer_id,
        &cookie,
        &account,
        &root,
        Some("7"),
        |prepared| v33_approval(prepared, &root),
    )
    .await;
    let typed = &prepared["signing_request"]["typedData"];
    assert_eq!(typed["primaryType"], "Enable");
    assert_eq!(typed["domain"]["version"], "0.3.3");
    assert_eq!(typed["domain"]["chainId"], "0");
    assert_eq!(typed["message"]["nonce"], "7");
    assert_eq!(prepared["signing_request"]["replay"]["nonce"], "7");
    let grant = &tokens["authorization_details"][0];
    assert_eq!(grant["enable"]["version"], V33_APPROVAL_VERSION);
    assert_eq!(grant["enable"]["account"], IMPORTED);
    assert_eq!(grant["permission_request"], prepared["permission_request"]);
}

#[tokio::test]
async fn a_kernel_v33_import_needs_an_ecdsa_root_and_its_prepare_an_enable_nonce() {
    // A v3.3 account's root is its ECDSA validator: a passkey signer is no root.
    let passkey = Root::WebAuthn(
        p256::ecdsa::SigningKey::from_slice(&[0x33; 32]).unwrap(),
        b"root-credential".to_vec(),
    );
    import_as(&passkey, "0.3.3")
        .await
        .3
        .failure(RelayErrorCode::Forbidden);

    let root = Root::Ecdsa(root_key());
    let (h, signer_id, cookie, reply) = import_as(&root, "0.3.3").await;
    let account = reply.ok(201).clone();
    let v4 = imported(&root).await;
    for (harness, signer, cookie, account, nonce) in [
        // A v3.3 prepare without, or with a noncanonical, enable nonce.
        (&h, &signer_id, &cookie, &account, None),
        (&h, &signer_id, &cookie, &account, Some(json!("07"))),
        (&h, &signer_id, &cookie, &account, Some(json!("0"))),
        (&h, &signer_id, &cookie, &account, Some(json!(7))),
        // A Kernel 0.4.0 prepare with one.
        (&v4.0, &v4.1, &v4.2, &v4.3, Some(json!("7"))),
    ] {
        let (_, id) = pushed_par(harness).await;
        let mut selection = json!({ "signer_id": signer, "account_id": account["account_id"] });
        if let Some(nonce) = nonce {
            selection["enable_nonce"] = nonce;
        }
        harness
            .send(portal_call(
                "POST",
                &format!("/portal/transactions/{id}/prepare"),
                Some(cookie),
                Some(selection),
            ))
            .await
            .failure(RelayErrorCode::RequestInvalid);
    }
}
