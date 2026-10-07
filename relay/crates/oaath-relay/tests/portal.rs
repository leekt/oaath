//! Portal signer/account registry over the memory store: idempotent signer
//! registration, smallest-unused account indices at the fixture-pinned
//! addresses, one root per account, and same-origin enforcement.

mod support;

use axum::body::Body;
use axum::http::Request;
use oaath_relay::error::RelayErrorCode as E;
use oaath_relay::registry::{ACCOUNT_SIGNER_RECORD_VERSION, AccountSignerRecord, MembershipRole};
use serde_json::{Value, json};
use support::*;

/// One case of the TypeScript-generated (Anvil-pinned) address fixture.
fn address_case(name: &str) -> (Value, String) {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/deriveKernelV4AccountAddress.json"
    ))
    .unwrap();
    let case = fixtures
        .into_iter()
        .find(|case| case["name"] == json!(name))
        .unwrap();
    (
        case["input"]["account"]["ownerCredential"].clone(),
        case["expect"]["ok"].as_str().unwrap().to_owned(),
    )
}

fn portal(method: &str, path: &str, site: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(site) = site {
        builder = builder.header("sec-fetch-site", site);
    }
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .unwrap()
}

async fn register(h: &Harness, profile: &Value) -> String {
    let reply = h
        .send(portal(
            "POST",
            "/portal/signers",
            Some("same-origin"),
            Some(json!({ "profile": profile })),
        ))
        .await;
    let body = reply.ok(200);
    assert_eq!(body.as_object().unwrap().len(), 1);
    text(body, "signer_id").to_owned()
}

async fn create_account(h: &Harness, signer_id: &str) -> Reply {
    h.send(portal(
        "POST",
        "/portal/accounts",
        Some("same-origin"),
        Some(json!({ "root_signer_id": signer_id })),
    ))
    .await
}

async fn accounts(h: &Harness, signer_id: &str) -> Reply {
    h.send(portal(
        "GET",
        &format!("/portal/signers/{signer_id}/accounts"),
        Some("same-origin"),
        None,
    ))
    .await
}

#[tokio::test]
async fn registers_a_signer_idempotently_on_its_profile() {
    let h = harness();
    let (ecdsa, _) = address_case("ecdsa index 0");
    let first = register(&h, &ecdsa).await;
    assert_eq!(first.len(), 43);
    assert_eq!(register(&h, &ecdsa).await, first);
    // Identity is the captured profile, not its JSON spelling.
    let reordered = json!({
        "address": ecdsa["address"],
        "kind": "ecdsa",
        "version": "oaath.owner-credential-profile/v1",
    });
    assert_eq!(register(&h, &reordered).await, first);
    let (p256, _) = address_case("p256 index 0");
    assert_ne!(register(&h, &p256).await, first);
}

#[tokio::test]
async fn refuses_a_profile_that_is_not_an_owner_credential() {
    let h = harness();
    let (ecdsa, _) = address_case("ecdsa index 0");
    let mut operator = ecdsa.clone();
    operator["version"] = json!("oaath.operator-credential-profile/v1");
    let mut zero = ecdsa.clone();
    zero["address"] = json!(format!("0x{}", "00".repeat(20)));
    for body in [
        json!({}),
        json!({ "profile": operator }),
        json!({ "profile": zero }),
        json!({ "profile": ecdsa, "label": "extra" }),
        json!({ "profile": "0x1111111111111111111111111111111111111111" }),
    ] {
        h.send(portal(
            "POST",
            "/portal/signers",
            Some("same-origin"),
            Some(body),
        ))
        .await
        .failure(E::RequestInvalid);
    }
}

#[tokio::test]
async fn derives_accounts_at_the_smallest_unused_index_and_lists_them() {
    let h = harness();
    let (ecdsa, address_0) = address_case("ecdsa index 0");
    let (_, address_1) = address_case("ecdsa index 1");
    let signer = register(&h, &ecdsa).await;
    assert_eq!(
        *accounts(&h, &signer).await.ok(200),
        json!({ "accounts": [] })
    );

    let first = create_account(&h, &signer).await.ok(201).clone();
    let keys: Vec<&String> = first.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["account_id", "address", "profile"]);
    assert_eq!(first["address"], json!(address_0));
    assert_eq!(
        first["profile"],
        json!({
            "version": "oaath.kernel-account-profile/v1",
            "kind": "kernel",
            "accountIndex": "0",
            "kernelVersion": "0.4.0",
            "factoryRoute": "kernel_factory",
            "entryPoint": { "version": "0.9" },
            "ownerCredential": ecdsa,
        })
    );
    h.clock.advance(1);
    let second = create_account(&h, &signer).await.ok(201).clone();
    assert_eq!(second["address"], json!(address_1));
    assert_eq!(second["profile"]["accountIndex"], json!("1"));

    assert_eq!(
        *accounts(&h, &signer).await.ok(200),
        json!({ "accounts": [
            {
                "account_id": first["account_id"],
                "address": address_0,
                "role": "root",
                "profile": first["profile"],
            },
            {
                "account_id": second["account_id"],
                "address": address_1,
                "role": "root",
                "profile": second["profile"],
            },
        ] })
    );
}

#[tokio::test]
async fn derives_p256_and_webauthn_roots_at_their_pinned_addresses() {
    let h = harness();
    let (p256, p256_address) = address_case("p256 index 0");
    let signer = register(&h, &p256).await;
    assert_eq!(
        create_account(&h, &signer).await.ok(201)["address"],
        json!(p256_address)
    );
    let (webauthn, webauthn_address) = address_case("webauthn index 1");
    let signer = register(&h, &webauthn).await;
    create_account(&h, &signer).await.ok(201);
    assert_eq!(
        create_account(&h, &signer).await.ok(201)["address"],
        json!(webauthn_address)
    );
}

#[tokio::test]
async fn refuses_an_unknown_signer_and_malformed_requests() {
    let h = harness();
    create_account(&h, "unknown-signer")
        .await
        .failure(E::NotFound);
    accounts(&h, "unknown-signer").await.failure(E::NotFound);
    accounts(&h, "not%20canonical")
        .await
        .failure(E::RequestInvalid);
    for body in [
        json!({}),
        json!({ "root_signer_id": 7 }),
        json!({ "root_signer_id": "a", "account_index": 0 }),
    ] {
        h.send(portal(
            "POST",
            "/portal/accounts",
            Some("same-origin"),
            Some(body),
        ))
        .await
        .failure(E::RequestInvalid);
    }
    h.send(portal("GET", "/portal/signers", Some("same-origin"), None))
        .await
        .failure(E::MethodNotAllowed);
    h.send(portal("GET", "/portal/other", Some("same-origin"), None))
        .await
        .failure(E::NotFound);
}

#[tokio::test]
async fn refuses_cross_site_requests() {
    let h = harness();
    let (ecdsa, _) = address_case("ecdsa index 0");
    let signer = register(&h, &ecdsa).await;
    for site in ["cross-site", "same-site"] {
        for request in [
            portal(
                "POST",
                "/portal/signers",
                Some(site),
                Some(json!({ "profile": ecdsa })),
            ),
            portal(
                "POST",
                "/portal/accounts",
                Some(site),
                Some(json!({ "root_signer_id": signer })),
            ),
            portal(
                "GET",
                &format!("/portal/signers/{signer}/accounts"),
                Some(site),
                None,
            ),
        ] {
            h.send(request).await.failure(E::Forbidden);
        }
    }
    // A refused cross-site create derived nothing.
    assert_eq!(
        *accounts(&h, &signer).await.ok(200),
        json!({ "accounts": [] })
    );
    // Direct navigation and non-browser clients are not cross-site.
    for site in [Some("none"), None] {
        h.send(portal(
            "GET",
            &format!("/portal/signers/{signer}/accounts"),
            site,
            None,
        ))
        .await
        .ok(200);
    }
}

#[tokio::test]
async fn refuses_a_second_root_and_a_membership_on_an_unknown_account() {
    let h = harness();
    let (ecdsa, _) = address_case("ecdsa index 0");
    let (p256, _) = address_case("p256 index 0");
    let root = register(&h, &ecdsa).await;
    let other = register(&h, &p256).await;
    let account = create_account(&h, &root).await.ok(201).clone();
    let membership = |account_id: &str, signer_id: &str| AccountSignerRecord {
        version: ACCOUNT_SIGNER_RECORD_VERSION,
        account_id: account_id.to_owned(),
        signer_id: signer_id.to_owned(),
        role: MembershipRole::Root,
        request_id: None,
        created_at: CLOCK_START,
    };
    let mut transaction = h.store.begin().await.unwrap();
    assert!(
        !transaction
            .insert_account_signer(&membership(text(&account, "account_id"), &other))
            .await
            .unwrap()
    );
    assert!(
        !transaction
            .insert_account_signer(&membership("unknown-account", &other))
            .await
            .unwrap()
    );
    assert!(
        !transaction
            .insert_account_signer(&membership(text(&account, "account_id"), "unknown-signer"))
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
    assert_eq!(
        *accounts(&h, &other).await.ok(200),
        json!({ "accounts": [] })
    );
}

/// A passkey profile whose `authenticatorIdHash` binds `credential_id`, as
/// the SDK enrols it (`keccak256(rawId)`), with a fixture public key.
fn passkey(credential_id: &[u8], public_key_case: &str) -> (Value, String) {
    use base64::Engine;
    let (fixture, _) = address_case(public_key_case);
    let profile = json!({
        "version": "oaath.owner-credential-profile/v1",
        "kind": "webauthn",
        "publicKey": fixture["publicKey"],
        "authenticatorIdHash": format!(
            "0x{}",
            hex::encode(alloy_primitives::keccak256(credential_id))
        ),
    });
    (
        profile,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
    )
}

async fn by_credential(h: &Harness, credential_id: &str, site: Option<&str>) -> Reply {
    h.send(portal(
        "GET",
        &format!("/portal/signers/by-credential/{credential_id}"),
        site,
        None,
    ))
    .await
}

#[tokio::test]
async fn recognises_a_passkey_by_its_credential_id() {
    let h = harness();
    let (profile, credential_id) = passkey(b"credential-1", "webauthn index 0");
    let signer = register(&h, &profile).await;
    assert_eq!(
        *by_credential(&h, &credential_id, Some("same-origin"))
            .await
            .ok(200),
        json!({ "signer_id": signer, "kind": "webauthn", "profile": profile })
    );
    let (_, unknown) = passkey(b"credential-2", "webauthn index 0");
    by_credential(&h, &unknown, Some("same-origin"))
        .await
        .failure(E::NotFound);
    for malformed in ["a+b", "YQ%3D%3D", "Y"] {
        by_credential(&h, malformed, Some("same-origin"))
            .await
            .failure(E::RequestInvalid);
    }
    by_credential(&h, &credential_id, Some("cross-site"))
        .await
        .failure(E::Forbidden);
}

#[tokio::test]
async fn reads_an_ambiguous_credential_as_absent() {
    let h = harness();
    let (profile, credential_id) = passkey(b"credential-1", "webauthn index 0");
    register(&h, &profile).await;
    // Another public key claiming the same authenticator.
    let (mut copied, _) = passkey(b"credential-1", "webauthn index 0");
    copied["publicKey"] = address_case("p256 index 0").0["publicKey"].clone();
    register(&h, &copied).await;
    by_credential(&h, &credential_id, Some("same-origin"))
        .await
        .failure(E::NotFound);
}
