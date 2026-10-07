//! Adding a signer to an existing account over the memory store: a link
//! request from the new signer, the root's one signature over the membership
//! approval for every root kind, and removal. Restart behavior is in
//! `postgres.rs`.

mod support;

use alloy_primitives::B256;
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::grant::{Root, root_key, sign_in};
use support::*;

fn roots() -> [Root; 3] {
    [
        Root::Ecdsa(root_key()),
        Root::P256(p256::ecdsa::SigningKey::from_slice(&[0x22; 32]).unwrap()),
        Root::WebAuthn(
            p256::ecdsa::SigningKey::from_slice(&[0x33; 32]).unwrap(),
            b"root-credential".to_vec(),
        ),
    ]
}

/// The new device's passkey.
fn passkey() -> Root {
    Root::WebAuthn(
        p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap(),
        b"second-device".to_vec(),
    )
}

struct Signed {
    signer_id: String,
    cookie: String,
}

async fn signed_in(h: &Harness, root: &Root) -> Signed {
    let (signer_id, cookie) = sign_in(h, root).await;
    Signed { signer_id, cookie }
}

/// A signed-in root and its first account.
async fn open_account(h: &Harness, root: &Root) -> (Signed, Value) {
    let signed = signed_in(h, root).await;
    let account = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&signed.cookie),
            Some(json!({ "root_signer_id": signed.signer_id, "creation_key": creation_key() })),
        ))
        .await
        .ok(201)
        .clone();
    (signed, account)
}

async fn create_link(h: &Harness, signer: &Signed, address: &str) -> Reply {
    h.send(portal_call(
        "POST",
        "/portal/links",
        Some(&signer.cookie),
        Some(json!({ "signer_id": signer.signer_id, "account": address, "label": "Work laptop" })),
    ))
    .await
}

async fn read_link(h: &Harness, link_id: &str, cookie: &str) -> Reply {
    h.send(portal_call(
        "GET",
        &format!("/portal/links/{link_id}"),
        Some(cookie),
        None,
    ))
    .await
}

async fn decide(h: &Harness, link_id: &str, action: &str, cookie: &str, body: Value) -> Reply {
    h.send(portal_call(
        "POST",
        &format!("/portal/links/{link_id}/{action}"),
        Some(cookie),
        Some(body),
    ))
    .await
}

fn signature(root: &Root, view: &Value) -> Value {
    let digest: B256 = text(view, "digest").parse().unwrap();
    json!({ "signature": format!("0x{}", hex::encode(root.sign(digest))) })
}

async fn accounts(h: &Harness, signer: &Signed) -> Value {
    h.send(portal_call(
        "GET",
        &format!("/portal/signers/{}/accounts", signer.signer_id),
        Some(&signer.cookie),
        None,
    ))
    .await
    .ok(200)["accounts"]
        .clone()
}

async fn members(h: &Harness, account_id: &str, cookie: &str) -> Reply {
    h.send(portal_call(
        "GET",
        &format!("/portal/accounts/{account_id}/members"),
        Some(cookie),
        None,
    ))
    .await
}

async fn remove(h: &Harness, account_id: &str, signer_id: &str, cookie: &str) -> Reply {
    h.send(portal_call(
        "DELETE",
        &format!("/portal/accounts/{account_id}/members/{signer_id}"),
        Some(cookie),
        None,
    ))
    .await
}

#[tokio::test]
async fn each_root_kind_admits_a_login_only_member_with_one_signature() {
    for root in roots() {
        let h = harness();
        let (owner, account) = open_account(&h, &root).await;
        let address = text(&account, "address");
        let account_id = text(&account, "account_id");
        let device = signed_in(&h, &passkey()).await;

        // The address is accepted in its EIP-55 form too.
        let checksummed = address
            .parse::<alloy_primitives::Address>()
            .unwrap()
            .to_checksum(None);
        let created = create_link(&h, &device, &checksummed).await.ok(201).clone();
        assert_eq!(created["expires_at"], json!(CLOCK_SECONDS + 3_600));
        let link_id = text(&created, "link_id").to_owned();

        // The requester and the root read the same request.
        let view = read_link(&h, &link_id, &owner.cookie).await.ok(200).clone();
        assert_eq!(read_link(&h, &link_id, &device.cookie).await.ok(200), &view);
        assert_eq!(view["status"], "pending");
        assert_eq!(view["address"], address);
        assert_eq!(view["label"], "Work laptop");
        assert_eq!(view["role"], "permission");
        assert_eq!(view["signer"]["kind"], "webauthn");
        assert_eq!(view["signer"]["profile"], passkey().profile());
        assert_eq!(
            view["typed_data"],
            json!({
                "types": {
                    "EIP712Domain": [
                        { "name": "name", "type": "string" },
                        { "name": "version", "type": "string" },
                    ],
                    "MembershipApproval": [
                        { "name": "account", "type": "address" },
                        { "name": "signerProfileHash", "type": "bytes32" },
                        { "name": "role", "type": "string" },
                        { "name": "issuedAt", "type": "uint64" },
                        { "name": "expiresAt", "type": "uint64" },
                        { "name": "nonce", "type": "string" },
                    ],
                },
                "primaryType": "MembershipApproval",
                "domain": { "name": "OAAth", "version": "1" },
                "message": {
                    "account": address,
                    "signerProfileHash": view["signer"]["profile_hash"],
                    "role": "permission",
                    "issuedAt": CLOCK_SECONDS,
                    "expiresAt": CLOCK_SECONDS + 3_600,
                    "nonce": link_id,
                },
            })
        );
        assert_eq!(accounts(&h, &device).await, json!([]));

        let approved = decide(
            &h,
            &link_id,
            "approve",
            &owner.cookie,
            signature(&root, &view),
        )
        .await
        .ok(200)
        .clone();
        assert_eq!(approved["status"], "approved");
        assert_eq!(
            accounts(&h, &device).await,
            json!([{
                "account_id": account_id,
                "address": address,
                "role": "permission",
                "status": "active",
                "profile": account["profile"],
            }])
        );
        let listed = members(&h, account_id, &owner.cookie).await.ok(200).clone();
        assert_eq!(
            listed["members"],
            json!([
                {
                    "signer_id": owner.signer_id,
                    "kind": root.profile()["kind"],
                    "profile": root.profile(),
                    "role": "root",
                    "link_id": null,
                    "label": null,
                    "grant_id": null,
                    "joined_at": CLOCK_SECONDS,
                    "status": "active",
                    "suspended_at": null,
                },
                {
                    "signer_id": device.signer_id,
                    "kind": "webauthn",
                    "profile": passkey().profile(),
                    "role": "permission",
                    "link_id": link_id,
                    "label": "Work laptop",
                    "grant_id": null,
                    "joined_at": CLOCK_SECONDS,
                    "status": "active",
                    "suspended_at": null,
                },
            ])
        );

        // The link is single use.
        decide(
            &h,
            &link_id,
            "approve",
            &owner.cookie,
            signature(&root, &view),
        )
        .await
        .failure(E::AlreadyDecided);
        // A member cannot ask again.
        create_link(&h, &device, address)
            .await
            .failure(E::AlreadyDecided);

        // Removal is off-chain and leaves the root alone.
        remove(&h, account_id, &owner.signer_id, &owner.cookie)
            .await
            .failure(E::RequestInvalid);
        assert_eq!(
            remove(&h, account_id, &device.signer_id, &owner.cookie)
                .await
                .ok(200),
            &json!({ "removed": 1 })
        );
        assert_eq!(accounts(&h, &device).await, json!([]));
        assert_eq!(
            read_link(&h, &link_id, &owner.cookie).await.ok(200)["status"],
            "removed"
        );
        remove(&h, account_id, &device.signer_id, &owner.cookie)
            .await
            .failure(E::NotFound);
    }
}

#[tokio::test]
async fn the_root_rejects_a_link_once() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let (owner, account) = open_account(&h, &root).await;
    let device = signed_in(&h, &passkey()).await;
    let link = create_link(&h, &device, text(&account, "address"))
        .await
        .ok(201)
        .clone();
    let link_id = text(&link, "link_id");
    let view = read_link(&h, link_id, &owner.cookie).await.ok(200).clone();

    // Rejecting takes no body; only the root decides.
    decide(
        &h,
        link_id,
        "reject",
        &owner.cookie,
        json!({ "reason": "x" }),
    )
    .await
    .failure(E::RequestInvalid);
    decide(&h, link_id, "reject", &device.cookie, json!({}))
        .await
        .failure(E::Forbidden);
    assert_eq!(
        decide(&h, link_id, "reject", &owner.cookie, json!({}))
            .await
            .ok(200)["status"],
        "rejected"
    );
    decide(
        &h,
        link_id,
        "approve",
        &owner.cookie,
        signature(&root, &view),
    )
    .await
    .failure(E::AlreadyDecided);
    assert_eq!(accounts(&h, &device).await, json!([]));
}

#[tokio::test]
async fn refuses_other_approvers_signatures_and_expired_links() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let (owner, account) = open_account(&h, &root).await;
    let device = signed_in(&h, &passkey()).await;
    let link_id = text(
        create_link(&h, &device, text(&account, "address"))
            .await
            .ok(201),
        "link_id",
    )
    .to_owned();
    let view = read_link(&h, &link_id, &owner.cookie).await.ok(200).clone();

    // Another account's root, signing in with its own session, is not this
    // account's root: it can neither read nor approve.
    let stranger_root = Root::P256(p256::ecdsa::SigningKey::from_slice(&[0x55; 32]).unwrap());
    let (stranger, stranger_account) = open_account(&h, &stranger_root).await;
    read_link(&h, &link_id, &stranger.cookie)
        .await
        .failure(E::Forbidden);
    decide(
        &h,
        &link_id,
        "approve",
        &stranger.cookie,
        signature(&stranger_root, &view),
    )
    .await
    .failure(E::Forbidden);
    // The requester cannot approve itself.
    decide(
        &h,
        &link_id,
        "approve",
        &device.cookie,
        signature(&passkey(), &view),
    )
    .await
    .failure(E::Forbidden);

    // The root's session with a forged approval: another key, the approval of
    // a link for another account, and garbage.
    let other_key = Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x66; 32]).unwrap());
    let other_link = text(
        create_link(&h, &device, text(&stranger_account, "address"))
            .await
            .ok(201),
        "link_id",
    )
    .to_owned();
    let other_view = read_link(&h, &other_link, &stranger.cookie)
        .await
        .ok(200)
        .clone();
    for forged in [
        signature(&other_key, &view),
        signature(&root, &other_view),
        json!({ "signature": format!("0x{}", "00".repeat(65)) }),
    ] {
        decide(&h, &link_id, "approve", &owner.cookie, forged)
            .await
            .failure(E::Forbidden);
    }
    for malformed in [
        json!({}),
        json!({ "signature": "0x" }),
        json!({ "signature": "0xZZ" }),
    ] {
        decide(&h, &link_id, "approve", &owner.cookie, malformed)
            .await
            .failure(E::RequestInvalid);
    }
    // The root of the other account cannot decide this link either way.
    decide(&h, &link_id, "reject", &stranger.cookie, json!({}))
        .await
        .failure(E::Forbidden);

    // An hour later the link has expired, and it never decides.
    h.clock.advance(3_600_000);
    // Sessions last half an hour; both sign in again.
    let owner = signed_in(&h, &root).await;
    let device = signed_in(&h, &passkey()).await;
    assert_eq!(
        read_link(&h, &link_id, &owner.cookie).await.ok(200)["status"],
        "expired"
    );
    decide(
        &h,
        &link_id,
        "approve",
        &owner.cookie,
        signature(&root, &view),
    )
    .await
    .failure(E::Expired);
    assert_eq!(accounts(&h, &device).await, json!([]));
}

#[tokio::test]
async fn gates_link_requests_and_member_lists_on_sessions() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let (owner, account) = open_account(&h, &root).await;
    let address = text(&account, "address");
    let account_id = text(&account, "account_id");
    let device = signed_in(&h, &passkey()).await;

    // No session, another signer's session, a malformed or unknown account.
    let body = json!({ "signer_id": device.signer_id, "account": address, "label": "Phone" });
    h.send(portal_call(
        "POST",
        "/portal/links",
        None,
        Some(body.clone()),
    ))
    .await
    .failure(E::Unauthenticated);
    h.send(portal_call(
        "POST",
        "/portal/links",
        Some(&owner.cookie),
        Some(body.clone()),
    ))
    .await
    .failure(E::Forbidden);
    for (account, label) in [
        (json!("0x1234"), json!("Phone")),
        (json!(address), json!("")),
        (json!(address), json!("   ")),
        (json!(address), json!("x".repeat(65))),
    ] {
        h.send(portal_call(
            "POST",
            "/portal/links",
            Some(&device.cookie),
            Some(json!({ "signer_id": device.signer_id, "account": account, "label": label })),
        ))
        .await
        .failure(E::RequestInvalid);
    }
    create_link(&h, &device, &format!("0x{}", "ab".repeat(20)))
        .await
        .failure(E::NotFound);
    // The root is already a member of its own account.
    create_link(&h, &owner, address)
        .await
        .failure(E::AlreadyDecided);
    read_link(&h, "unknown-link", &owner.cookie)
        .await
        .failure(E::NotFound);

    // Only the root lists or removes members.
    members(&h, account_id, &device.cookie)
        .await
        .failure(E::Forbidden);
    remove(&h, account_id, &owner.signer_id, &device.cookie)
        .await
        .failure(E::Forbidden);
    members(&h, "unknown-account", &owner.cookie)
        .await
        .failure(E::NotFound);
}
