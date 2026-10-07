//! Importing an existing Kernel v4 account over the memory store: the root's
//! one signature over the import statement for every root kind, what is
//! refused, and the imported account then working like a derived one.
//! Restart behavior is in `postgres.rs`.

mod support;

use alloy_primitives::{Address, B256};
use oaath_protocol::identity::{
    KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION, parse_owner_credential_profile,
};
use oaath_relay::account_import::{AccountImport, import_digest};
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::grant::{Root, link_member, root_key, sign_in};
use support::*;

const IMPORTED: &str = "0x00000000000000000000000000000000000000ab";

fn fingerprint(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

/// The import body `signer` signs for `address` and `signed_fingerprint`,
/// submitting `fingerprint`.
fn statement(
    signer: &Root,
    owner: &Root,
    address: &str,
    signed_fingerprint: &str,
    fingerprint: &str,
    issued_at: u64,
    root_signer_id: &str,
) -> Value {
    let owner_hash = parse_owner_credential_profile(&owner.profile())
        .unwrap()
        .hash();
    let digest = import_digest(&AccountImport {
        account: address.parse::<Address>().unwrap(),
        ownerProfileHash: owner_hash,
        inventoryFingerprint: signed_fingerprint.parse::<B256>().unwrap(),
        issuedAt: issued_at,
        nonce: "import-1".to_owned(),
    });
    json!({
        "root_signer_id": root_signer_id,
        "address": address,
        "inventory_fingerprint": fingerprint,
        "issued_at": issued_at,
        "nonce": "import-1",
        "signature": format!("0x{}", hex::encode(signer.sign(digest))),
    })
}

async fn import(h: &Harness, cookie: &str, body: Value) -> Reply {
    h.send(portal_call(
        "POST",
        "/portal/accounts/import",
        Some(cookie),
        Some(body),
    ))
    .await
}

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

#[tokio::test]
async fn each_root_kind_imports_its_account_with_one_signature() {
    for root in roots() {
        let h = harness();
        let (signer_id, cookie) = sign_in(&h, &root).await;
        let fp = fingerprint(0x22);
        // EIP-55 input is accepted and recorded lowercase.
        let checksummed = IMPORTED.parse::<Address>().unwrap().to_checksum(None);
        let imported = import(
            &h,
            &cookie,
            statement(
                &root,
                &root,
                &checksummed,
                &fp,
                &fp,
                CLOCK_SECONDS,
                &signer_id,
            ),
        )
        .await
        .ok(201)
        .clone();
        assert_eq!(imported["address"], IMPORTED);
        assert_eq!(
            imported["profile"],
            json!({
                "version": KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
                "kind": "kernel",
                "address": IMPORTED,
                "kernelVersion": "0.4.0",
                "entryPoint": { "version": "0.9" },
                "ownerCredential": root.profile(),
            })
        );
        let accounts = h
            .send(portal_call(
                "GET",
                &format!("/portal/signers/{signer_id}/accounts"),
                Some(&cookie),
                None,
            ))
            .await
            .ok(200)
            .clone();
        assert_eq!(
            accounts["accounts"],
            json!([{
                "account_id": imported["account_id"],
                "address": IMPORTED,
                "role": "root",
                "status": "active",
                "profile": imported["profile"],
            }])
        );
        // Imported once: by anyone, again.
        import(
            &h,
            &cookie,
            statement(&root, &root, IMPORTED, &fp, &fp, CLOCK_SECONDS, &signer_id),
        )
        .await
        .failure(E::AlreadyDecided);
        let mut transaction = h.store.begin().await.unwrap();
        let evidence = transaction
            .lock_account_import(text(&imported, "account_id"))
            .await
            .unwrap()
            .unwrap();
        transaction.rollback().await;
        assert_eq!(evidence.inventory_fingerprint, fp);
        assert_eq!(evidence.issued_at, CLOCK_SECONDS);
    }
}

#[tokio::test]
async fn refuses_another_key_another_fingerprint_another_session_and_stale_statements() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let (signer_id, cookie) = sign_in(&h, &root).await;
    let other = Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x66; 32]).unwrap());
    let (other_id, other_cookie) = sign_in(&h, &other).await;
    let (shown, signed) = (fingerprint(0x22), fingerprint(0x23));

    for (cookie, body, code) in [
        // Another key signs the root's statement.
        (
            &cookie,
            statement(
                &other,
                &root,
                IMPORTED,
                &shown,
                &shown,
                CLOCK_SECONDS,
                &signer_id,
            ),
            E::Forbidden,
        ),
        // The root signed one fingerprint; another is submitted.
        (
            &cookie,
            statement(
                &root,
                &root,
                IMPORTED,
                &signed,
                &shown,
                CLOCK_SECONDS,
                &signer_id,
            ),
            E::Forbidden,
        ),
        // Another signer's session imports in the root's name.
        (
            &other_cookie,
            statement(
                &root,
                &root,
                IMPORTED,
                &shown,
                &shown,
                CLOCK_SECONDS,
                &signer_id,
            ),
            E::Forbidden,
        ),
        // The statement names another owner than the signer it is submitted as.
        (
            &other_cookie,
            statement(
                &other,
                &root,
                IMPORTED,
                &shown,
                &shown,
                CLOCK_SECONDS,
                &other_id,
            ),
            E::Forbidden,
        ),
        // Older than five minutes, or from the future.
        (
            &cookie,
            statement(
                &root,
                &root,
                IMPORTED,
                &shown,
                &shown,
                CLOCK_SECONDS - 301,
                &signer_id,
            ),
            E::Expired,
        ),
        (
            &cookie,
            statement(
                &root,
                &root,
                IMPORTED,
                &shown,
                &shown,
                CLOCK_SECONDS + 1,
                &signer_id,
            ),
            E::Expired,
        ),
    ] {
        import(&h, cookie, body).await.failure(code);
    }
    for malformed in [
        json!({}),
        {
            let mut body = statement(
                &root,
                &root,
                IMPORTED,
                &shown,
                &shown,
                CLOCK_SECONDS,
                &signer_id,
            );
            body["inventory_fingerprint"] = json!("0x1234");
            body
        },
        {
            let mut body = statement(
                &root,
                &root,
                IMPORTED,
                &shown,
                &shown,
                CLOCK_SECONDS,
                &signer_id,
            );
            body["address"] = json!("0xnot-an-address");
            body
        },
    ] {
        import(&h, &cookie, malformed)
            .await
            .failure(E::RequestInvalid);
    }
    // A registered derived account's address cannot be imported.
    let derived = h
        .send(portal_call(
            "POST",
            "/portal/accounts",
            Some(&cookie),
            Some(json!({ "root_signer_id": signer_id })),
        ))
        .await
        .ok(201)
        .clone();
    import(
        &h,
        &cookie,
        statement(
            &root,
            &root,
            text(&derived, "address"),
            &shown,
            &shown,
            CLOCK_SECONDS,
            &signer_id,
        ),
    )
    .await
    .failure(E::AlreadyDecided);
    // Nothing was imported.
    let accounts = h
        .send(portal_call(
            "GET",
            &format!("/portal/signers/{signer_id}/accounts"),
            Some(&cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(accounts["accounts"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_imported_account_takes_members_and_templates_like_a_derived_one() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let (signer_id, cookie) = sign_in(&h, &root).await;
    let fp = fingerprint(0x22);
    let imported = import(
        &h,
        &cookie,
        statement(&root, &root, IMPORTED, &fp, &fp, CLOCK_SECONDS, &signer_id),
    )
    .await
    .ok(201)
    .clone();
    let account_id = text(&imported, "account_id");

    let passkey = Root::WebAuthn(
        p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap(),
        b"member".to_vec(),
    );
    let (member_id, member_cookie) = sign_in(&h, &passkey).await;
    link_member(&h, IMPORTED, (&member_id, &member_cookie), (&root, &cookie)).await;
    let member_accounts = h
        .send(portal_call(
            "GET",
            &format!("/portal/signers/{member_id}/accounts"),
            Some(&member_cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(member_accounts["accounts"][0]["address"], IMPORTED);
    assert_eq!(member_accounts["accounts"][0]["role"], "permission");

    h.send(portal_call(
        "POST",
        &format!("/portal/accounts/{account_id}/policies"),
        Some(&cookie),
        Some(json!({
            "name": "Payments",
            "lifetime_seconds": 86_400,
            "policy": {
                "calls": [{ "target": format!("0x{}", "aa".repeat(20)), "selector": "0xa9059cbb", "valueLimit": "0" }],
                "perChainOperationLimit": { "count": 1, "intervalSeconds": null },
            },
        })),
    ))
    .await
    .ok(201);
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
    assert_eq!(members["members"].as_array().unwrap().len(), 2);
}
