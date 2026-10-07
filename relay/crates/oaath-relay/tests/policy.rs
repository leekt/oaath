//! Policy templates and the grants an account root gives its members from
//! them, over the memory store: template CRUD and validation, a link approved
//! with a template (the root's one signature is the member's enable), a later
//! assignment, and who may do each. Restart behavior is in `postgres.rs`.

mod support;

use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::grant::{Root, approval, root_key, sign_in};
use support::*;

/// The new device's passkey.
fn passkey() -> Root {
    Root::WebAuthn(
        p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap(),
        b"second-device".to_vec(),
    )
}

fn template_body(name: &str, value_limit: &str) -> Value {
    json!({
        "name": name,
        "lifetime_seconds": 86_400,
        "policy": {
            "calls": [
                { "target": format!("0x{}", "aa".repeat(20)), "selector": "0xa9059cbb", "valueLimit": "0" },
                { "target": format!("0x{}", "bb".repeat(20)), "selector": "0x12345678", "valueLimit": value_limit },
            ],
            "perChainOperationLimit": { "count": 5, "intervalSeconds": 86_400 },
        },
    })
}

struct Owner {
    signer_id: String,
    cookie: String,
    account: Value,
}

async fn owner(h: &Harness, root: &Root) -> Owner {
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
    Owner {
        signer_id,
        cookie,
        account,
    }
}

fn policies_path(owner: &Owner) -> String {
    format!(
        "/portal/accounts/{}/policies",
        text(&owner.account, "account_id")
    )
}

async fn create_template(h: &Harness, owner: &Owner, body: Value) -> Reply {
    h.send(portal_call(
        "POST",
        &policies_path(owner),
        Some(&owner.cookie),
        Some(body),
    ))
    .await
}

fn post<'a>(
    h: &'a Harness,
    path: &str,
    cookie: &str,
    body: Value,
) -> impl std::future::Future<Output = Reply> + use<'a> {
    h.send(portal_call("POST", path, Some(cookie), Some(body)))
}

/// A pending link from `member` (signed in with `cookie`) to the owner's account.
async fn link(h: &Harness, owner: &Owner, member: &str, cookie: &str) -> String {
    let created = post(
        h,
        "/portal/links",
        cookie,
        json!({ "signer_id": member, "account": owner.account["address"], "label": "Laptop" }),
    )
    .await;
    text(created.ok(201), "link_id").to_owned()
}

#[tokio::test]
async fn the_root_creates_edits_lists_and_deletes_templates_and_nothing_else_does() {
    let h = harness();
    let owner = owner(&h, &Root::Ecdsa(root_key())).await;
    let created = create_template(&h, &owner, template_body("Payments", "1000"))
        .await
        .ok(201)
        .clone();
    let template_id = text(&created, "template_id").to_owned();
    assert_eq!(
        created,
        json!({
            "template_id": template_id,
            "name": "Payments",
            "policy": template_body("Payments", "1000")["policy"],
            "lifetime_seconds": 86_400,
            "created_at": CLOCK_SECONDS,
            "updated_at": CLOCK_SECONDS,
        })
    );
    h.clock.advance(1_000);
    let path = format!("{}/{template_id}", policies_path(&owner));
    let updated = h
        .send(portal_call(
            "PUT",
            &path,
            Some(&owner.cookie),
            Some(template_body("Payments v2", "5")),
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(updated["name"], "Payments v2");
    assert_eq!(updated["updated_at"], json!(CLOCK_SECONDS + 1));
    assert_eq!(updated["created_at"], json!(CLOCK_SECONDS));
    let listed = h
        .send(portal_call(
            "GET",
            &policies_path(&owner),
            Some(&owner.cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(listed, json!({ "policies": [updated] }));

    // Only what the SDK compiles: no argument rules, no extra keys, at least
    // one call, a bounded lifetime and a named template.
    let mut refused = Vec::new();
    let mut argument_rules = template_body("x", "1");
    argument_rules["policy"]["calls"][0]["argumentEquals"] =
        json!([{ "index": 0, "value": format!("0x{}", "00".repeat(32)) }]);
    refused.push(argument_rules);
    let mut no_calls = template_body("x", "1");
    no_calls["policy"]["calls"] = json!([]);
    refused.push(no_calls);
    let mut windowed = template_body("x", "1");
    windowed["policy"]["validUntil"] = json!(1);
    refused.push(windowed);
    for lifetime in [json!(0), json!(59), json!(366 * 86_400 + 1), json!("86400")] {
        let mut body = template_body("x", "1");
        body["lifetime_seconds"] = lifetime;
        refused.push(body);
    }
    let mut selector = template_body("x", "1");
    selector["policy"]["calls"][0]["selector"] = json!("0x1234");
    refused.push(selector);
    refused.push(template_body("   ", "1"));
    let mut extra = template_body("x", "1");
    extra["owner"] = json!("someone");
    refused.push(extra);
    for body in refused {
        create_template(&h, &owner, body)
            .await
            .failure(E::RequestInvalid);
    }

    // Another signer, even the root of another account, manages none of them.
    let other = owner_of_another(&h).await;
    for (method, path, body) in [
        ("GET", policies_path(&owner), None),
        ("POST", policies_path(&owner), Some(template_body("x", "1"))),
        ("PUT", path.clone(), Some(template_body("x", "1"))),
        ("DELETE", path.clone(), None),
    ] {
        h.send(portal_call(method, &path, Some(&other.cookie), body))
            .await
            .failure(E::Forbidden);
    }
    h.send(portal_call("GET", &policies_path(&owner), None, None))
        .await
        .failure(E::Unauthenticated);

    assert_eq!(
        h.send(portal_call("DELETE", &path, Some(&owner.cookie), None))
            .await
            .ok(200),
        &json!({})
    );
    h.send(portal_call("DELETE", &path, Some(&owner.cookie), None))
        .await
        .failure(E::NotFound);
}

async fn owner_of_another(h: &Harness) -> Owner {
    owner(
        h,
        &Root::P256(p256::ecdsa::SigningKey::from_slice(&[0x55; 32]).unwrap()),
    )
    .await
}

#[tokio::test]
async fn a_link_approved_with_a_template_gives_the_member_a_root_signed_grant() {
    for root in [
        Root::Ecdsa(root_key()),
        Root::WebAuthn(
            p256::ecdsa::SigningKey::from_slice(&[0x33; 32]).unwrap(),
            b"root-credential".to_vec(),
        ),
    ] {
        let h = harness();
        let owner = owner(&h, &root).await;
        let template_id = text(
            create_template(&h, &owner, template_body("Payments", "1000"))
                .await
                .ok(201),
            "template_id",
        )
        .to_owned();
        let (member_id, member_cookie) = sign_in(&h, &passkey()).await;
        let link_id = link(&h, &owner, &member_id, &member_cookie).await;
        let prepare = |cookie: &str| {
            post(
                &h,
                &format!("/portal/links/{link_id}/prepare"),
                cookie,
                json!({ "template_id": template_id }),
            )
        };
        // Only the root prepares.
        prepare(&member_cookie).await.failure(E::Forbidden);
        let prepared = prepare(&owner.cookie).await.ok(200).clone();
        let request = &prepared["permission_request"];
        assert_eq!(request["requestId"], json!(link_id));
        assert_eq!(
            request["operatorCredential"],
            json!({
                "version": "oaath.operator-credential-profile/v1",
                "kind": "webauthn",
                "publicKey": passkey().profile()["publicKey"],
                "authenticatorIdHash": passkey().profile()["authenticatorIdHash"],
            })
        );
        assert_eq!(request["application"]["clientId"], "oaath-portal");
        assert_eq!(request["application"]["origin"], ISSUER);
        assert_eq!(request["context"]["accountId"], owner.account["address"]);
        assert_eq!(request["policy"]["validAfter"], json!(CLOCK_SECONDS));
        assert_eq!(
            request["policy"]["validUntil"],
            json!(CLOCK_SECONDS + 86_400)
        );
        assert_eq!(request["expiresAt"], json!(CLOCK_SECONDS + 86_401));

        // The root's one signature is the enable over the member's install.
        let artifact = approval(&prepared, &root);
        let approve = |artifact: &Value| {
            post(
                &h,
                &format!("/portal/links/{link_id}/approve"),
                &owner.cookie,
                json!({ "template_id": template_id, "artifact": artifact.to_string() }),
            )
        };
        // Another key's enable is refused before anything is written.
        approve(&approval(
            &prepared,
            &Root::Ecdsa(k256::ecdsa::SigningKey::from_slice(&[0x66; 32]).unwrap()),
        ))
        .await
        .failure(E::RequestInvalid);
        let approved = approve(&artifact).await.ok(200).clone();
        assert_eq!(approved["status"], "approved");
        assert_eq!(approved["grant_id"], json!(link_id));
        approve(&artifact).await.failure(E::AlreadyDecided);

        // The member signs in as the account, and holds the grant.
        let members = h
            .send(portal_call(
                "GET",
                &format!(
                    "/portal/accounts/{}/members",
                    text(&owner.account, "account_id")
                ),
                Some(&owner.cookie),
                None,
            ))
            .await
            .ok(200)
            .clone();
        let rows: Vec<(Value, Value)> = members["members"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|member| member["signer_id"] == json!(member_id))
            .map(|member| (member["link_id"].clone(), member["grant_id"].clone()))
            .collect();
        assert!(rows.contains(&(json!(link_id), json!(null))));
        assert!(rows.contains(&(json!(null), json!(link_id))));
        assert_eq!(rows.len(), 2);
        let view = |cookie: &str| {
            h.send(portal_call(
                "GET",
                &format!("/portal/grants/{link_id}"),
                Some(cookie),
                None,
            ))
        };
        let grant = view(&member_cookie).await.ok(200).clone();
        assert_eq!(grant["status"], "approved");
        assert_eq!(grant["permission_request"], *request);
        assert_eq!(grant["enable"], artifact["installApproval"]);
        assert_eq!(view(&owner.cookie).await.ok(200), &grant);
        view(&owner_of_another(&h).await.cookie)
            .await
            .failure(E::Forbidden);

        // Suspension invalidates it, as for any grant.
        post(
            &h,
            &format!(
                "/portal/accounts/{}/members/{member_id}/suspend",
                text(&owner.account, "account_id")
            ),
            &owner.cookie,
            json!({}),
        )
        .await
        .ok(200);
        assert_eq!(view(&owner.cookie).await.ok(200)["status"], "invalidated");
    }
}

#[tokio::test]
async fn refuses_a_p256_member_and_a_template_edited_after_preparation() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let owner = owner(&h, &root).await;
    let template_id = text(
        create_template(&h, &owner, template_body("Payments", "1000"))
            .await
            .ok(201),
        "template_id",
    )
    .to_owned();
    let prepare = |link_id: &str| {
        post(
            &h,
            &format!("/portal/links/{link_id}/prepare"),
            &owner.cookie,
            json!({ "template_id": template_id }),
        )
    };

    // A raw P-256 key has no operator kind: it can sign in, not hold a policy.
    let (p256_id, p256_cookie) = sign_in(
        &h,
        &Root::P256(p256::ecdsa::SigningKey::from_slice(&[0x77; 32]).unwrap()),
    )
    .await;
    let p256_link = link(&h, &owner, &p256_id, &p256_cookie).await;
    prepare(&p256_link).await.failure(E::RequestInvalid);

    let (member_id, member_cookie) = sign_in(&h, &passkey()).await;
    let link_id = link(&h, &owner, &member_id, &member_cookie).await;
    let prepared = prepare(&link_id).await.ok(200).clone();
    h.send(portal_call(
        "PUT",
        &format!("{}/{template_id}", policies_path(&owner)),
        Some(&owner.cookie),
        Some(template_body("Payments", "1")),
    ))
    .await
    .ok(200);
    post(
        &h,
        &format!("/portal/links/{link_id}/approve"),
        &owner.cookie,
        json!({ "template_id": template_id, "artifact": approval(&prepared, &root).to_string() }),
    )
    .await
    .failure(E::RequestInvalid);
    // An unknown template, and another account's.
    let other = owner_of_another(&h).await;
    let foreign = text(
        create_template(&h, &other, template_body("Theirs", "1"))
            .await
            .ok(201),
        "template_id",
    )
    .to_owned();
    for template in ["unknown", foreign.as_str()] {
        post(
            &h,
            &format!("/portal/links/{link_id}/prepare"),
            &owner.cookie,
            json!({ "template_id": template }),
        )
        .await
        .failure(E::NotFound);
    }
    // The link is still pending.
    let view = h
        .send(portal_call(
            "GET",
            &format!("/portal/links/{link_id}"),
            Some(&owner.cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    assert_eq!(view["status"], "pending");
    assert_eq!(view["grant_id"], Value::Null);
}

#[tokio::test]
async fn the_root_assigns_a_template_to_an_existing_member_with_a_fresh_signature() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let owner = owner(&h, &root).await;
    let account_id = text(&owner.account, "account_id").to_owned();
    let template_id = text(
        create_template(&h, &owner, template_body("Payments", "1000"))
            .await
            .ok(201),
        "template_id",
    )
    .to_owned();
    let (member_id, member_cookie) = sign_in(&h, &passkey()).await;
    support::grant::link_member(
        &h,
        text(&owner.account, "address"),
        (&member_id, &member_cookie),
        (&root, &owner.cookie),
    )
    .await;
    let grants = format!("/portal/accounts/{account_id}/members/{member_id}/grants");
    let selection = json!({ "template_id": template_id });

    // Only the root, and never for the root itself.
    post(
        &h,
        &format!("{grants}/prepare"),
        &member_cookie,
        selection.clone(),
    )
    .await
    .failure(E::Forbidden);
    post(
        &h,
        &format!(
            "/portal/accounts/{account_id}/members/{}/grants/prepare",
            owner.signer_id
        ),
        &owner.cookie,
        selection.clone(),
    )
    .await
    .failure(E::RequestInvalid);

    let mut issued = Vec::new();
    for _ in 0..2 {
        let prepared = post(
            &h,
            &format!("{grants}/prepare"),
            &owner.cookie,
            selection.clone(),
        )
        .await
        .ok(200)
        .clone();
        let request = &prepared["permission_request"];
        let mut artifact = approval(&prepared, &root);
        artifact["decidedAt"] = request["requestedAt"].clone();
        let assigned = post(
            &h,
            &grants,
            &owner.cookie,
            json!({
                "template_id": template_id,
                "request_id": request["requestId"],
                "requested_at": request["requestedAt"],
                "artifact": artifact.to_string(),
            }),
        )
        .await
        .ok(201)
        .clone();
        assert_eq!(assigned["grant_id"], request["requestId"]);
        // A replay of the same decision is refused.
        post(
            &h,
            &grants,
            &owner.cookie,
            json!({
                "template_id": template_id,
                "request_id": request["requestId"],
                "requested_at": request["requestedAt"],
                "artifact": artifact.to_string(),
            }),
        )
        .await
        .failure(E::AlreadyDecided);
        issued.push(text(&assigned, "grant_id").to_owned());
        h.clock.advance(1_000);
    }
    // Both grants stand: a new one never replaces an earlier one.
    for grant_id in &issued {
        assert_eq!(
            h.send(portal_call(
                "GET",
                &format!("/portal/grants/{grant_id}"),
                Some(&member_cookie),
                None,
            ))
            .await
            .ok(200)["status"],
            "approved"
        );
    }
    // A preparation older than ten minutes is refused.
    let prepared = post(&h, &format!("{grants}/prepare"), &owner.cookie, selection)
        .await
        .ok(200)
        .clone();
    h.clock.advance(601_000);
    let request = &prepared["permission_request"];
    post(
        &h,
        &grants,
        &owner.cookie,
        json!({
            "template_id": template_id,
            "request_id": request["requestId"],
            "requested_at": request["requestedAt"],
            "artifact": approval(&prepared, &root).to_string(),
        }),
    )
    .await
    .failure(E::Expired);
}
