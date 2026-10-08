//! Authenticated OAuth client ownership through the HTTP/session boundary.
mod support;

use k256::ecdsa::SigningKey;
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::grant::{Root, root_key, sign_in};
use support::*;

fn metadata(name: &str) -> Value {
    json!({"client_name": name, "redirect_uris": [REDIRECT_URI], "revocation_delivery": "relay"})
}

#[tokio::test]
async fn client_management_requires_a_session_and_refuses_foreign_or_public_clients() {
    let h = harness();
    for method in ["GET", "POST", "PUT"] {
        let path = if method == "PUT" {
            "/portal/clients/unknown"
        } else {
            "/portal/clients"
        };
        h.send(portal_call(
            method,
            path,
            None,
            (method != "GET").then(|| metadata("App")),
        ))
        .await
        .failure(E::Unauthenticated);
    }
    let (_, owner) = sign_in(&h, &Root::Ecdsa(root_key())).await;
    let (_, stranger) = sign_in(
        &h,
        &Root::Ecdsa(SigningKey::from_slice(&[0x66; 32]).unwrap()),
    )
    .await;
    let app = h
        .send(portal_call(
            "POST",
            "/portal/clients",
            Some(&owner),
            Some(metadata("Owner app")),
        ))
        .await
        .ok(201)
        .clone();
    let public = h
        .send(post("/oauth/clients", None, Some(metadata("Public app"))))
        .await
        .ok(201)
        .clone();
    for client in [&app, &public] {
        h.send(portal_call(
            "PUT",
            &format!("/portal/clients/{}", text(client, "client_id")),
            Some(&stranger),
            Some(metadata("Stolen")),
        ))
        .await
        .failure(E::NotFound);
    }
    h.send(portal_call(
        "PUT",
        &format!("/portal/clients/{}", text(&public, "client_id")),
        Some(&owner),
        Some(metadata("Claimed")),
    ))
    .await
    .failure(E::NotFound);
    assert_eq!(
        *h.send(portal_call("GET", "/portal/clients", Some(&stranger), None))
            .await
            .ok(200),
        json!({"clients": []})
    );
    for field in ["owner_signer_id", "client_id"] {
        let mut injected = metadata("Injected");
        injected[field] = json!("someone-else");
        h.send(portal_call(
            "POST",
            "/portal/clients",
            Some(&owner),
            Some(injected),
        ))
        .await
        .failure(E::RequestInvalid);
    }
    h.clock.advance(1_800_000);
    h.send(portal_call("GET", "/portal/clients", Some(&owner), None))
        .await
        .failure(E::Unauthenticated);
}

#[tokio::test]
async fn owner_can_create_list_and_update_validated_metadata() {
    let h = harness();
    let (_, cookie) = sign_in(&h, &Root::Ecdsa(root_key())).await;
    let app = h
        .send(portal_call(
            "POST",
            "/portal/clients",
            Some(&cookie),
            Some(metadata("First app")),
        ))
        .await
        .ok(201)
        .clone();
    let path = format!("/portal/clients/{}", text(&app, "client_id"));
    let changed = json!({"client_name": "Renamed app", "redirect_uris": ["https://new.example/callback", "http://localhost:3000/callback"], "token_endpoint_auth_method": "none", "revocation_delivery": "dapp"});
    let updated = h
        .send(portal_call("PUT", &path, Some(&cookie), Some(changed)))
        .await
        .ok(200)
        .clone();
    assert_eq!(updated["client_id"], app["client_id"]);
    assert_eq!(updated["client_name"], "Renamed app");
    assert_eq!(updated["revocation_delivery"], "dapp");
    assert_eq!(
        *h.send(portal_call("GET", "/portal/clients", Some(&cookie), None))
            .await
            .ok(200),
        json!({"clients": [updated.clone()]})
    );
    for invalid in [
        json!([]),
        json!(["http://remote.example/cb"]),
        json!(["https://app.example/cb#fragment"]),
    ] {
        let mut bad = metadata("Bad");
        bad["redirect_uris"] = invalid;
        h.send(portal_call("PUT", &path, Some(&cookie), Some(bad)))
            .await
            .failure(E::RequestInvalid);
    }
    assert_eq!(
        *h.send(portal_call("GET", "/portal/clients", Some(&cookie), None))
            .await
            .ok(200),
        json!({"clients": [updated]})
    );
}

#[test]
fn client_record_refuses_retired_missing_or_malformed_ownership() {
    use oaath_relay::oauth::records::{OAUTH_CLIENT_RECORD_VERSION, OAuthClientRecord};
    let current = json!({"version": OAUTH_CLIENT_RECORD_VERSION, "clientId": "abc", "clientName": "App", "redirectUris": [REDIRECT_URI], "ownerSignerId": null, "revocationDelivery": "relay", "createdAt": CLOCK_START});
    assert!(OAuthClientRecord::parse(&current).is_ok());
    let mut old = current.clone();
    old["version"] = json!("oaath.oauth-client-record/v1");
    assert_eq!(OAuthClientRecord::parse(&old), Err(E::RecordUnreadable));
    let mut missing = current.clone();
    missing.as_object_mut().unwrap().remove("ownerSignerId");
    assert_eq!(OAuthClientRecord::parse(&missing), Err(E::RecordUnreadable));
    for owner in [json!(""), json!(7), json!({})] {
        let mut bad = current.clone();
        bad["ownerSignerId"] = owner;
        assert_eq!(OAuthClientRecord::parse(&bad), Err(E::RecordUnreadable));
    }
}
