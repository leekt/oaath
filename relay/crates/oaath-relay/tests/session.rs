//! Portal sessions over the memory store: Sign-In with Ethereum and passkey
//! proofs, single-use expiring nonces, and the session cookie, read back
//! through the session owner (`session_signer`). Restart behavior is in
//! `postgres.rs`.

mod support;

use alloy_primitives::B256;
use k256::ecdsa::SigningKey;
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::grant::{Root, root_key, sign_in, webauthn_assertion};
use support::*;

async fn register(h: &Harness, root: &Root) -> String {
    let reply = h
        .send(portal_call(
            "POST",
            "/portal/signers",
            None,
            Some(json!({ "profile": root.profile() })),
        ))
        .await;
    text(reply.ok(200), "signer_id").to_owned()
}

async fn challenge(h: &Harness, body: Value) -> Reply {
    h.send(portal_call(
        "POST",
        "/portal/sessions/challenge",
        None,
        Some(body),
    ))
    .await
}

async fn prove(h: &Harness, signer_id: &str, nonce: &Value, signature: &str) -> Reply {
    h.send(portal_call(
        "POST",
        "/portal/sessions",
        None,
        Some(json!({ "signer_id": signer_id, "nonce": nonce, "signature": signature })),
    ))
    .await
}

/// The signer of the session `cookie` names, as the session owner reads it.
async fn session_of(h: &Harness, cookie: Option<&str>) -> Result<String, E> {
    let request = portal_call("GET", "/", cookie, None);
    oaath_relay::session::session_signer(h.store.as_ref(), h.clock.as_ref(), request.headers())
        .await
}

fn personal_sign(key: &SigningKey, message: &str) -> String {
    let hash = alloy_primitives::eip191_hash_message(message.as_bytes());
    let (signature, recovery) = key.sign_prehash_recoverable(&hash.0).unwrap();
    format!(
        "0x{}{:02x}",
        hex::encode(signature.to_bytes()),
        27 + recovery.to_byte()
    )
}

#[tokio::test]
async fn signs_in_an_ecdsa_signer_with_sign_in_with_ethereum() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let signer_id = register(&h, &root).await;
    let issued = challenge(&h, json!({ "signer_id": signer_id }))
        .await
        .ok(200)
        .clone();
    let nonce = text(&issued, "nonce");
    assert_eq!(nonce.len(), 64);
    assert_eq!(issued["expires_at"], json!(CLOCK_SECONDS + 300));
    let checksummed = support::grant::address_of(&root_key())
        .parse::<alloy_primitives::Address>()
        .unwrap()
        .to_checksum(None);
    assert_eq!(
        text(&issued, "message"),
        format!(
            "oaath.test wants you to sign in with your Ethereum account:\n\
             {checksummed}\n\n\
             Sign in to OAAth. This signature approves nothing.\n\n\
             URI: {ISSUER}\n\
             Version: 1\n\
             Chain ID: 421614\n\
             Nonce: {nonce}\n\
             Issued At: 2023-11-14T22:13:20Z\n\
             Expiration Time: 2023-11-14T22:18:20Z"
        )
    );

    let reply = prove(&h, &signer_id, &issued["nonce"], &root.prove(&issued)).await;
    assert_eq!(
        *reply.ok(200),
        json!({ "signer_id": signer_id, "expires_at": CLOCK_SECONDS + 1_800 })
    );
    let set_cookie = reply.headers["set-cookie"].to_str().unwrap();
    let token = cookie_of(&reply);
    assert!(token.starts_with("oaath_portal_session="));
    assert_eq!(
        set_cookie,
        format!("{token}; Max-Age=1800; Path=/portal; HttpOnly; Secure; SameSite=Strict")
    );
    assert_eq!(session_of(&h, Some(&token)).await, Ok(signer_id.clone()));

    // The nonce is single use.
    prove(&h, &signer_id, &issued["nonce"], &root.prove(&issued))
        .await
        .failure(E::Unauthenticated);
}

#[tokio::test]
async fn refuses_another_key_domain_uri_and_an_unknown_or_expired_nonce() {
    let h = harness();
    let root = Root::Ecdsa(root_key());
    let signer_id = register(&h, &root).await;
    let issued = challenge(&h, json!({ "signer_id": signer_id }))
        .await
        .ok(200)
        .clone();
    let message = text(&issued, "message");
    let nonce = &issued["nonce"];

    // Another key, and the right key over another domain or URI.
    let other = SigningKey::from_slice(&[0x66; 32]).unwrap();
    for signature in [
        personal_sign(&other, message),
        personal_sign(
            &root_key(),
            &message.replace("oaath.test wants", "evil.example wants"),
        ),
        personal_sign(
            &root_key(),
            &message.replace(&format!("URI: {ISSUER}"), "URI: https://evil.example"),
        ),
        // The raw nonce is not the sign-in message.
        format!(
            "0x{}",
            hex::encode(root.sign(nonce.as_str().unwrap().parse::<B256>().unwrap()))
        ),
    ] {
        prove(&h, &signer_id, nonce, &signature)
            .await
            .failure(E::Unauthenticated);
    }
    // A refused proof consumed nothing: the genuine signature still signs in.
    prove(&h, &signer_id, nonce, &personal_sign(&root_key(), message))
        .await
        .ok(200);

    // An unknown nonce, and malformed proofs.
    prove(
        &h,
        &signer_id,
        &json!("ab".repeat(32)),
        &root.prove(&issued),
    )
    .await
    .failure(E::Unauthenticated);
    for body in [
        json!({ "signer_id": signer_id, "nonce": "AB".repeat(32), "signature": "0x00" }),
        json!({ "signer_id": signer_id, "nonce": nonce, "signature": "00" }),
        json!({ "signer_id": signer_id, "nonce": nonce }),
    ] {
        h.send(portal_call("POST", "/portal/sessions", None, Some(body)))
            .await
            .failure(E::RequestInvalid);
    }

    // An expired nonce.
    let late = challenge(&h, json!({ "signer_id": signer_id }))
        .await
        .ok(200)
        .clone();
    h.clock.advance(300_000);
    prove(&h, &signer_id, &late["nonce"], &root.prove(&late))
        .await
        .failure(E::Expired);

    // Challenges name a known signer or none.
    challenge(&h, json!({ "signer_id": "unknown-signer" }))
        .await
        .failure(E::NotFound);
    challenge(&h, json!({ "signer_id": signer_id, "x": 1 }))
        .await
        .failure(E::RequestInvalid);
}

#[tokio::test]
async fn signs_in_a_passkey_with_an_assertion_over_the_nonce() {
    let h = harness();
    let key = p256::ecdsa::SigningKey::from_slice(&[0x33; 32]).unwrap();
    let root = Root::WebAuthn(key.clone(), b"credential-1".to_vec());
    let signer_id = register(&h, &root).await;
    // A passkey challenge names no signer: the authenticator picks the credential.
    let issued = challenge(&h, json!({})).await.ok(200).clone();
    assert_eq!(issued.as_object().unwrap().len(), 2);
    let digest: B256 = text(&issued, "nonce").parse().unwrap();
    let assertion = |digest: B256, rp_id: &str, origin: &str| {
        format!(
            "0x{}",
            hex::encode(webauthn_assertion(&key, digest, rp_id, origin))
        )
    };

    for signature in [
        assertion(B256::repeat_byte(0xab), "oaath.test", ISSUER),
        assertion(digest, "oaath.test", "https://evil.example"),
        assertion(digest, "evil.example", ISSUER),
    ] {
        prove(&h, &signer_id, &issued["nonce"], &signature)
            .await
            .failure(E::Unauthenticated);
    }
    let reply = prove(
        &h,
        &signer_id,
        &issued["nonce"],
        &assertion(digest, "oaath.test", ISSUER),
    )
    .await;
    reply.ok(200);
    assert_eq!(
        session_of(&h, Some(&cookie_of(&reply))).await,
        Ok(signer_id)
    );
}

#[tokio::test]
async fn ends_a_session_on_sign_out_and_expiry_only() {
    let h = harness();
    let (signer_id, cookie) = sign_in(&h, &Root::Ecdsa(root_key())).await;
    let other = Root::P256(p256::ecdsa::SigningKey::from_slice(&[0x22; 32]).unwrap());
    let (other_id, other_cookie) = sign_in(&h, &other).await;
    assert_eq!(session_of(&h, None).await, Err(E::Unauthenticated));
    assert_eq!(
        session_of(&h, Some("oaath_portal_session=forged")).await,
        Err(E::Unauthenticated)
    );
    assert_eq!(session_of(&h, Some(&cookie)).await, Ok(signer_id));

    // Sign-out ends only that session and clears the cookie.
    let out = h
        .send(portal_call(
            "DELETE",
            "/portal/sessions",
            Some(&cookie),
            None,
        ))
        .await;
    assert_eq!(*out.ok(200), json!({}));
    assert_eq!(
        out.headers["set-cookie"],
        "oaath_portal_session=; Max-Age=0; Path=/portal; HttpOnly; Secure; SameSite=Strict"
    );
    assert_eq!(session_of(&h, Some(&cookie)).await, Err(E::Unauthenticated));
    assert_eq!(session_of(&h, Some(&other_cookie)).await, Ok(other_id));

    // Expiry ends a session.
    h.clock.advance(1_800_000);
    assert_eq!(
        session_of(&h, Some(&other_cookie)).await,
        Err(E::Unauthenticated)
    );

    // Sessions are same-origin like every portal route.
    let mut cross = portal_call("DELETE", "/portal/sessions", None, None);
    cross
        .headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    h.send(cross).await.failure(E::Forbidden);
}
