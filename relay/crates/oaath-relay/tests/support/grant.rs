//! Grant test helpers: a dapp `oaath_grant` detail and root keys that sign a
//! prepared replayable install the way the SDK key profiles do.
#![allow(dead_code)]

use alloy_primitives::{B256, keccak256};
use k256::ecdsa::SigningKey;
use oaath_relay::grant::approval::capability_hash;
use serde_json::{Value, json};

use super::{CLOCK_SECONDS, Harness, ISSUER, cookie_of, portal_call};

pub fn root_key() -> SigningKey {
    SigningKey::from_slice(&[0x11; 32]).unwrap()
}

pub fn address_of(key: &SigningKey) -> String {
    let point = key.verifying_key().to_encoded_point(false);
    format!(
        "0x{}",
        hex::encode(&keccak256(&point.as_bytes()[1..])[12..])
    )
}

pub fn policy(value_limit: &str) -> Value {
    json!({
        "version": "oaath.grant-policy/v1",
        "calls": [
            { "target": format!("0x{}", "aa".repeat(20)), "selector": "0xa9059cbb", "valueLimit": "0", "argumentEquals": [] },
            { "target": format!("0x{}", "bb".repeat(20)), "selector": "0x12345678", "valueLimit": value_limit, "argumentEquals": [] },
        ],
        "validAfter": CLOCK_SECONDS,
        "validUntil": CLOCK_SECONDS + 3_600,
        "perChainOperationLimit": { "count": 10, "intervalSeconds": null },
    })
}

pub fn detail() -> Value {
    json!({
        "type": "oaath_grant",
        "signer": {
            "version": "oaath.operator-credential-profile/v1",
            "kind": "ecdsa",
            "address": format!("0x{}", "44".repeat(20)),
        },
        "policy": policy("1000"),
        "chains": [8453, 1],
        "expires_at": CLOCK_SECONDS + 7_200,
        "device_id": "device-1",
    })
}

/// A root key that signs a replayable-install digest as its SDK key profile.
pub enum Root {
    Ecdsa(SigningKey),
    P256(p256::ecdsa::SigningKey),
    WebAuthn(p256::ecdsa::SigningKey, Vec<u8>),
}

impl Root {
    pub fn profile(&self) -> Value {
        let version = "oaath.owner-credential-profile/v1";
        let point = |key: &p256::ecdsa::SigningKey| {
            format!(
                "0x{}",
                hex::encode(key.verifying_key().to_encoded_point(false).as_bytes())
            )
        };
        match self {
            Root::Ecdsa(key) => {
                json!({ "version": version, "kind": "ecdsa", "address": address_of(key) })
            }
            Root::P256(key) => {
                json!({ "version": version, "kind": "p256", "publicKey": point(key) })
            }
            Root::WebAuthn(key, credential_id) => json!({
                "version": version,
                "kind": "webauthn",
                "publicKey": point(key),
                "authenticatorIdHash": format!("0x{}", hex::encode(keccak256(credential_id))),
            }),
        }
    }

    pub fn sign(&self, digest: B256) -> Vec<u8> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let p256_sign = |key: &p256::ecdsa::SigningKey, prehash: &[u8]| {
            let signature: p256::ecdsa::Signature = key.sign_prehash(prehash).unwrap();
            signature.normalize_s().unwrap_or(signature)
        };
        match self {
            Root::Ecdsa(key) => {
                let (signature, recovery) = key.sign_prehash_recoverable(&digest.0).unwrap();
                [signature.to_bytes().to_vec(), vec![27 + recovery.to_byte()]].concat()
            }
            Root::P256(key) => p256_sign(key, &digest.0).to_bytes().to_vec(),
            Root::WebAuthn(key, _) => webauthn_assertion(key, digest, "oaath.test", ISSUER),
        }
    }

    /// The sign-in proof for an issued challenge: a `personal_sign` of the
    /// SIWE message, or the key's signature over the nonce bytes.
    pub fn prove(&self, challenge: &Value) -> String {
        let signature = match self {
            Root::Ecdsa(key) => {
                let message = challenge["message"].as_str().unwrap();
                let hash = alloy_primitives::eip191_hash_message(message.as_bytes());
                let (signature, recovery) = key.sign_prehash_recoverable(&hash.0).unwrap();
                [signature.to_bytes().to_vec(), vec![27 + recovery.to_byte()]].concat()
            }
            _ => self.sign(challenge["nonce"].as_str().unwrap().parse().unwrap()),
        };
        format!("0x{}", hex::encode(signature))
    }
}

/// Registers `root`, signs in through the wire, and answers its signer id and
/// session `Cookie` header value.
pub async fn sign_in(h: &Harness, root: &Root) -> (String, String) {
    let registered = h
        .send(portal_call(
            "POST",
            "/portal/signers",
            None,
            Some(json!({ "profile": root.profile() })),
        ))
        .await;
    let signer_id = registered.ok(200)["signer_id"].as_str().unwrap().to_owned();
    let challenge = h
        .send(portal_call(
            "POST",
            "/portal/sessions/challenge",
            None,
            Some(json!({ "signer_id": signer_id })),
        ))
        .await
        .ok(200)
        .clone();
    let reply = h
        .send(portal_call(
            "POST",
            "/portal/sessions",
            None,
            Some(json!({
                "signer_id": signer_id,
                "nonce": challenge["nonce"],
                "signature": root.prove(&challenge),
            })),
        ))
        .await;
    reply.ok(200);
    (signer_id, cookie_of(&reply))
}

/// The reviewed validator's ABI assertion envelope over `digest` (the WebAuthn
/// challenge), with user presence and verification, for `rp_id` and `origin`.
pub fn webauthn_assertion(
    key: &p256::ecdsa::SigningKey,
    digest: B256,
    rp_id: &str,
    origin: &str,
) -> Vec<u8> {
    use alloy_sol_types::SolValue;
    use base64::Engine;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};
    let authenticator_data = [
        Sha256::digest(rp_id.as_bytes()).to_vec(),
        vec![0x05, 0, 0, 0, 1],
    ]
    .concat();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.0);
    let client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    );
    let message = Sha256::digest(
        [
            authenticator_data.clone(),
            Sha256::digest(client_data.as_bytes()).to_vec(),
        ]
        .concat(),
    );
    let signature: p256::ecdsa::Signature = key.sign_prehash(&message).unwrap();
    let signature = signature.normalize_s().unwrap_or(signature);
    let (r, s) = signature.split_bytes();
    (
        alloy_primitives::Bytes::from(authenticator_data),
        client_data,
        alloy_primitives::U256::from(1),
        alloy_primitives::U256::from_be_slice(&r),
        alloy_primitives::U256::from_be_slice(&s),
        false,
    )
        .abi_encode_params()
}

/// The SDK-shaped approval artifact for a prepared grant, signed by `root`.
pub fn approval(prepared: &Value, root: &Root) -> Value {
    let signing = &prepared["signing_request"];
    let digest: B256 = signing["expectedDigest"].as_str().unwrap().parse().unwrap();
    let enable = root.sign(digest);
    let message = &signing["typedData"]["message"];
    let packages: Vec<Value> = message["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|install| {
            let mut install = install.clone();
            install["moduleType"] = json!(
                install["moduleType"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            );
            install
        })
        .collect();
    json!({
        "version": "oaath.permission-decision/v1",
        "kind": "approve",
        "requestId": prepared["permission_request"]["requestId"],
        "requestHash": prepared["request_hash"],
        "decidedAt": CLOCK_SECONDS,
        "approvedPolicy": prepared["approved_policy"],
        "capabilityHash": format!("{:#x}", capability_hash(digest, &enable)),
        "installApproval": {
            "version": "oaath.kernel.all-chain-approval/v1",
            "account": signing["signer"]["account"],
            "installNonce": message["nonce"],
            "packages": packages,
            "digest": signing["expectedDigest"],
            "enableSignature": format!("0x{}", hex::encode(&enable)),
        },
    })
}

/// Links `member` (signed in with `member_cookie`) to the account at
/// `address`, approved by its `root` through the wire.
pub async fn link_member(
    h: &Harness,
    address: &str,
    (member_id, member_cookie): (&str, &str),
    (root, root_cookie): (&Root, &str),
) {
    let created = h
        .send(portal_call(
            "POST",
            "/portal/links",
            Some(member_cookie),
            Some(json!({ "signer_id": member_id, "account": address, "label": "Member" })),
        ))
        .await;
    let link_id = created.ok(201)["link_id"].as_str().unwrap().to_owned();
    let view = h
        .send(portal_call(
            "GET",
            &format!("/portal/links/{link_id}"),
            Some(root_cookie),
            None,
        ))
        .await
        .ok(200)
        .clone();
    let digest: B256 = view["digest"].as_str().unwrap().parse().unwrap();
    h.send(portal_call(
        "POST",
        &format!("/portal/links/{link_id}/approve"),
        Some(root_cookie),
        Some(json!({ "signature": format!("0x{}", hex::encode(root.sign(digest))) })),
    ))
    .await
    .ok(200);
}
