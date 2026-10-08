//! A loopback chain and bundler stand-in for revocations, and a root whose
//! member holds an approved template grant.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::B256;
use axum::Json;
use axum::extract::State;
use axum::routing::post as route_post;
use k256::ecdsa::SigningKey;
use oaath_relay::bundler::Bundler;
use oaath_relay::chain::ChainReader;
use serde_json::{Value, json};

use super::grant::{Root, approval, root_key, sign_in};
use super::{Harness, Reply, creation_key, portal_call, text};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Send {
    Accept,
    Reject,
    Hang,
}

pub struct Stub {
    pub installed: bool,
    /// The sequence Kernel stores for the enable's install key: 0 leaves the
    /// enable replayable, 1 consumes it.
    pub install_sequence: u64,
    pub deployed: bool,
    pub send: Send,
    pub receipt: Option<Value>,
    pub calls: HashMap<String, usize>,
}

pub type Shared = Arc<Mutex<Stub>>;

fn word(value: u64) -> String {
    format!("0x{value:064x}")
}

async fn answer(State(stub): State<Shared>, Json(request): Json<Value>) -> Json<Value> {
    let method = request["method"].as_str().unwrap_or_default().to_owned();
    let send = {
        let mut stub = stub.lock().unwrap();
        *stub.calls.entry(method.clone()).or_default() += 1;
        stub.send
    };
    if method == "eth_sendUserOperation" && send == Send::Hang {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let stub = stub.lock().unwrap();
    let result = match method.as_str() {
        "eth_chainId" => json!("0x66eee"),
        "eth_blockNumber" => json!("0x10"),
        "eth_getBlockByNumber" => {
            json!({ "number": "0x20", "hash": format!("0x{}", "ab".repeat(32)) })
        }
        "eth_getCode" => json!(if stub.deployed { "0x6080" } else { "0x" }),
        "eth_call" => {
            let data = request["params"][0]["data"].as_str().unwrap_or_default();
            // isModuleInstalled(uint256,address,bytes); Kernel's nonce(uint192);
            // otherwise getNonce on the EntryPoint.
            let nonce_selector = format!(
                "0x{}",
                hex::encode(&alloy_primitives::keccak256(b"nonce(uint192)")[..4])
            );
            if data.starts_with("0x112d3a7d") {
                json!(word(u64::from(stub.installed)))
            } else if data.starts_with(&nonce_selector) {
                // key << 64 | sequence, for the key asked.
                let key = &data[data.len() - 48..];
                json!(format!("0x{:0>48}{:016x}", key, stub.install_sequence))
            } else {
                json!(format!("0x{:064x}", (1u128 << 64) + 3))
            }
        }
        "pimlico_getUserOperationGasPrice" => json!({
            "fast": { "maxFeePerGas": "0x3b9aca00", "maxPriorityFeePerGas": "0x5f5e100" },
        }),
        "eth_estimateUserOperationGas" => json!({
            "callGasLimit": "0x30000",
            "verificationGasLimit": "0x80000",
            "preVerificationGas": "0x10000",
        }),
        "eth_sendUserOperation" if stub.send == Send::Reject => {
            return Json(
                json!({ "jsonrpc": "2.0", "id": request["id"], "error": { "code": -32500 } }),
            );
        }
        "eth_sendUserOperation" => json!(format!("0x{}", "cd".repeat(32))),
        "eth_getUserOperationReceipt" => stub.receipt.clone().unwrap_or(Value::Null),
        _ => {
            return Json(
                json!({ "jsonrpc": "2.0", "id": request["id"], "error": { "code": -32601 } }),
            );
        }
    };
    Json(json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }))
}

/// One loopback JSON-RPC stand-in serving both the chain and the bundler.
pub async fn stub(send: Send) -> (String, Shared) {
    let shared = Arc::new(Mutex::new(Stub {
        installed: true,
        install_sequence: 0,
        deployed: true,
        send,
        receipt: None,
        calls: HashMap::new(),
    }));
    let router = axum::Router::new()
        .route("/", route_post(answer))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (url, shared)
}

pub fn calls(shared: &Shared, method: &str) -> usize {
    shared
        .lock()
        .unwrap()
        .calls
        .get(method)
        .copied()
        .unwrap_or(0)
}

pub fn configure(url: &str) -> impl FnOnce(&mut oaath_relay::RelayOptions) + use<> {
    let url = url.to_owned();
    move |options| {
        options.chain = Some(Arc::new(
            ChainReader::new(421_614, &url)
                .unwrap()
                .with_timeout(Duration::from_millis(500))
                .unwrap(),
        ));
        options.bundler = Some(Arc::new(
            Bundler::with_timeout(421_614, &url, Duration::from_millis(300)).unwrap(),
        ));
    }
}

pub struct Granted {
    pub root: Root,
    pub cookie: String,
    pub account: Value,
    pub member_id: String,
    pub grant_id: String,
}

/// A root's account whose member holds an approved template grant.
pub async fn template_grant(h: &Harness) -> Granted {
    let root = Root::Ecdsa(root_key());
    let (root_id, cookie) = sign_in(h, &root).await;
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
    let policies = format!("/portal/accounts/{}/policies", text(&account, "account_id"));
    let template = h
        .send(portal_call(
            "POST",
            &policies,
            Some(&cookie),
            Some(json!({
                "name": "Payments",
                "lifetime_seconds": 3_600,
                "policy": {
                    "calls": [{ "target": format!("0x{}", "aa".repeat(20)), "selector": "0xa9059cbb", "valueLimit": "0" }],
                    "perChainOperationLimit": { "count": 3, "intervalSeconds": null },
                },
            })),
        ))
        .await
        .ok(201)
        .clone();
    let member = Root::Ecdsa(SigningKey::from_slice(&[0x55; 32]).unwrap());
    let (member_id, member_cookie) = sign_in(h, &member).await;
    let link_id = text(
        h.send(portal_call(
            "POST",
            "/portal/links",
            Some(&member_cookie),
            Some(
                json!({ "signer_id": member_id, "account": account["address"], "label": "Laptop" }),
            ),
        ))
        .await
        .ok(201),
        "link_id",
    )
    .to_owned();
    let selection = json!({ "template_id": template["template_id"] });
    let prepared = h
        .send(portal_call(
            "POST",
            &format!("/portal/links/{link_id}/prepare"),
            Some(&cookie),
            Some(selection),
        ))
        .await
        .ok(200)
        .clone();
    h.send(portal_call(
        "POST",
        &format!("/portal/links/{link_id}/approve"),
        Some(&cookie),
        Some(json!({
            "template_id": template["template_id"],
            "artifact": approval(&prepared, &root).to_string(),
        })),
    ))
    .await
    .ok(200);
    Granted {
        root,
        cookie,
        account,
        member_id,
        grant_id: link_id,
    }
}

pub async fn suspend(h: &Harness, granted: &Granted) {
    h.send(portal_call(
        "POST",
        &format!(
            "/portal/accounts/{}/members/{}/suspend",
            text(&granted.account, "account_id"),
            granted.member_id
        ),
        Some(&granted.cookie),
        Some(json!({})),
    ))
    .await
    .ok(200);
}

pub async fn status(h: &Harness, granted: &Granted) -> Reply {
    h.send(portal_call(
        "GET",
        &format!("/portal/grants/{}/revocation", granted.grant_id),
        Some(&granted.cookie),
        None,
    ))
    .await
}

pub async fn prepare(h: &Harness, granted: &Granted) -> Reply {
    h.send(portal_call(
        "POST",
        &format!("/portal/grants/{}/revocation/prepare", granted.grant_id),
        Some(&granted.cookie),
        Some(json!({ "estimation_signature": format!("0x{}", "11".repeat(65)) })),
    ))
    .await
}

pub async fn sign(h: &Harness, granted: &Granted, request: &Value) -> Reply {
    let digest: B256 = request["userOperationHash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let signature = format!("0x{}", hex::encode(granted.root.sign(digest)));
    h.send(portal_call(
        "POST",
        &format!("/portal/grants/{}/revocation/sign", granted.grant_id),
        Some(&granted.cookie),
        Some(json!({ "signature": signature })),
    ))
    .await
}

pub fn receipt(request: &Value, success: bool) -> Value {
    json!({
        "userOpHash": request["userOperationHash"],
        "sender": request["userOperation"]["sender"],
        "success": success,
        "receipt": { "transactionHash": format!("0x{}", "ef".repeat(32)), "blockNumber": "0x11" },
    })
}
