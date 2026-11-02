//! A local JSON-RPC stand-in for chain 421614 that answers exactly the reads
//! an import proof sends, from a table of accounts. It never touches a
//! network beyond loopback.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::keccak256;
use alloy_sol_types::SolValue;
use axum::Json;
use axum::extract::State;
use axum::routing::post;
use oaath_protocol::identity::OwnerCredentialProfile;
use oaath_relay::chain::{
    ChainReader, ENTRY_POINT_V07, KERNEL_V4_IMPLEMENTATION, KERNEL_V33_ACCOUNT_ID,
    KERNEL_V33_IMPLEMENTATION, P256_ROOT_VALIDATOR, WEBAUTHN_ROOT_VALIDATOR, implementation_word,
    owner_words, root_word,
};
use oaath_relay::registry::ECDSA_ROOT_VALIDATOR;
use serde_json::{Value, json};

/// What the chain holds at one address.
#[derive(Clone)]
pub struct StubAccount {
    pub code: String,
    pub implementation: String,
    pub root_validator: String,
    /// The owner material the root validator stores for this account.
    pub owner: OwnerCredentialProfile,
    /// A Kernel 0.3.3 account's `accountId()`; none for Kernel v4.
    pub account_id: Option<String>,
}

impl StubAccount {
    /// A reviewed Kernel v4 account rooted in `owner`.
    pub fn kernel(owner: &OwnerCredentialProfile) -> Self {
        Self {
            code: "0x6080".to_owned(),
            implementation: KERNEL_V4_IMPLEMENTATION.to_owned(),
            root_validator: validator_for(owner).to_owned(),
            owner: owner.clone(),
            account_id: None,
        }
    }

    /// A Kernel 0.3.3 account rooted in the ECDSA validator storing `owner`,
    /// at `currentNonce()` 1 with no permission enabled.
    pub fn kernel_v33(owner: &OwnerCredentialProfile) -> Self {
        Self {
            code: "0x6080".to_owned(),
            implementation: KERNEL_V33_IMPLEMENTATION.to_owned(),
            root_validator: ECDSA_ROOT_VALIDATOR.to_owned(),
            owner: owner.clone(),
            account_id: Some(KERNEL_V33_ACCOUNT_ID.to_owned()),
        }
    }
}

fn selector(signature: &str) -> String {
    hex::encode(&keccak256(signature.as_bytes())[..4])
}

pub fn validator_for(owner: &OwnerCredentialProfile) -> &'static str {
    match owner {
        OwnerCredentialProfile::Ecdsa { .. } => ECDSA_ROOT_VALIDATOR,
        OwnerCredentialProfile::P256 { .. } => P256_ROOT_VALIDATOR,
        OwnerCredentialProfile::WebAuthn { .. } => WEBAUTHN_ROOT_VALIDATOR,
    }
}

#[derive(Default)]
pub struct StubState {
    pub chain_id: u64,
    pub accounts: HashMap<String, StubAccount>,
    pub delay: Option<Duration>,
}

pub struct StubChain {
    pub url: String,
    pub state: Arc<Mutex<StubState>>,
    calls: Arc<AtomicUsize>,
}

impl StubChain {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn reader(&self) -> Arc<ChainReader> {
        Arc::new(
            ChainReader::new(421_614, &self.url)
                .unwrap()
                .with_timeout(Duration::from_millis(500))
                .unwrap(),
        )
    }
}

fn word(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

async fn answer(
    State((state, calls)): State<(Arc<Mutex<StubState>>, Arc<AtomicUsize>)>,
    Json(request): Json<Value>,
) -> Json<Value> {
    calls.fetch_add(1, Ordering::SeqCst);
    let delay = state.lock().unwrap().delay;
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    }
    let state = state.lock().unwrap();
    let params = &request["params"];
    let account = |index: usize| {
        params[index]
            .as_str()
            .and_then(|address| state.accounts.get(&address.to_lowercase()))
    };
    let result = match request["method"].as_str().unwrap_or_default() {
        "eth_chainId" => json!(format!("0x{:x}", state.chain_id)),
        "eth_blockNumber" => json!("0x10"),
        "eth_getCode" => json!(account(0).map_or("0x".to_owned(), |a| a.code.clone())),
        "eth_getStorageAt" => json!(account(0).map_or(word(&[0; 32]), |a| word(
            implementation_word(&a.implementation).as_slice()
        ))),
        "eth_call" => {
            let to = params[0]["to"].as_str().unwrap_or_default().to_lowercase();
            let data = params[0]["data"].as_str().unwrap_or_default();
            match state.accounts.get(&to) {
                // Kernel 0.3.3's account reads.
                Some(target) if target.account_id.is_some() => {
                    let call = &data[2..10];
                    let mut address = [0u8; 32];
                    address[12..].copy_from_slice(&hex::decode(&ENTRY_POINT_V07[2..]).unwrap());
                    let mut one = [0u8; 32];
                    one[31] = 1;
                    if call == selector("accountId()") {
                        json!(word(
                            &(target.account_id.clone().unwrap(),).abi_encode_params()
                        ))
                    } else if call == selector("entrypoint()") {
                        json!(word(&address))
                    } else if call == selector("currentNonce()") {
                        json!(word(&one))
                    } else if call == selector("validationConfig(bytes21)") {
                        json!(word(&[0; 64]))
                    } else {
                        json!(word(root_word(&target.root_validator).as_slice()))
                    }
                }
                // `root()` on the account.
                Some(target) => json!(word(root_word(&target.root_validator).as_slice())),
                // An owner read on a validator: the account is the argument.
                None => {
                    let argument = format!("0x{}", &data[data.len() - 40..]);
                    match state.accounts.get(&argument) {
                        Some(target) if target.root_validator == to => {
                            json!(word(&owner_words(&target.owner)))
                        }
                        _ => json!(word(&[0; 32])),
                    }
                }
            }
        }
        _ => {
            return Json(
                json!({ "jsonrpc": "2.0", "id": request["id"], "error": { "code": -32601 } }),
            );
        }
    };
    Json(json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }))
}

/// Starts the stand-in on loopback with `accounts` at chain `chain_id`.
pub async fn stub_chain(chain_id: u64, accounts: &[(&str, StubAccount)]) -> StubChain {
    let state = Arc::new(Mutex::new(StubState {
        chain_id,
        accounts: accounts
            .iter()
            .map(|(address, account)| (address.to_lowercase(), account.clone()))
            .collect(),
        ..StubState::default()
    }));
    let calls = Arc::new(AtomicUsize::new(0));
    let router = axum::Router::new()
        .route("/", post(answer))
        .with_state((state.clone(), calls.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    StubChain { url, state, calls }
}
