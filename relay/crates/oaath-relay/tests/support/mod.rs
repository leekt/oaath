//! Shared relay test harness: deterministic clock, reversible KMS, and
//! request/response helpers.
#![allow(dead_code)]

pub mod chain;
pub mod grant;

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oaath_relay::authorization::challenge::sha256_base64url;
use oaath_relay::clock::RelayClock;
use oaath_relay::error::RelayErrorCode;
use oaath_relay::kms::{KmsUnavailable, RelayKms};
use oaath_relay::oauth::OAuthConfiguration;
use oaath_relay::oauth::id_token::IdTokenKey;
use oaath_relay::store::RelayStore;
use oaath_relay::store::memory::MemoryRelayStore;
use oaath_relay::{Relay, RelayOptions};
use serde_json::{Value, json};

pub const ISSUER: &str = "https://oaath.test";
pub const ID_TOKEN_KID: &str = "test-key-1";

/// A fixed P-256 test key as PKCS#8 PEM.
pub fn id_token_pem() -> String {
    use p256::pkcs8::EncodePrivateKey;
    p256::SecretKey::from_slice(&[7u8; 32])
        .unwrap()
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string()
}

pub const REDIRECT_URI: &str = "https://app.example/callback";
/// 43 unreserved characters: the RFC 7636 minimum.
pub const CODE_VERIFIER: &str = "u9Xq2Tb7yZ0aVc4Nk1Lm6Pr8Sd3Wf5Hg7Jt9Bn2Qx0z";

/// `createTestClock`'s start.
pub const CLOCK_START: u64 = 1_700_000_000_000;
pub const CLOCK_SECONDS: u64 = CLOCK_START / 1_000;

pub struct TestClock {
    now: AtomicU64,
    broken: AtomicBool,
}

impl TestClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(CLOCK_START),
            broken: AtomicBool::new(false),
        })
    }

    pub fn advance(&self, milliseconds: u64) {
        self.now.fetch_add(milliseconds, Ordering::SeqCst);
    }

    pub fn break_clock(&self) {
        self.broken.store(true, Ordering::SeqCst);
    }
}

impl RelayClock for TestClock {
    fn now(&self) -> Option<u64> {
        (!self.broken.load(Ordering::SeqCst)).then(|| self.now.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KmsMode {
    Reversible,
    Failing,
    Leaking,
}

/// Deterministic and reversible, so a "restart" can still open earlier references.
pub struct TestKms {
    pub mode: KmsMode,
    pub encryptions: AtomicUsize,
    /// When set, every reference opens as this plaintext: a corrupted
    /// durable read boundary after a valid admission.
    pub opened: Mutex<Option<String>>,
}

const KMS_PREFIX: &str = "oaath-test-kms:v1:";

impl TestKms {
    pub fn new(mode: KmsMode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            encryptions: AtomicUsize::new(0),
            opened: Mutex::new(None),
        })
    }

    pub fn encryptions(&self) -> usize {
        self.encryptions.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RelayKms for TestKms {
    async fn encrypt(&self, plaintext: &str) -> Result<String, KmsUnavailable> {
        self.encryptions.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            KmsMode::Reversible => Ok(format!("{KMS_PREFIX}{}", STANDARD.encode(plaintext))),
            KmsMode::Failing => Err(KmsUnavailable),
            KmsMode::Leaking => Ok(format!("ref:{plaintext}")),
        }
    }

    async fn decrypt(&self, ciphertext_ref: &str) -> Result<String, KmsUnavailable> {
        if self.mode == KmsMode::Failing {
            return Err(KmsUnavailable);
        }
        if let Some(opened) = self.opened.lock().unwrap().clone() {
            return Ok(opened);
        }
        let encoded = ciphertext_ref
            .strip_prefix(KMS_PREFIX)
            .ok_or(KmsUnavailable)?;
        String::from_utf8(STANDARD.decode(encoded).map_err(|_| KmsUnavailable)?)
            .map_err(|_| KmsUnavailable)
    }
}

pub struct Harness {
    pub relay: Arc<Relay>,
    pub store: Arc<dyn RelayStore>,
    pub clock: Arc<TestClock>,
    pub kms: Arc<TestKms>,
}

pub fn options(
    store: Arc<dyn RelayStore>,
    clock: Arc<TestClock>,
    kms: Arc<TestKms>,
) -> RelayOptions {
    RelayOptions {
        store,
        kms,
        clock,
        request_ttl_ms: None,
        code_ttl_ms: None,
        max_body_bytes: None,
        oauth: Some(OAuthConfiguration {
            issuer: ISSUER.to_owned(),
            key: IdTokenKey::from_pkcs8_pem(Some(ID_TOKEN_KID), &id_token_pem()).unwrap(),
        }),
        chain: None,
    }
}

pub fn harness_with(configure: impl FnOnce(&mut RelayOptions)) -> Harness {
    harness_on(
        Arc::new(MemoryRelayStore::new()),
        TestClock::new(),
        configure,
    )
}

pub fn harness_on(
    store: Arc<dyn RelayStore>,
    clock: Arc<TestClock>,
    configure: impl FnOnce(&mut RelayOptions),
) -> Harness {
    let kms = TestKms::new(KmsMode::Reversible);
    let mut options = options(store.clone(), clock.clone(), kms.clone());
    configure(&mut options);
    Harness {
        relay: Arc::new(Relay::new(options).expect("valid options")),
        store,
        clock,
        kms,
    }
}

pub fn harness() -> Harness {
    harness_with(|_| {})
}

pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub headers: HeaderMap,
}

impl Reply {
    /// Asserts a failure by code and status only; a response never carries text.
    #[track_caller]
    pub fn failure(&self, code: RelayErrorCode) {
        assert_eq!(self.status, code.status(), "body: {}", self.body);
        assert_eq!(self.body, json!({ "error": { "code": code } }));
    }

    #[track_caller]
    pub fn ok(&self, status: u16) -> &Value {
        assert_eq!(self.status, status, "body: {}", self.body);
        assert_eq!(self.headers["cache-control"], "no-store");
        assert_eq!(
            self.headers["content-type"],
            "application/json; charset=utf-8"
        );
        &self.body
    }
}

pub fn request(
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

pub fn post(path: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    request("POST", path, token, body)
}

pub fn get(path: &str, token: Option<&str>) -> Request<Body> {
    request("GET", path, token, None)
}

/// A portal request carrying the session `cookie` (a `Cookie` header value).
pub fn portal_call(
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut request = request(method, path, None, body);
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert("cookie", cookie.parse().unwrap());
    }
    request
}

/// The `Cookie` header value a browser sends back for a `Set-Cookie` reply.
pub fn cookie_of(reply: &Reply) -> String {
    let set_cookie = reply.headers["set-cookie"].to_str().unwrap();
    set_cookie.split(';').next().unwrap().to_owned()
}

impl Harness {
    /// Setup only, for a test whose subject is not sign-in: a session for
    /// `signer_id` written straight to the store. Sign-in itself is proven
    /// through the wire in `tests/session.rs`.
    pub async fn session_for(&self, signer_id: &str) -> String {
        use oaath_relay::session::{
            PORTAL_SESSION_RECORD_VERSION, PortalSessionRecord, SESSION_COOKIE, SESSION_TTL_MS,
        };
        let token = oaath_relay::authorization::challenge::random_identifier();
        let now = self.clock.now().unwrap();
        let mut transaction = self.store.begin().await.unwrap();
        assert!(
            transaction
                .insert_portal_session(&PortalSessionRecord {
                    version: PORTAL_SESSION_RECORD_VERSION,
                    token_hash: sha256_base64url(&token),
                    signer_id: signer_id.to_owned(),
                    created_at: now,
                    expires_at: now + SESSION_TTL_MS,
                    signed_out_at: None,
                })
                .await
                .unwrap()
        );
        transaction.commit().await.unwrap();
        format!("{SESSION_COOKIE}={token}")
    }

    pub async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.relay.handle(request).await;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        Reply {
            status,
            body: serde_json::from_slice(&bytes).unwrap(),
            headers,
        }
    }
}

/// A fresh idempotency key for one account creation.
pub fn creation_key() -> String {
    oaath_relay::authorization::challenge::random_identifier()
}

pub fn code_challenge() -> String {
    sha256_base64url(CODE_VERIFIER)
}

pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}
