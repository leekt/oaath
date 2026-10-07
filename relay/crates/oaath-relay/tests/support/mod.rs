//! Shared relay test harness: deterministic clock, deployment authentication,
//! reversible KMS, real protocol scopes and artifacts, and request/response
//! helpers.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oaath_protocol::capture::parse_json;
use oaath_protocol::grant_policy::{hash_grant_policy, hash_grant_policy_calls};
use oaath_protocol::permission::hash_permission_request;
use oaath_relay::authentication::{
    AuthenticationFailure, RateLimitVerdict, RateLimiterUnavailable, RelayAuthentication,
    RelayCaller, RelayCallerRole, RelayRateLimiter, bearer_token,
};
use oaath_relay::authorization::challenge::sha256_base64url;
use oaath_relay::authorization::request::RelayOwnerRouting;
use oaath_relay::clock::RelayClock;
use oaath_relay::error::{RelayErrorCode, RelayResult};
use oaath_relay::kms::{KmsUnavailable, RelayKms};
use oaath_relay::records::AuthorizationOwnerRoute;
use oaath_relay::store::RelayStore;
use oaath_relay::store::memory::MemoryRelayStore;
use oaath_relay::{Relay, RelayOptions};
use serde_json::{Value, json};

pub const REDIRECT_URI: &str = "https://app.example/callback";
/// 43 unreserved characters: the RFC 7636 minimum.
pub const CODE_VERIFIER: &str = "u9Xq2Tb7yZ0aVc4Nk1Lm6Pr8Sd3Wf5Hg7Jt9Bn2Qx0z";

pub const CLIENT_TOKEN: &str = "client-token";
pub const OWNER_TOKEN: &str = "owner-token";
pub const OTHER_CLIENT_TOKEN: &str = "other-client-token";
pub const OTHER_OWNER_TOKEN: &str = "other-owner-token";
pub const NO_AUDIENCE_CLIENT_TOKEN: &str = "no-audience-client-token";

/// `createTestClock`'s start.
pub const CLOCK_START: u64 = 1_700_000_000_000;
pub const CLOCK_SECONDS: u64 = CLOCK_START / 1_000;

/// `APPROVABLE_PERMISSION_SCOPE`: a real `@oaath/protocol` permission scope,
/// exactly as `@oaath/sdk` stores it (the request without its relay id).
pub fn approvable_scope() -> String {
    permission_scope(
        json!({
            "version": "oaath.grant-policy/v2",
            "calls": [call("100")],
            "validAfter": 100,
            "validUntil": 190,
            "perChainOperationLimit": { "count": 10, "intervalSeconds": null },
        }),
        100,
        200,
    )
}

pub fn call(value_limit: &str) -> Value {
    json!({
        "target": format!("0x{}", "11".repeat(20)),
        "selector": "0x12345678",
        "valueLimit": value_limit,
        "argumentEquals": [],
    })
}

/// `LIVE_PERMISSION_POLICY`: a policy window live at the test clock.
pub fn live_policy() -> Value {
    json!({
        "version": "oaath.grant-policy/v2",
        "calls": [call("100")],
        "validAfter": 100,
        "validUntil": CLOCK_SECONDS + 600,
        "perChainOperationLimit": { "count": 10, "intervalSeconds": null },
    })
}

/// `LIVE_PERMISSION_SCOPE`.
pub fn live_scope() -> String {
    permission_scope(live_policy(), CLOCK_SECONDS - 100, CLOCK_SECONDS + 700)
}

pub fn permission_scope(policy: Value, requested_at: u64, expires_at: u64) -> String {
    json!({
        "version": "oaath.permission-request/v2",
        "context": {
            "version": "oaath.workspace-account-context/v1",
            "workspaceId": "personal-1",
            "workspaceKind": "personal",
            "accountId": "account-1",
        },
        "application": {
            "applicationId": "oaath-native-tests",
            "clientId": "client-a",
            "origin": "https://app.example",
            "deviceId": "device-1",
        },
        "chainScope": "all",
        "logicalAccount": {
            "version": "oaath.kernel-account-profile/v1",
            "kind": "kernel",
            "accountIndex": "7",
            "kernelVersion": "0.4.0",
            "factoryRoute": "meta_factory",
            "entryPoint": { "version": "0.9" },
            "ownerCredential": {
                "version": "oaath.owner-credential-profile/v1",
                "kind": "ecdsa",
                "address": format!("0x{}", "33".repeat(20)),
            },
        },
        "operatorCredential": {
            "version": "oaath.operator-credential-profile/v1",
            "kind": "ecdsa",
            "address": format!("0x{}", "44".repeat(20)),
        },
        "policy": policy,
        "requestedAt": requested_at,
        "expiresAt": expires_at,
        "sessionSigner": null,
    })
    .to_string()
}

/// A real permission decision for the stored scope, as `support.ts` and
/// `verify.test.ts` build it. `overrides` replace fields in place; a
/// `"kind": "reject"` override drops the approval-only fields.
pub fn decision_artifact(
    scope: &str,
    request_id: &str,
    decided_at: u64,
    overrides: Value,
) -> String {
    let mut request = parse_json(scope).unwrap();
    request["requestId"] = json!(request_id);
    let mut decision = json!({
        "version": "oaath.permission-decision/v1",
        "kind": "approve",
        "requestId": request_id,
        "requestHash": hash_permission_request(&request).unwrap(),
        "decidedAt": decided_at,
        "approvedPolicy": request["policy"],
        "capabilityHash": format!("0x{}", "ab".repeat(32)),
    });
    for (key, value) in overrides.as_object().unwrap() {
        decision[key] = value.clone();
    }
    if decision["kind"] == json!("reject") {
        let record = decision.as_object_mut().unwrap();
        record.shift_remove("approvedPolicy");
        record.shift_remove("capabilityHash");
    }
    decision.to_string()
}

/// `permissionArtifact`: approved at the request time for `approvable_scope`.
pub fn permission_artifact(request_id: &str) -> String {
    decision_artifact(&approvable_scope(), request_id, 100, json!({}))
}

pub fn calls_digest(calls: &Value) -> String {
    hash_grant_policy_calls(calls).unwrap()
}

pub fn policy_digest(policy: &Value) -> String {
    hash_grant_policy(policy).unwrap()
}

pub fn caller(
    role: RelayCallerRole,
    client_id: &str,
    subject: &str,
    redirect_uris: &[&str],
    audience: Option<&str>,
) -> RelayCaller {
    RelayCaller {
        role,
        client_id: client_id.into(),
        subject: subject.into(),
        redirect_uris: redirect_uris.iter().map(|uri| (*uri).to_owned()).collect(),
        organization_audience: audience.map(str::to_owned),
    }
}

pub fn callers() -> HashMap<String, RelayCaller> {
    use RelayCallerRole::{Client, Owner};
    HashMap::from([
        (
            CLIENT_TOKEN.into(),
            caller(
                Client,
                "client-a",
                "subject-1",
                &[REDIRECT_URI],
                Some("org-1"),
            ),
        ),
        (
            OTHER_CLIENT_TOKEN.into(),
            caller(
                Client,
                "client-b",
                "subject-1",
                &[REDIRECT_URI],
                Some("org-2"),
            ),
        ),
        (
            NO_AUDIENCE_CLIENT_TOKEN.into(),
            caller(Client, "client-a", "subject-1", &[REDIRECT_URI], None),
        ),
        (
            OWNER_TOKEN.into(),
            caller(Owner, "owner-console", "subject-1", &[], None),
        ),
        (
            OTHER_OWNER_TOKEN.into(),
            caller(Owner, "owner-console", "subject-2", &[], None),
        ),
    ])
}

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

/// Bearer token lookup, or a fixed answer that replaces it.
pub enum TestAuthentication {
    Tokens(HashMap<String, RelayCaller>),
    Fixed(RelayCaller),
    Failing,
}

#[async_trait]
impl RelayAuthentication for TestAuthentication {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<RelayCaller>, AuthenticationFailure> {
        match self {
            Self::Tokens(callers) => {
                Ok(bearer_token(headers).and_then(|token| callers.get(token).cloned()))
            }
            Self::Fixed(caller) => Ok(Some(caller.clone())),
            Self::Failing => Err(AuthenticationFailure::Failed),
        }
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

pub struct TestOwnerRouting {
    pub route: Mutex<Option<AuthorizationOwnerRoute>>,
    pub resolutions: AtomicUsize,
}

impl TestOwnerRouting {
    pub fn new(route: Option<(&str, &str)>) -> Arc<Self> {
        Arc::new(Self {
            route: Mutex::new(route.map(|(device, subject)| AuthorizationOwnerRoute {
                owner_device_id: device.into(),
                owner_subject: subject.into(),
            })),
            resolutions: AtomicUsize::new(0),
        })
    }

    pub fn set(&self, device: &str, subject: &str) {
        *self.route.lock().unwrap() = Some(AuthorizationOwnerRoute {
            owner_device_id: device.into(),
            owner_subject: subject.into(),
        });
    }
}

#[async_trait]
impl RelayOwnerRouting for TestOwnerRouting {
    async fn resolve_owner(
        &self,
        caller: &RelayCaller,
        request_id: &str,
        _requested_scope: &str,
    ) -> RelayResult<Option<AuthorizationOwnerRoute>> {
        assert_eq!(caller.subject, "subject-1");
        assert_eq!(request_id.len(), 43);
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(self.route.lock().unwrap().clone())
    }
}

pub enum LimiterMode {
    Allowed,
    Limited,
    Failing,
}

pub struct TestLimiter {
    pub mode: LimiterMode,
    pub seen: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl RelayRateLimiter for TestLimiter {
    async fn check(
        &self,
        route: &str,
        client_id: &str,
    ) -> Result<RateLimitVerdict, RateLimiterUnavailable> {
        self.seen
            .lock()
            .unwrap()
            .push((route.to_owned(), client_id.to_owned()));
        match self.mode {
            LimiterMode::Allowed => Ok(RateLimitVerdict::Allowed),
            LimiterMode::Limited => Ok(RateLimitVerdict::Limited),
            LimiterMode::Failing => Err(RateLimiterUnavailable),
        }
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
        authentication: Arc::new(TestAuthentication::Tokens(callers())),
        owner_routing: TestOwnerRouting::new(Some(("phone-1", "subject-1"))),
        kms,
        clock,
        rate_limit: None,
        request_ttl_ms: None,
        code_ttl_ms: None,
        max_body_bytes: None,
        bootstrap: None,
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

impl Harness {
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

    pub async fn create_request_with(&self, scope: &str) -> Value {
        self.send(post(
            "/authorization/requests",
            Some(CLIENT_TOKEN),
            Some(json!({
                "redirectUri": REDIRECT_URI,
                "codeChallenge": code_challenge(),
                "requestedScope": scope,
            })),
        ))
        .await
        .ok(201)
        .clone()
    }

    pub async fn create_request(&self) -> String {
        let created = self.create_request_with(&approvable_scope()).await;
        created["requestId"].as_str().unwrap().to_owned()
    }

    pub async fn decide(&self, request_id: &str, token: &str, body: Value) -> Reply {
        self.send(post(
            &format!("/authorization/requests/{request_id}/decision"),
            Some(token),
            Some(body),
        ))
        .await
    }

    pub async fn approve_with(&self, request_id: &str, artifact: &str) -> Value {
        self.decide(
            request_id,
            OWNER_TOKEN,
            json!({ "outcome": "approved", "artifact": artifact }),
        )
        .await
        .ok(200)
        .clone()
    }

    pub async fn approve(&self, request_id: &str) -> Value {
        self.approve_with(request_id, &permission_artifact(request_id))
            .await
    }

    pub async fn consume_with(
        &self,
        code: &str,
        token: &str,
        verifier: &str,
        redirect: &str,
    ) -> Reply {
        self.send(post(
            "/authorization/codes/consume",
            Some(token),
            Some(json!({ "code": code, "codeVerifier": verifier, "redirectUri": redirect })),
        ))
        .await
    }

    pub async fn consume(&self, code: &str) -> Reply {
        self.consume_with(code, CLIENT_TOKEN, CODE_VERIFIER, REDIRECT_URI)
            .await
    }

    pub async fn claim_as(&self, artifact_id: &str, token: &str) -> Reply {
        self.send(post(
            &format!("/authorization/artifacts/{artifact_id}/claim"),
            Some(token),
            None,
        ))
        .await
    }

    pub async fn claim(&self, artifact_id: &str) -> Reply {
        self.claim_as(artifact_id, CLIENT_TOKEN).await
    }

    pub async fn fetch(&self, request_id: &str, token: &str) -> Reply {
        self.send(get(
            &format!("/authorization/requests/{request_id}"),
            Some(token),
        ))
        .await
    }
}

pub fn code_challenge() -> String {
    sha256_base64url(CODE_VERIFIER)
}

pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}
