//! HTTP relay handler, wire-identical to `packages/server/src/relay/handler.ts`.
//!
//! Every wire input is exact-captured once here and handed to a use case as
//! typed data. Every failure leaves as a structured code projected to a status;
//! no message text, driver output, or internal detail reaches a response body.
//!
//! ```text
//! POST /authorization/requests                       client  create request
//! GET  /authorization/requests/{requestId}           owner   fetch request
//! POST /authorization/requests/{requestId}/decision  owner   approve or reject
//! POST /authorization/requests/{requestId}/withdraw  client  withdraw request
//! GET  /authorization/requests/{requestId}/code      client  released-code pickup
//! POST /authorization/codes/consume                  client  one-time code consume
//! POST /authorization/artifacts/{artifactId}/claim   client  one-time artifact claim
//! POST /authorization/resume                         client  fresh auth + recovery read
//! GET  /bootstrap                                    client  URL-only service context
//! POST /invalidations                                client  capability invalidation
//! POST /grants/verify                                client  grant reference verification
//! POST /portal/signers                               portal  register signer
//! GET  /portal/signers/{signerId}/accounts           portal  signer's accounts
//! GET  /portal/signers/by-credential/{credentialId}  portal  recognise a passkey
//! POST /portal/accounts                              portal  derive and record account
//! POST /portal/sessions/challenge                    portal  sign-in challenge
//! POST /portal/sessions                              portal  prove a signer, set cookie
//! DELETE /portal/sessions                            portal  sign out, clear cookie
//! POST /portal/links                                 portal  ask to join an account
//! GET  /portal/links/{linkId}                        portal  read a link (requester, root)
//! POST /portal/links/{linkId}/approve|reject         portal  the root decides a link
//! GET  /portal/accounts/{accountId}/members          portal  the root lists members
//! DELETE /portal/accounts/{accountId}/members/{id}   portal  the root removes a member
//! POST /portal/accounts/{a}/members/{id}/suspend     portal  the root suspends a member
//! POST /portal/accounts/{a}/members/{id}/restore     portal  the root restores a member
//! POST /portal/accounts/{a}/members/{id}/grants(/prepare) portal  the root grants a template
//! GET|POST|PUT|DELETE /portal/accounts/{a}/policies(/{t})  portal  the root's templates
//! POST /portal/links/{linkId}/prepare                portal  what a template approval signs
//! GET  /portal/grants/{grantId}                      portal  a member grant (root, member)
//! ```
//!
//! A signer's accounts, account creation, and grant prepare and approved
//! decisions require that signer's portal session (`session.rs`).
//!
//! Later stages: `/grants/{grantId}/revocations/{chainId}`, `/chains/...`,
//! `/session-signers...`, and `/native/...` answer `relay_not_found` here,
//! exactly as the TypeScript relay does when those surfaces are unconfigured.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::response::Response;
use oaath_protocol::capture::parse_json;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::authentication::{
    RelayAuthentication, RelayCaller, RelayCallerRole, RelayRateLimiter, assert_within_rate_limit,
    authenticate_caller,
};
use crate::authorization::artifact::claim_encrypted_artifact;
use crate::authorization::code::{
    ConsumeAuthorizationCode, consume_authorization_code, fetch_authorization_code,
    withdraw_authorization_request,
};
use crate::authorization::decision::{
    DecisionCommand, DecisionPorts, submit_authorization_decision,
};
use crate::authorization::invalidation::record_capability_invalidation;
use crate::authorization::request::{
    CreateAuthorizationRequest, RelayOwnerRouting, create_authorization_request,
    fetch_authorization_request, resume_authorization,
};
use crate::authorization::verify::verify_grant_reference;
use crate::bootstrap::{BootstrapConfiguration, capture_chains, serve_bootstrap};
use crate::clock::RelayClock;
use crate::error::{RelayErrorCode, RelayResult};
use crate::kms::RelayKms;
use crate::link::{
    LinkOutcome, create_link, decide_link, identifier_segment, list_members, prepare_link_grant,
    read_link, remove_member, set_member_status,
};
use crate::member_grant::{assign_grant, member_grant_view, prepare_assignment};
use crate::oauth::{
    LoginDecision, OAuthConfiguration, OAuthResult, decide_login, discovery, exchange_code, grant,
    login_decision, operation, parse_form, prepare_grant, push_authorization_request,
    read_transaction, recover_redirect, register_client,
};
use crate::policy::{delete_template, list_templates, save_template};
use crate::portal::{
    assert_same_origin, create_account, register_signer, signer_accounts, signer_by_credential,
};
use crate::records::{
    bounded_text, canonical_identifier, canonical_str, is_lowercase_hash, limits,
};
use crate::registry::MembershipStatus;
use crate::session::{
    cleared_session_cookie, issue_challenge, require_signer, session_cookie, session_signer,
    sign_in, sign_out,
};
use crate::store::RelayStore;

const DEFAULT_REQUEST_TTL_MS: u64 = 300_000;
const DEFAULT_CODE_TTL_MS: u64 = 60_000;
const DEFAULT_MAX_BODY_BYTES: u64 = 65_536;
const MAX_TTL_MS: u64 = 86_400_000;
/// The relay owns the authorization-code lifetime ceiling, in milliseconds.
const MAX_CODE_TTL_MS: u64 = 600_000;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;
const CLIENT: &[RelayCallerRole] = &[RelayCallerRole::Client];
const OWNER: &[RelayCallerRole] = &[RelayCallerRole::Owner];

pub struct RelayOptions {
    pub store: Arc<dyn RelayStore>,
    pub authentication: Arc<dyn RelayAuthentication>,
    /// Resolves an approving device independently of the requesting member.
    pub owner_routing: Arc<dyn RelayOwnerRouting>,
    pub kms: Arc<dyn RelayKms>,
    pub clock: Arc<dyn RelayClock>,
    /// Optional. There is no default limiter.
    pub rate_limit: Option<Arc<dyn RelayRateLimiter>>,
    pub request_ttl_ms: Option<u64>,
    pub code_ttl_ms: Option<u64>,
    pub max_body_bytes: Option<u64>,
    /// Optional URL-only bootstrap surface.
    pub bootstrap: Option<BootstrapConfiguration>,
    /// Optional OAuth 2.0 / OpenID Connect login surface.
    pub oauth: Option<OAuthConfiguration>,
}

pub struct Relay {
    store: Arc<dyn RelayStore>,
    authentication: Arc<dyn RelayAuthentication>,
    owner_routing: Arc<dyn RelayOwnerRouting>,
    kms: Arc<dyn RelayKms>,
    clock: Arc<dyn RelayClock>,
    rate_limit: Option<Arc<dyn RelayRateLimiter>>,
    request_ttl_ms: u64,
    code_ttl_ms: u64,
    max_body_bytes: usize,
    bootstrap: Option<BootstrapConfiguration>,
    oauth: Option<OAuthConfiguration>,
}

fn duration(value: Option<u64>, fallback: u64, maximum: u64) -> RelayResult<u64> {
    match value {
        None => Ok(fallback),
        Some(milliseconds) if (1..=maximum).contains(&milliseconds) => Ok(milliseconds),
        Some(_) => Err(RelayErrorCode::Internal),
    }
}

/// One response: the status and the exact JSON body.
pub struct RelayReply {
    status: u16,
    body: Vec<u8>,
    /// Only a portal session route sets a cookie.
    set_cookie: Option<String>,
}

fn reply(status: u16, body: &impl Serialize) -> RelayResult<RelayReply> {
    let body = serde_json::to_vec(body).map_err(|_| RelayErrorCode::Internal)?;
    Ok(RelayReply {
        status,
        body,
        set_cookie: None,
    })
}

fn failure(code: RelayErrorCode) -> RelayReply {
    RelayReply {
        status: code.status(),
        body: serde_json::to_vec(&json!({ "error": { "code": code } })).unwrap_or_default(),
        set_cookie: None,
    }
}

fn http_response(reply: RelayReply) -> Response {
    let mut response = Response::new(Body::from(reply.body));
    *response.status_mut() =
        StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(cookie) = reply
        .set_cookie
        .and_then(|cookie| HeaderValue::from_str(&cookie).ok())
    {
        headers.insert(header::SET_COOKIE, cookie);
    }
    response
}

fn require_method(method: &Method, expected: &Method) -> RelayResult<()> {
    if method == expected {
        Ok(())
    } else {
        Err(RelayErrorCode::MethodNotAllowed)
    }
}

/// WHATWG URL path segments: `\` separates like `/`, `.` and `..` (also
/// percent-encoded) are resolved, and empty segments are dropped. Segments
/// stay percent-encoded, so an encoded character never passes identifier
/// capture.
fn path_segments(path: &str) -> Vec<&str> {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split(['/', '\\']) {
        let lower = segment.to_ascii_lowercase();
        match lower.as_str() {
            "." | "%2e" => {}
            ".." | ".%2e" | "%2e." | "%2e%2e" => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    segments.retain(|segment| !segment.is_empty());
    segments
}

/// A plain JSON object read from a bounded `application/json` body.
async fn body_record(
    headers: &HeaderMap,
    body: Body,
    max_body_bytes: usize,
) -> RelayResult<Map<String, Value>> {
    let text = body_text(headers, body, max_body_bytes, "application/json").await?;
    // `-0` keeps its sign, as `JSON.parse` keeps it, for the protocol parsers.
    match parse_json(&text) {
        Ok(Value::Object(record)) => Ok(record),
        _ => Err(INVALID),
    }
}

/// A bounded body of the expected media type, decoded like `Request.text()`:
/// lossy UTF-8 with a leading BOM dropped.
async fn body_text(
    headers: &HeaderMap,
    body: Body,
    max_body_bytes: usize,
    media_type: &str,
) -> RelayResult<String> {
    let content_type = headers
        .get_all(header::CONTENT_TYPE)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect::<Vec<_>>()
        .join(", ");
    if !content_type.to_ascii_lowercase().starts_with(media_type) {
        return Err(INVALID);
    }
    // Lossy decoding never shrinks a body, so a raw body beyond the bound is
    // beyond it after decoding too.
    let bytes = to_bytes(body, max_body_bytes.saturating_add(1))
        .await
        .map_err(|_| INVALID)?;
    let decoded = String::from_utf8_lossy(&bytes);
    let text = decoded.strip_prefix('\u{feff}').unwrap_or(&decoded);
    if text.len() > max_body_bytes {
        return Err(INVALID);
    }
    Ok(text.to_owned())
}

fn exact_body(record: &Map<String, Value>, keys: &[&str]) -> RelayResult<()> {
    if record.len() == keys.len() && keys.iter().all(|key| record.contains_key(*key)) {
        Ok(())
    } else {
        Err(INVALID)
    }
}

fn decision_command(record: &Map<String, Value>) -> RelayResult<DecisionCommand> {
    match record.get("outcome").and_then(Value::as_str) {
        Some("approved") => {
            exact_body(record, &["outcome", "artifact"])?;
            let artifact =
                bounded_text(record.get("artifact"), limits::ARTIFACT_PLAINTEXT, INVALID)?;
            Ok(DecisionCommand::Approved {
                artifact: artifact.to_owned(),
            })
        }
        Some("rejected") => {
            exact_body(record, &["outcome"])?;
            Ok(DecisionCommand::Rejected)
        }
        _ => Err(INVALID),
    }
}

impl Relay {
    pub fn new(options: RelayOptions) -> RelayResult<Self> {
        if let Some(bootstrap) = &options.bootstrap {
            capture_chains(&bootstrap.chains)?;
        }
        let max_body_bytes = duration(options.max_body_bytes, DEFAULT_MAX_BODY_BYTES, MAX_TTL_MS)?;
        Ok(Self {
            store: options.store,
            authentication: options.authentication,
            owner_routing: options.owner_routing,
            kms: options.kms,
            clock: options.clock,
            rate_limit: options.rate_limit,
            request_ttl_ms: duration(options.request_ttl_ms, DEFAULT_REQUEST_TTL_MS, MAX_TTL_MS)?,
            code_ttl_ms: duration(options.code_ttl_ms, DEFAULT_CODE_TTL_MS, MAX_CODE_TTL_MS)?,
            max_body_bytes: usize::try_from(max_body_bytes)
                .map_err(|_| RelayErrorCode::Internal)?,
            bootstrap: options.bootstrap,
            oauth: options.oauth,
        })
    }

    /// The axum router: every path goes through the one relay route table.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(move |request: Request<Body>| {
            let relay = self.clone();
            async move { relay.handle(request).await }
        })
    }

    pub fn store(&self) -> &Arc<dyn RelayStore> {
        &self.store
    }

    pub async fn handle(&self, request: Request<Body>) -> Response {
        let head = path_segments(request.uri().path()).first().copied();
        if matches!(head, Some("oauth" | ".well-known")) {
            let path = request.uri().path().to_owned();
            let reply = match self.oauth_route(&path, request).await {
                Ok(reply) => reply,
                Err(failure) => {
                    tracing::debug!(code = %failure.code, "oauth request failed");
                    RelayReply {
                        status: failure.status,
                        body: serde_json::to_vec(&failure.body()).unwrap_or_default(),
                        set_cookie: None,
                    }
                }
            };
            return http_response(reply);
        }
        let reply = match self.route(request).await {
            Ok(reply) => reply,
            Err(code) => {
                tracing::debug!(code = %code, "relay request failed");
                failure(code)
            }
        };
        http_response(reply)
    }

    /// `/oauth/*` and discovery, answering RFC 6749 error bodies.
    async fn oauth_route(&self, path: &str, request: Request<Body>) -> OAuthResult<RelayReply> {
        let (parts, body) = request.into_parts();
        let (method, headers) = (&parts.method, &parts.headers);
        let segments = path_segments(path);
        let oauth = self.oauth.as_ref().ok_or(RelayErrorCode::NotFound)?;
        let store = self.store.as_ref();
        let clock = self.clock.as_ref();
        let form = |body| async move {
            let text = body_text(
                headers,
                body,
                self.max_body_bytes,
                "application/x-www-form-urlencoded",
            )
            .await?;
            parse_form(&text)
        };
        match segments.as_slice() {
            [".well-known", "openid-configuration"] => {
                require_method(method, &Method::GET)?;
                Ok(reply(200, &discovery(&oauth.issuer))?)
            }
            ["oauth", "jwks"] => {
                require_method(method, &Method::GET)?;
                Ok(reply(200, oauth.key.jwks())?)
            }
            ["oauth", "clients"] => {
                require_method(method, &Method::POST)?;
                let body = body_record(headers, body, self.max_body_bytes).await?;
                Ok(reply(201, &register_client(store, clock, &body).await?)?)
            }
            ["oauth", "par"] => {
                require_method(method, &Method::POST)?;
                let form = form(body).await?;
                let pushed =
                    push_authorization_request(store, clock, self.request_ttl_ms, &form).await?;
                Ok(reply(201, &pushed)?)
            }
            ["oauth", "token"] => {
                require_method(method, &Method::POST)?;
                let form = form(body).await?;
                let kms = self.kms.as_ref();
                Ok(reply(
                    200,
                    &exchange_code(store, clock, kms, oauth, &form).await?,
                )?)
            }
            ["oauth", "revoke"] => {
                require_method(method, &Method::POST)?;
                let form = form(body).await?;
                Ok(reply(
                    200,
                    &grant::revoke_token(store, clock, &form).await?,
                )?)
            }
            ["oauth", "grants", id] => {
                require_method(method, &Method::GET)?;
                let id = canonical_str(id, INVALID)?;
                let view = grant::grant_view(store, clock, self.kms.as_ref(), headers, id).await?;
                Ok(reply(200, &view)?)
            }
            ["oauth", "grants", id, "invalidate"] => {
                require_method(method, &Method::POST)?;
                let id = canonical_str(id, INVALID)?;
                let body = body_record(headers, body, self.max_body_bytes).await?;
                let kms = self.kms.as_ref();
                let evidence =
                    grant::invalidate_grant(store, clock, kms, headers, id, &body).await?;
                Ok(reply(200, &evidence)?)
            }
            _ => Err(RelayErrorCode::NotFound.into()),
        }
    }

    /// Limiting happens after authentication so a deployment can key on
    /// clientId. The authentication port owns unauthenticated abuse.
    async fn authenticate(
        &self,
        headers: &HeaderMap,
        roles: &[RelayCallerRole],
        route: &str,
    ) -> RelayResult<RelayCaller> {
        let caller = authenticate_caller(self.authentication.as_ref(), headers, roles).await?;
        assert_within_rate_limit(self.rate_limit.as_deref(), route, &caller.client_id).await?;
        Ok(caller)
    }

    async fn route(&self, request: Request<Body>) -> RelayResult<RelayReply> {
        let (parts, body) = request.into_parts();
        let method = &parts.method;
        let headers = &parts.headers;
        let segments = path_segments(parts.uri.path());
        let segment = |index: usize| segments.get(index).copied();
        let (head, group, third, fourth) = (segment(0), segment(1), segment(2), segment(3));
        let count = segments.len();

        // Later stage: phone revocation custody.
        if head == Some("grants") && third == Some("revocations") && count == 4 {
            return Err(RelayErrorCode::NotFound);
        }
        // Later stage: EXPERIMENTAL PREVIEW owner-phone routes.
        if head == Some("native") {
            return Err(RelayErrorCode::NotFound);
        }

        // Portal routes; same-origin only.
        if head == Some("portal") {
            assert_same_origin(headers)?;
            let store = self.store.as_ref();
            let clock = self.clock.as_ref();
            if group == Some("sessions") && (count == 2 || count == 3) {
                let issuer = &self.oauth.as_ref().ok_or(RelayErrorCode::NotFound)?.issuer;
                match third {
                    None if method == Method::DELETE => {
                        sign_out(store, clock, headers).await?;
                        let mut reply = reply(200, &json!({}))?;
                        reply.set_cookie = Some(cleared_session_cookie());
                        return Ok(reply);
                    }
                    None => {
                        require_method(method, &Method::POST)?;
                        let body = body_record(headers, body, self.max_body_bytes).await?;
                        let started = sign_in(store, clock, issuer, &body).await?;
                        let mut reply = reply(200, &started.signed_in)?;
                        reply.set_cookie = Some(session_cookie(&started.token));
                        return Ok(reply);
                    }
                    Some("challenge") => {
                        require_method(method, &Method::POST)?;
                        let body = body_record(headers, body, self.max_body_bytes).await?;
                        return reply(200, &issue_challenge(store, clock, issuer, &body).await?);
                    }
                    Some(_) => return Err(RelayErrorCode::NotFound),
                }
            }
            if count == 2 && group == Some("signers") {
                require_method(method, &Method::POST)?;
                let body = body_record(headers, body, self.max_body_bytes).await?;
                return reply(200, &register_signer(store, clock, &body).await?);
            }
            if count == 4 && group == Some("signers") && third == Some("by-credential") {
                require_method(method, &Method::GET)?;
                let credential_id = fourth.unwrap_or_default();
                return reply(200, &signer_by_credential(store, credential_id).await?);
            }
            if count == 4 && group == Some("signers") && fourth == Some("accounts") {
                require_method(method, &Method::GET)?;
                let signer_id = canonical_str(third.unwrap_or_default(), INVALID)?;
                require_signer(store, clock, headers, signer_id).await?;
                return reply(200, &signer_accounts(store, signer_id).await?);
            }
            if count == 2 && group == Some("accounts") {
                require_method(method, &Method::POST)?;
                let session = session_signer(store, clock, headers).await?;
                let body = body_record(headers, body, self.max_body_bytes).await?;
                return reply(201, &create_account(store, clock, &body, &session).await?);
            }
            if group == Some("links") && (2..=4).contains(&count) {
                let session = session_signer(store, clock, headers).await?;
                if count == 2 {
                    require_method(method, &Method::POST)?;
                    let body = body_record(headers, body, self.max_body_bytes).await?;
                    return reply(201, &create_link(store, clock, &body, &session).await?);
                }
                let link_id = identifier_segment(third)?;
                let issuer = &self.oauth.as_ref().ok_or(RelayErrorCode::NotFound)?.issuer;
                let outcome = match fourth {
                    None => {
                        require_method(method, &Method::GET)?;
                        return reply(200, &read_link(store, clock, link_id, &session).await?);
                    }
                    Some("prepare") => {
                        require_method(method, &Method::POST)?;
                        let body = body_record(headers, body, self.max_body_bytes).await?;
                        let prepared =
                            prepare_link_grant(store, clock, issuer, link_id, &body, &session)
                                .await?;
                        return reply(200, &prepared);
                    }
                    Some("approve") => LinkOutcome::Approved,
                    Some("reject") => LinkOutcome::Rejected,
                    Some(_) => return Err(RelayErrorCode::NotFound),
                };
                require_method(method, &Method::POST)?;
                let body = body_record(headers, body, self.max_body_bytes).await?;
                let kms = self.kms.as_ref();
                let view =
                    decide_link(store, clock, kms, issuer, link_id, &body, &session, outcome)
                        .await?;
                return reply(200, &view);
            }
            if group == Some("accounts") && fourth == Some("policies") && (count == 4 || count == 5)
            {
                let session = session_signer(store, clock, headers).await?;
                let account_id = identifier_segment(third)?;
                if count == 4 {
                    if method == Method::GET {
                        return reply(200, &list_templates(store, account_id, &session).await?);
                    }
                    require_method(method, &Method::POST)?;
                    let body = body_record(headers, body, self.max_body_bytes).await?;
                    let saved = save_template(store, clock, account_id, None, &body, &session);
                    return reply(201, &saved.await?);
                }
                let template_id = identifier_segment(segment(4))?;
                if method == Method::DELETE {
                    let deleted = delete_template(store, account_id, template_id, &session);
                    return reply(200, &deleted.await?);
                }
                require_method(method, &Method::PUT)?;
                let body = body_record(headers, body, self.max_body_bytes).await?;
                let saved =
                    save_template(store, clock, account_id, Some(template_id), &body, &session);
                return reply(200, &saved.await?);
            }
            if group == Some("grants") && count == 3 {
                require_method(method, &Method::GET)?;
                let session = session_signer(store, clock, headers).await?;
                let grant_id = identifier_segment(third)?;
                let kms = self.kms.as_ref();
                return reply(
                    200,
                    &member_grant_view(store, kms, grant_id, &session).await?,
                );
            }
            if group == Some("accounts") && fourth == Some("members") && (4..=7).contains(&count) {
                let session = session_signer(store, clock, headers).await?;
                let account_id = identifier_segment(third)?;
                if count == 4 {
                    require_method(method, &Method::GET)?;
                    return reply(200, &list_members(store, account_id, &session).await?);
                }
                let signer_id = identifier_segment(segment(4))?;
                let kms = self.kms.as_ref();
                if segment(5) == Some("grants") {
                    require_method(method, &Method::POST)?;
                    let issuer = &self.oauth.as_ref().ok_or(RelayErrorCode::NotFound)?.issuer;
                    let body = body_record(headers, body, self.max_body_bytes).await?;
                    return match (count, segment(6)) {
                        (7, Some("prepare")) => {
                            let prepared = prepare_assignment(
                                store, clock, issuer, account_id, signer_id, &body, &session,
                            );
                            reply(200, &prepared.await?)
                        }
                        (6, None) => {
                            let assigned = assign_grant(
                                store, clock, kms, issuer, account_id, signer_id, &body, &session,
                            );
                            reply(201, &assigned.await?)
                        }
                        _ => Err(RelayErrorCode::NotFound),
                    };
                }
                if count == 6 {
                    require_method(method, &Method::POST)?;
                    let status = match segment(5) {
                        Some("suspend") => MembershipStatus::Suspended,
                        Some("restore") => MembershipStatus::Active,
                        _ => return Err(RelayErrorCode::NotFound),
                    };
                    exact_body(&body_record(headers, body, self.max_body_bytes).await?, &[])?;
                    let standing = set_member_status(
                        store, clock, kms, account_id, signer_id, &session, status,
                    )
                    .await?;
                    return reply(200, &standing);
                }
                require_method(method, &Method::DELETE)?;
                let removed =
                    remove_member(store, clock, kms, account_id, signer_id, &session).await?;
                return reply(200, &removed);
            }
            if group == Some("transactions") && (count == 3 || count == 4) {
                let oauth = self.oauth.as_ref().ok_or(RelayErrorCode::NotFound)?;
                let id = canonical_str(third.unwrap_or_default(), INVALID)?;
                let kms = self.kms.as_ref();
                match fourth {
                    None => {
                        require_method(method, &Method::GET)?;
                        return reply(200, &read_transaction(store, clock, id).await?);
                    }
                    Some("decision") => {
                        require_method(method, &Method::POST)?;
                        let body = body_record(headers, body, self.max_body_bytes).await?;
                        let decision = login_decision(&body)?;
                        if let LoginDecision::Approved { signer_id, .. }
                        | LoginDecision::Grant { signer_id, .. } = &decision
                        {
                            require_signer(store, clock, headers, signer_id).await?;
                        }
                        if let LoginDecision::Grant {
                            signer_id,
                            account_id,
                            artifact,
                        } = &decision
                        {
                            if operation::is_operation_transaction(store, id).await? {
                                let redirect = operation::decide_operation(
                                    store,
                                    clock,
                                    kms,
                                    oauth,
                                    self.code_ttl_ms,
                                    id,
                                    signer_id,
                                    account_id,
                                    artifact,
                                )
                                .await?;
                                return reply(200, &redirect);
                            }
                            let redirect = grant::decide_grant(
                                store,
                                clock,
                                kms,
                                oauth,
                                self.code_ttl_ms,
                                id,
                                signer_id,
                                account_id,
                                artifact,
                            )
                            .await?;
                            return reply(200, &redirect);
                        }
                        let redirect = decide_login(
                            store,
                            clock,
                            kms,
                            &oauth.issuer,
                            self.code_ttl_ms,
                            id,
                            decision,
                        )
                        .await?;
                        return reply(200, &redirect);
                    }
                    Some("prepare") => {
                        require_method(method, &Method::POST)?;
                        let session = session_signer(store, clock, headers).await?;
                        let body = body_record(headers, body, self.max_body_bytes).await?;
                        let prepared = prepare_grant(store, clock, id, &body, &session).await?;
                        return reply(200, &prepared);
                    }
                    Some("redirect") => {
                        require_method(method, &Method::GET)?;
                        let redirect =
                            recover_redirect(store, clock, kms, &oauth.issuer, id).await?;
                        return reply(200, &redirect);
                    }
                    Some(_) => {}
                }
            }
            return Err(RelayErrorCode::NotFound);
        }

        if head == Some("bootstrap") && count == 1 {
            require_method(method, &Method::GET)?;
            let caller = self
                .authenticate(headers, CLIENT, "bootstrap.fetch")
                .await?;
            let bootstrap = self.bootstrap.as_ref().ok_or(RelayErrorCode::NotFound)?;
            return reply(200, &serve_bootstrap(bootstrap, &caller).await?);
        }

        if head == Some("authorization")
            && group == Some("requests")
            && fourth == Some("withdraw")
            && count == 4
        {
            require_method(method, &Method::POST)?;
            let caller = self
                .authenticate(headers, CLIENT, "authorization.withdraw")
                .await?;
            let request_id = canonical_str(third.unwrap_or_default(), INVALID)?;
            exact_body(&body_record(headers, body, self.max_body_bytes).await?, &[])?;
            let withdrawn = withdraw_authorization_request(
                self.store.as_ref(),
                self.clock.as_ref(),
                &caller,
                request_id,
            )
            .await?;
            return reply(200, &withdrawn);
        }

        // Later stage: remote session-key custody.
        if head == Some("session-signers") {
            return Err(RelayErrorCode::NotFound);
        }

        if head == Some("grants") && count == 2 && group == Some("verify") {
            require_method(method, &Method::POST)?;
            let caller = self.authenticate(headers, CLIENT, "grants.verify").await?;
            // Every result state answers 200: the machine decision lives in the
            // typed envelope.
            let assertion = Value::Object(body_record(headers, body, self.max_body_bytes).await?);
            let result = verify_grant_reference(
                self.store.as_ref(),
                self.clock.as_ref(),
                self.kms.as_ref(),
                &caller,
                &assertion,
            )
            .await?;
            return reply(200, &result.to_json());
        }

        if head == Some("invalidations") && count == 1 {
            require_method(method, &Method::POST)?;
            let caller = self
                .authenticate(headers, CLIENT, "invalidations.create")
                .await?;
            let record = body_record(headers, body, self.max_body_bytes).await?;
            exact_body(&record, &["grantId", "capabilityHash"])?;
            let grant_id = canonical_identifier(record.get("grantId"), INVALID)?;
            let capability_hash = bounded_text(record.get("capabilityHash"), 66, INVALID)?;
            if !is_lowercase_hash(capability_hash) {
                return Err(INVALID);
            }
            let evidence = record_capability_invalidation(
                self.store.as_ref(),
                self.clock.as_ref(),
                &caller,
                grant_id,
                capability_hash,
            )
            .await?;
            return reply(200, &evidence);
        }

        // Later stage: chain execution relays and paymaster proxies. With no
        // chain ports configured, the TypeScript relay answers exactly this.
        if head == Some("chains") {
            if count == 4 && third == Some("paymaster") {
                require_method(method, &Method::POST)?;
                return Err(RelayErrorCode::NotFound);
            }
            if count != 3 {
                return Err(RelayErrorCode::NotFound);
            }
            require_method(method, &Method::POST)?;
            return Err(RelayErrorCode::NotFound);
        }

        if head != Some("authorization") {
            return Err(RelayErrorCode::NotFound);
        }
        let store = self.store.as_ref();
        let clock = self.clock.as_ref();

        if count == 2 && group == Some("requests") {
            require_method(method, &Method::POST)?;
            let caller = self
                .authenticate(headers, CLIENT, "authorization.create")
                .await?;
            let record = body_record(headers, body, self.max_body_bytes).await?;
            exact_body(&record, &["redirectUri", "codeChallenge", "requestedScope"])?;
            let redirect_uri =
                bounded_text(record.get("redirectUri"), limits::REDIRECT_URI, INVALID)?;
            let code_challenge =
                bounded_text(record.get("codeChallenge"), limits::CODE_CHALLENGE, INVALID)?;
            let requested_scope = bounded_text(
                record.get("requestedScope"),
                limits::REQUESTED_SCOPE,
                INVALID,
            )?;
            let created = create_authorization_request(
                store,
                clock,
                self.owner_routing.as_ref(),
                CreateAuthorizationRequest {
                    caller: &caller,
                    redirect_uri,
                    code_challenge,
                    requested_scope,
                    request_ttl_ms: self.request_ttl_ms,
                },
            )
            .await?;
            return reply(201, &created);
        }

        if count == 3 && group == Some("requests") {
            require_method(method, &Method::GET)?;
            let caller = self
                .authenticate(headers, OWNER, "authorization.fetch")
                .await?;
            let request_id = canonical_str(third.unwrap_or_default(), INVALID)?;
            let state = fetch_authorization_request(store, clock, &caller, request_id).await?;
            return reply(200, &state);
        }

        if count == 4 && group == Some("requests") && fourth == Some("decision") {
            require_method(method, &Method::POST)?;
            let caller = self
                .authenticate(headers, OWNER, "authorization.decide")
                .await?;
            let command =
                decision_command(&body_record(headers, body, self.max_body_bytes).await?)?;
            let request_id = canonical_str(third.unwrap_or_default(), INVALID)?;
            let decided = submit_authorization_decision(
                DecisionPorts {
                    store,
                    clock,
                    kms: self.kms.as_ref(),
                },
                &caller,
                request_id,
                command,
                self.code_ttl_ms,
            )
            .await?;
            return reply(200, &decided);
        }

        if count == 4 && group == Some("requests") && fourth == Some("code") {
            require_method(method, &Method::GET)?;
            let caller = self
                .authenticate(headers, CLIENT, "authorization.code")
                .await?;
            let request_id = canonical_str(third.unwrap_or_default(), INVALID)?;
            let fetched =
                fetch_authorization_code(store, clock, self.kms.as_ref(), &caller, request_id)
                    .await?;
            return reply(200, &fetched);
        }

        if count == 3 && group == Some("codes") && third == Some("consume") {
            require_method(method, &Method::POST)?;
            let caller = self
                .authenticate(headers, CLIENT, "authorization.consume")
                .await?;
            let record = body_record(headers, body, self.max_body_bytes).await?;
            exact_body(&record, &["code", "codeVerifier", "redirectUri"])?;
            let input = ConsumeAuthorizationCode {
                code: canonical_identifier(record.get("code"), INVALID)?,
                code_verifier: bounded_text(
                    record.get("codeVerifier"),
                    limits::CODE_VERIFIER,
                    INVALID,
                )?,
                redirect_uri: bounded_text(
                    record.get("redirectUri"),
                    limits::REDIRECT_URI,
                    INVALID,
                )?,
            };
            let consumed = consume_authorization_code(store, clock, &caller, input).await?;
            return reply(200, &consumed);
        }

        if count == 4 && group == Some("artifacts") && fourth == Some("claim") {
            require_method(method, &Method::POST)?;
            let caller = self
                .authenticate(headers, CLIENT, "authorization.claim")
                .await?;
            let artifact_id = canonical_str(third.unwrap_or_default(), INVALID)?;
            let claimed =
                claim_encrypted_artifact(store, clock, self.kms.as_ref(), &caller, artifact_id)
                    .await?;
            return reply(200, &claimed);
        }

        if count == 2 && group == Some("resume") {
            require_method(method, &Method::POST)?;
            let caller = self
                .authenticate(headers, CLIENT, "authorization.resume")
                .await?;
            let record = body_record(headers, body, self.max_body_bytes).await?;
            exact_body(&record, &["requestId"])?;
            let request_id = canonical_identifier(record.get("requestId"), INVALID)?;
            let state = resume_authorization(store, clock, &caller, request_id).await?;
            return reply(200, &state);
        }

        Err(RelayErrorCode::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::path_segments;

    #[test]
    fn resolves_paths_like_the_whatwg_url_parser() {
        assert_eq!(path_segments("/"), Vec::<&str>::new());
        assert_eq!(
            path_segments("/authorization//requests/"),
            ["authorization", "requests"]
        );
        assert_eq!(
            path_segments("/authorization/requests/../resume"),
            ["authorization", "resume"]
        );
        assert_eq!(
            path_segments("/authorization/%2E/resume"),
            ["authorization", "resume"]
        );
        assert_eq!(path_segments("/a\\b"), ["a", "b"]);
        assert_eq!(
            path_segments("/a/not%20canonical"),
            ["a", "not%20canonical"]
        );
    }
}
