//! OAuth 2.0 / OpenID Connect login over the relay's authorization state
//! machine (stage 5a, login only; grants arrive with `authorization_details`
//! in a later stage).
//!
//! ```text
//! state and owner      PAR (immutable: client intent, state, nonce) ->
//!                      request + decision (+ code) written together at decision
//!                      -> code consumed once at /oauth/token
//! persisted evidence   oauth_client_v1, oauth_par_v1, then the existing
//!                      authorization request/decision/code records keyed by the
//!                      PAR id
//! resource occupied?   one decision per PAR id; a consumed code is terminal
//! retry safe?          decide: refused once decided; the redirect endpoint
//!                      reopens the sealed code, never minting a second one.
//!                      token: never retried; a lost token reply restarts login
//! forbidden            decide after expiry; a second decision; a signer that is
//!                      not a member of the account; a token with the wrong
//!                      client, redirect, or verifier (burns the code)
//! crash/reload         each transition is one transaction (`settle`)
//! cleanup owner        the transaction; an expired PAR occupies nothing
//! ```
//!
//! The selection has one owner: the authorization request records the account
//! as `subject` and the signer as `owner_subject`. Its scope is the fixed
//! `oaath.login-selection/v1` marker, which no protocol classifier approves,
//! and no artifact is sealed: a login releases no payload beyond the id_token
//! the relay derives from those records. The PAR keeps owning `state`,
//! `nonce`, and `scope`.

pub mod id_token;
pub mod records;

use serde::Serialize;
use serde_json::{Map, Value, json};
use url::Url;

use self::id_token::IdTokenKey;
use self::records::{
    MAX_CLIENT_NAME, MAX_REDIRECT_URIS, MAX_STATE, OAUTH_CLIENT_RECORD_VERSION,
    OAUTH_PAR_RECORD_VERSION, OAuthClientRecord, ParRecord, redirect_uri_allowed,
};
use crate::authentication::{RelayCaller, RelayCallerRole};
use crate::authorization::challenge::{
    is_code_challenge_s256, random_identifier, sha256_base64url,
};
use crate::authorization::code::{ConsumeAuthorizationCode, consume_authorization_code};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::kms::{RelayKms, open_artifact, seal_artifact};
use crate::records::{
    AUTHORIZATION_CODE_RECORD_VERSION, AUTHORIZATION_DECISION_RECORD_VERSION,
    AUTHORIZATION_REQUEST_RECORD_VERSION, AuthorizationCodeRecord, AuthorizationDecisionRecord,
    AuthorizationRequestRecord, DecisionOutcome, bounded_str, canonical_str, limits,
};
use crate::store::{RelayStore, RelayTransaction, settle};

/// The stored scope of every login request: a kind marker, not a payload.
pub const LOGIN_SELECTION_SCOPE: &str = r#"{"version":"oaath.login-selection/v1"}"#;
/// Subject and owner of a cancelled login, which selected nothing.
const CANCELLED_SUBJECT: &str = "oaath-portal-cancelled";
const ID_TOKEN_TTL_SECONDS: u64 = 600;
const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;

pub struct OAuthConfiguration {
    /// Issuer URL without a trailing slash, e.g. `https://oaath.taek.tech`.
    pub issuer: String,
    pub key: IdTokenKey,
}

/// One RFC 6749 failure: the OAuth error, the relay's structured code, and an
/// optional fixed description.
#[derive(Debug, PartialEq, Eq)]
pub struct OAuthFailure {
    pub status: u16,
    pub error: &'static str,
    pub code: RelayErrorCode,
    pub description: Option<&'static str>,
}

impl OAuthFailure {
    fn new(status: u16, error: &'static str, code: RelayErrorCode) -> Self {
        Self {
            status,
            error,
            code,
            description: None,
        }
    }

    /// The default projection of a relay code onto an OAuth error.
    pub fn from_code(code: RelayErrorCode) -> Self {
        match code {
            RelayErrorCode::RequestInvalid | RelayErrorCode::Forbidden => {
                Self::new(400, "invalid_request", code)
            }
            RelayErrorCode::NotFound | RelayErrorCode::MethodNotAllowed => {
                Self::new(code.status(), "invalid_request", code)
            }
            RelayErrorCode::CodeInvalid
            | RelayErrorCode::CodeAlreadyConsumed
            | RelayErrorCode::Expired => Self::new(400, "invalid_grant", code),
            RelayErrorCode::StoreUnavailable | RelayErrorCode::KmsUnavailable => {
                Self::new(503, "temporarily_unavailable", code)
            }
            _ => Self::new(code.status(), "server_error", code),
        }
    }

    pub fn body(&self) -> Value {
        let mut body = json!({ "error": self.error, "error_code": self.code });
        if let Some(description) = self.description {
            body["error_description"] = json!(description);
        }
        body
    }
}

impl From<RelayErrorCode> for OAuthFailure {
    fn from(code: RelayErrorCode) -> Self {
        Self::from_code(code)
    }
}

pub type OAuthResult<T> = Result<T, OAuthFailure>;

/// Parses an `application/x-www-form-urlencoded` body; a repeated parameter
/// is invalid (RFC 6749 §3.1). Unrecognized parameters are ignored.
pub fn parse_form(text: &str) -> RelayResult<Map<String, Value>> {
    let mut form = Map::new();
    for (key, value) in url::form_urlencoded::parse(text.as_bytes()) {
        if form
            .insert(key.into_owned(), Value::String(value.into_owned()))
            .is_some()
        {
            return Err(INVALID);
        }
    }
    Ok(form)
}

fn param<'a>(form: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    form.get(key).and_then(Value::as_str)
}

fn required<'a>(form: &'a Map<String, Value>, key: &str) -> RelayResult<&'a str> {
    param(form, key)
        .filter(|value| !value.is_empty())
        .ok_or(INVALID)
}

fn optional_bounded(form: &Map<String, Value>, key: &str) -> RelayResult<Option<String>> {
    match param(form, key) {
        None | Some("") => Ok(None),
        Some(value) => Ok(Some(bounded_str(value, MAX_STATE, INVALID)?.to_owned())),
    }
}

pub fn discovery(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "pushed_authorization_request_endpoint": format!("{issuer}/oauth/par"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "jwks_uri": format!("{issuer}/oauth/jwks"),
        "registration_endpoint": format!("{issuer}/oauth/clients"),
        "require_pushed_authorization_requests": true,
        "authorization_response_iss_parameter_supported": true,
        "scopes_supported": ["openid", "account"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "iss", "sub", "aud", "azp", "iat", "exp", "nonce",
            "oaath_account", "signer", "verified",
        ],
    })
}

#[derive(Debug, Serialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: &'static str,
}

/// RFC 7591 open registration of one public client.
pub async fn register_client(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    body: &Map<String, Value>,
) -> OAuthResult<RegisteredClient> {
    let metadata = |code| OAuthFailure::new(400, "invalid_client_metadata", code);
    let allowed = ["client_name", "redirect_uris", "token_endpoint_auth_method"];
    if body.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(metadata(INVALID));
    }
    match body.get("token_endpoint_auth_method") {
        None => {}
        Some(Value::String(method)) if method == "none" => {}
        // private_key_jwt is a later stage.
        Some(_) => return Err(metadata(INVALID)),
    }
    let client_name = body
        .get("client_name")
        .and_then(Value::as_str)
        .and_then(|name| bounded_str(name, MAX_CLIENT_NAME, INVALID).ok())
        .ok_or_else(|| metadata(INVALID))?;
    let Some(Value::Array(uris)) = body.get("redirect_uris") else {
        return Err(OAuthFailure::new(400, "invalid_redirect_uri", INVALID));
    };
    let mut redirect_uris = Vec::new();
    for uri in uris {
        match uri.as_str() {
            Some(uri) if redirect_uri_allowed(uri) && !redirect_uris.iter().any(|u| u == uri) => {
                redirect_uris.push(uri.to_owned());
            }
            _ => return Err(OAuthFailure::new(400, "invalid_redirect_uri", INVALID)),
        }
    }
    if redirect_uris.is_empty() || redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(OAuthFailure::new(400, "invalid_redirect_uri", INVALID));
    }
    let record = OAuthClientRecord {
        version: OAUTH_CLIENT_RECORD_VERSION,
        client_id: random_identifier(),
        client_name: client_name.to_owned(),
        redirect_uris,
        created_at: relay_now(clock)?,
    };
    let mut transaction = store.begin().await?;
    let result = transaction
        .insert_oauth_client(&record)
        .await
        .and_then(|inserted| inserted.then_some(()).ok_or(RelayErrorCode::Internal));
    settle(transaction, result).await?;
    Ok(RegisteredClient {
        client_id: record.client_id,
        client_name: record.client_name,
        redirect_uris: record.redirect_uris,
        token_endpoint_auth_method: "none",
    })
}

#[derive(Debug, Serialize)]
pub struct PushedRequest {
    pub request_uri: String,
    pub expires_in: u64,
}

pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// RFC 9126 pushed authorization request for an OpenID login.
pub async fn push_authorization_request(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    request_ttl_ms: u64,
    form: &Map<String, Value>,
) -> OAuthResult<PushedRequest> {
    if form.contains_key("authorization_details") {
        return Err(OAuthFailure {
            description: Some("authorization_details grants are not supported yet"),
            ..OAuthFailure::new(400, "invalid_authorization_details", INVALID)
        });
    }
    if form.contains_key("request_uri") || form.contains_key("request") {
        return Err(INVALID.into());
    }
    let client_id = canonical_str(required(form, "client_id")?, INVALID)?;
    let redirect_uri = required(form, "redirect_uri")?;
    if required(form, "response_type")? != "code" {
        return Err(OAuthFailure::new(400, "unsupported_response_type", INVALID));
    }
    let code_challenge = required(form, "code_challenge")?;
    if required(form, "code_challenge_method")? != "S256" || !is_code_challenge_s256(code_challenge)
    {
        return Err(INVALID.into());
    }
    let scope = required(form, "scope")?;
    let scopes: Vec<&str> = scope.split(' ').collect();
    if !scopes.contains(&"openid")
        || scopes
            .iter()
            .any(|scope| !matches!(*scope, "openid" | "account"))
    {
        return Err(OAuthFailure::new(400, "invalid_scope", INVALID));
    }
    let created_at = relay_now(clock)?;
    let record = ParRecord {
        version: OAUTH_PAR_RECORD_VERSION,
        par_id: random_identifier(),
        client_id: client_id.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        code_challenge: code_challenge.to_owned(),
        state: optional_bounded(form, "state")?,
        nonce: optional_bounded(form, "nonce")?,
        scope: scope.to_owned(),
        created_at,
        expires_at: created_at + request_ttl_ms,
    };
    let mut transaction = store.begin().await?;
    match push(&mut *transaction, &record).await {
        Ok(()) => transaction.commit().await?,
        Err(failure) => {
            transaction.rollback().await;
            return Err(failure);
        }
    }
    Ok(PushedRequest {
        request_uri: format!("{REQUEST_URI_PREFIX}{}", record.par_id),
        expires_in: request_ttl_ms / 1_000,
    })
}

async fn push(transaction: &mut dyn RelayTransaction, record: &ParRecord) -> OAuthResult<()> {
    let client = transaction
        .lock_oauth_client(&record.client_id)
        .await?
        .ok_or_else(|| OAuthFailure::new(401, "invalid_client", RelayErrorCode::NotFound))?;
    // Exact match against the URIs fixed at registration.
    if !client.redirect_uris.contains(&record.redirect_uri) {
        return Err(OAuthFailure::new(
            400,
            "invalid_request",
            RelayErrorCode::Forbidden,
        ));
    }
    if !transaction.insert_par(record).await? {
        return Err(RelayErrorCode::Internal.into());
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct PortalTransaction {
    pub transaction_id: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_origin: String,
    pub authorization_details: Vec<Value>,
    /// Unix seconds.
    pub expires_at: u64,
}

/// What the portal shows before the selection.
pub async fn read_transaction(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    transaction_id: &str,
) -> RelayResult<PortalTransaction> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let par = transaction
            .lock_par(transaction_id)
            .await?
            .ok_or(RelayErrorCode::NotFound)?;
        let client = transaction
            .lock_oauth_client(&par.client_id)
            .await?
            .ok_or(RelayErrorCode::RecordUnreadable)?;
        Ok((par, client))
    }
    .await;
    let (par, client) = settle(transaction, result).await?;
    if now >= par.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    let origin = Url::parse(&par.redirect_uri)
        .map_err(|_| RelayErrorCode::RecordUnreadable)?
        .origin()
        .ascii_serialization();
    Ok(PortalTransaction {
        transaction_id: par.par_id,
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_origin: origin,
        authorization_details: Vec::new(),
        expires_at: par.expires_at / 1_000,
    })
}

pub enum LoginDecision {
    Approved {
        signer_id: String,
        account_id: String,
    },
    Cancelled,
}

/// `{outcome: "approved", signer_id, account_id}` or `{outcome: "cancelled"}`.
pub fn login_decision(body: &Map<String, Value>) -> RelayResult<LoginDecision> {
    let text = |key| body.get(key).and_then(Value::as_str);
    match text("outcome") {
        Some("approved") if body.len() == 3 => Ok(LoginDecision::Approved {
            signer_id: canonical_str(text("signer_id").ok_or(INVALID)?, INVALID)?.to_owned(),
            account_id: canonical_str(text("account_id").ok_or(INVALID)?, INVALID)?.to_owned(),
        }),
        Some("cancelled") if body.len() == 1 => Ok(LoginDecision::Cancelled),
        _ => Err(INVALID),
    }
}

#[derive(Debug, Serialize)]
pub struct LoginRedirect {
    pub redirect: String,
}

fn redirect_url(issuer: &str, par: &ParRecord, outcome: Result<&str, ()>) -> RelayResult<String> {
    let mut url = Url::parse(&par.redirect_uri).map_err(|_| RelayErrorCode::RecordUnreadable)?;
    {
        let mut query = url.query_pairs_mut();
        match outcome {
            Ok(code) => query.append_pair("code", code),
            Err(()) => query.append_pair("error", "access_denied"),
        };
        if let Some(state) = &par.state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", issuer);
    }
    Ok(url.into())
}

/// Records the portal's login decision: the request, its terminal decision,
/// and (when approved) the one-time code, in one transaction.
pub async fn decide_login(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    issuer: &str,
    code_ttl_ms: u64,
    transaction_id: &str,
    decision: LoginDecision,
) -> RelayResult<LoginRedirect> {
    let decided_at = relay_now(clock)?;
    // Seal before the transaction: the store only ever receives the reference.
    let code = match decision {
        LoginDecision::Approved { .. } => {
            let code = random_identifier();
            let code_ref = seal_artifact(kms, &code).await?;
            Some((code, code_ref))
        }
        LoginDecision::Cancelled => None,
    };
    let mut transaction = store.begin().await?;
    let result = decide(
        &mut *transaction,
        transaction_id,
        &decision,
        code.as_ref(),
        decided_at,
        code_ttl_ms,
    )
    .await;
    let par = settle(transaction, result).await?;
    let outcome = code.as_ref().map(|(code, _)| code.as_str()).ok_or(());
    Ok(LoginRedirect {
        redirect: redirect_url(issuer, &par, outcome)?,
    })
}

async fn decide(
    transaction: &mut dyn RelayTransaction,
    transaction_id: &str,
    decision: &LoginDecision,
    code: Option<&(String, String)>,
    decided_at: u64,
    code_ttl_ms: u64,
) -> RelayResult<ParRecord> {
    let par = transaction
        .lock_par(transaction_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    if transaction
        .lock_authorization_request(&par.par_id)
        .await?
        .is_some()
    {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    if decided_at >= par.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    let (subject, owner) = match decision {
        LoginDecision::Approved {
            signer_id,
            account_id,
        } => {
            transaction
                .lock_signer(signer_id)
                .await?
                .ok_or(RelayErrorCode::NotFound)?;
            transaction
                .lock_account(account_id)
                .await?
                .ok_or(RelayErrorCode::NotFound)?;
            let member = transaction
                .list_signer_accounts(signer_id)
                .await?
                .iter()
                .any(|(account, _)| &account.account_id == account_id);
            if !member {
                return Err(RelayErrorCode::Forbidden);
            }
            (account_id.as_str(), signer_id.as_str())
        }
        LoginDecision::Cancelled => (CANCELLED_SUBJECT, CANCELLED_SUBJECT),
    };
    let request = AuthorizationRequestRecord {
        version: AUTHORIZATION_REQUEST_RECORD_VERSION,
        request_id: par.par_id.clone(),
        client_id: par.client_id.clone(),
        subject: subject.to_owned(),
        owner_device_id: owner.to_owned(),
        owner_subject: owner.to_owned(),
        organization_audience: None,
        redirect_uri: par.redirect_uri.clone(),
        code_challenge: par.code_challenge.clone(),
        requested_scope: LOGIN_SELECTION_SCOPE.to_owned(),
        created_at: par.created_at,
        expires_at: par.expires_at,
    };
    let record = AuthorizationDecisionRecord {
        version: AUTHORIZATION_DECISION_RECORD_VERSION,
        request_id: par.par_id.clone(),
        outcome: if code.is_some() {
            DecisionOutcome::Approved
        } else {
            DecisionOutcome::Rejected
        },
        decided_at,
        code_ref: code.map(|(_, code_ref)| code_ref.clone()),
        code_expires_at: code.map(|_| decided_at + code_ttl_ms),
    };
    if !transaction.insert_authorization_request(&request).await?
        || !transaction.insert_authorization_decision(&record).await?
    {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    if let Some((code, _)) = code {
        let inserted = transaction
            .insert_authorization_code(&AuthorizationCodeRecord {
                version: AUTHORIZATION_CODE_RECORD_VERSION,
                code_hash: sha256_base64url(code),
                request_id: par.par_id.clone(),
                client_id: par.client_id.clone(),
                redirect_uri: par.redirect_uri.clone(),
                code_challenge: par.code_challenge.clone(),
                // A login seals no artifact; this handle is never claimable.
                artifact_id: random_identifier(),
                created_at: decided_at,
                expires_at: decided_at + code_ttl_ms,
                consumed_at: None,
            })
            .await?;
        if !inserted {
            return Err(RelayErrorCode::Internal);
        }
    }
    Ok(par)
}

/// Recovers the redirect after a lost decision reply by reopening the sealed
/// code; it never mints a second one.
pub async fn recover_redirect(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
    issuer: &str,
    transaction_id: &str,
) -> RelayResult<LoginRedirect> {
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = async {
        let par = transaction
            .lock_par(transaction_id)
            .await?
            .ok_or(RelayErrorCode::NotFound)?;
        let decision = transaction.lock_authorization_decision(&par.par_id).await?;
        Ok((par, decision))
    }
    .await;
    let (par, decision) = settle(transaction, result).await?;
    let Some(decision) = decision else {
        return Err(if now >= par.expires_at {
            RelayErrorCode::Expired
        } else {
            RelayErrorCode::NotFound
        });
    };
    let redirect = match (
        decision.outcome,
        decision.code_ref,
        decision.code_expires_at,
    ) {
        (DecisionOutcome::Approved, Some(code_ref), Some(code_expires_at)) => {
            if now >= code_expires_at {
                return Err(RelayErrorCode::Expired);
            }
            let code = open_artifact(kms, &code_ref).await?;
            redirect_url(issuer, &par, Ok(&code))?
        }
        (DecisionOutcome::Approved, _, _) => return Err(RelayErrorCode::RecordUnreadable),
        _ => redirect_url(issuer, &par, Err(()))?,
    };
    Ok(LoginRedirect { redirect })
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// Opaque and unstored: no endpoint accepts it until grants arrive.
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    azp: &'a str,
    iat: u64,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    oaath_account: Value,
    signer: Value,
    verified: bool,
}

/// `grant_type=authorization_code` with PKCE for a public client.
pub async fn exchange_code(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    configuration: &OAuthConfiguration,
    form: &Map<String, Value>,
) -> OAuthResult<TokenResponse> {
    if required(form, "grant_type")? != "authorization_code" {
        return Err(OAuthFailure::new(400, "unsupported_grant_type", INVALID));
    }
    let client_id = canonical_str(required(form, "client_id")?, INVALID)?;
    let code = required(form, "code")?;
    let code_verifier = bounded_str(
        required(form, "code_verifier")?,
        limits::CODE_VERIFIER,
        INVALID,
    )?;
    let redirect_uri = bounded_str(
        required(form, "redirect_uri")?,
        limits::REDIRECT_URI,
        INVALID,
    )?;
    let invalid_client = || OAuthFailure::new(401, "invalid_client", RelayErrorCode::NotFound);
    let mut transaction = store.begin().await?;
    let result = transaction.lock_oauth_client(client_id).await;
    if settle(transaction, result).await?.is_none() {
        return Err(invalid_client());
    }
    // A malformed code is as invalid as an unknown one.
    canonical_str(code, RelayErrorCode::CodeInvalid)?;
    let caller = RelayCaller {
        role: RelayCallerRole::Client,
        client_id: client_id.to_owned(),
        subject: client_id.to_owned(),
        redirect_uris: Vec::new(),
        organization_audience: None,
    };
    let consumed = consume_authorization_code(
        store,
        clock,
        &caller,
        ConsumeAuthorizationCode {
            code,
            code_verifier,
            redirect_uri,
        },
    )
    .await?;
    let iat = relay_now(clock)? / 1_000;
    let mut transaction = store.begin().await?;
    let result = login_claims(&mut *transaction, &consumed.request_id).await;
    let (par, account, signer) = settle(transaction, result).await?;
    let credential = signer.credential()?;
    let id_token = configuration.key.sign(&IdTokenClaims {
        iss: &configuration.issuer,
        sub: &account.address,
        aud: &par.client_id,
        azp: &par.client_id,
        iat,
        exp: iat + ID_TOKEN_TTL_SECONDS,
        nonce: par.nonce.as_deref(),
        oaath_account: account.account_profile()?.to_json(),
        signer: json!({
            "id": signer.signer_id,
            "kind": credential.kind(),
            "profile": credential.to_json(),
        }),
        verified: false,
    })?;
    Ok(TokenResponse {
        access_token: random_identifier(),
        token_type: "Bearer",
        expires_in: ID_TOKEN_TTL_SECONDS,
        id_token,
        scope: par.scope,
    })
}

async fn login_claims(
    transaction: &mut dyn RelayTransaction,
    request_id: &str,
) -> RelayResult<(
    ParRecord,
    crate::registry::AccountRecord,
    crate::registry::SignerRecord,
)> {
    // Only a login request's code redeems here; any other code was released
    // by another flow and answers as invalid.
    let request = transaction
        .lock_authorization_request(request_id)
        .await?
        .filter(|request| request.requested_scope == LOGIN_SELECTION_SCOPE)
        .ok_or(RelayErrorCode::CodeInvalid)?;
    let approved = transaction
        .lock_authorization_decision(request_id)
        .await?
        .is_some_and(|decision| decision.outcome == DecisionOutcome::Approved);
    if !approved {
        return Err(RelayErrorCode::RecordUnreadable);
    }
    let par = transaction
        .lock_par(request_id)
        .await?
        .ok_or(RelayErrorCode::RecordUnreadable)?;
    let account = transaction
        .lock_account(&request.subject)
        .await?
        .ok_or(RelayErrorCode::RecordUnreadable)?;
    let signer = transaction
        .lock_signer(&request.owner_subject)
        .await?
        .ok_or(RelayErrorCode::RecordUnreadable)?;
    Ok((par, account, signer))
}
