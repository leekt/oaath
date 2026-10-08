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

pub mod grant;
pub mod id_token;
pub mod operation;
pub mod pending;
pub mod records;

use crate::revocation::RevocationDelivery;
use oaath_protocol::capture::parse_json;
use oaath_protocol::identity::parse_kernel_account_profile;
use serde::Serialize;
use serde_json::{Map, Value, json};
use url::Url;

use self::id_token::IdTokenKey;
use self::records::{
    MAX_CLIENT_NAME, MAX_REDIRECT_URIS, MAX_STATE, OAUTH_CLIENT_RECORD_VERSION,
    OAUTH_PAR_RECORD_VERSION, OAuthClientRecord, ParRecord, redirect_uri_allowed,
};
use crate::authentication::{RelayCaller, RelayCallerRole};
use crate::authority::stored_permission_request;
use crate::authorization::artifact::claim_encrypted_artifact;
use crate::authorization::challenge::{
    is_code_challenge_s256, random_identifier, sha256_base64url,
};
use crate::authorization::code::{ConsumeAuthorizationCode, consume_authorization_code};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::details::{Composition, compose, parse_grant_details};
use crate::grant::grant_signing_request;
use crate::kms::{RelayKms, open_artifact, seal_artifact};
use crate::records::{
    AUTHORIZATION_CODE_RECORD_VERSION, AUTHORIZATION_DECISION_RECORD_VERSION,
    AUTHORIZATION_REQUEST_RECORD_VERSION, AuthorizationCodeRecord, AuthorizationDecisionRecord,
    AuthorizationRequestRecord, DecisionOutcome, bounded_str, canonical_str, limits,
};
use crate::registry::{AccountRecord, MembershipRole, require_active_member};
use crate::store::{RelayStore, RelayTransaction, settle};
use oaath_protocol::grant_policy::{
    GrantPolicy, is_captured_policy_attenuation, parse_grant_policy,
};
use oaath_protocol::permission::PermissionRequest;

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
            | RelayErrorCode::Expired
            | RelayErrorCode::MembershipSuspended => Self::new(400, "invalid_grant", code),
            // RFC 8628 §3.5 polling answers, as CIBA uses them.
            RelayErrorCode::AuthorizationPending => Self::new(400, "authorization_pending", code),
            RelayErrorCode::AccessDenied => Self::new(400, "access_denied", code),
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
            "oaath_account", "oaath_accounts", "signer", "verified",
        ],
    })
}

/// 160 random bits as lowercase hex: a client id is also the protocol
/// `application.clientId`, whose canonical form is lowercase.
fn client_identifier() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 20];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Debug, Serialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: &'static str,
    pub revocation_delivery: RevocationDelivery,
}

/// RFC 7591 open registration of one public client.
pub async fn register_client(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    body: &Map<String, Value>,
) -> OAuthResult<RegisteredClient> {
    let metadata = |code| OAuthFailure::new(400, "invalid_client_metadata", code);
    let allowed = [
        "client_name",
        "redirect_uris",
        "token_endpoint_auth_method",
        "revocation_delivery",
    ];
    if body.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(metadata(INVALID));
    }
    match body.get("token_endpoint_auth_method") {
        None => {}
        Some(Value::String(method)) if method == "none" => {}
        // private_key_jwt is a later stage.
        Some(_) => return Err(metadata(INVALID)),
    }
    // OAAth submits revocations unless the client opts in to submit them itself.
    let revocation_delivery = match body.get("revocation_delivery") {
        None => RevocationDelivery::Relay,
        value => RevocationDelivery::parse(value).ok_or_else(|| metadata(INVALID))?,
    };
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
        client_id: client_identifier(),
        client_name: client_name.to_owned(),
        redirect_uris,
        revocation_delivery,
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
        revocation_delivery: record.revocation_delivery,
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
    let par_id = random_identifier();
    let invalid_details = || OAuthFailure::new(400, "invalid_authorization_details", INVALID);
    let operation = match param(form, "authorization_details") {
        None => None,
        Some(details) => {
            operation::operation_request(&parse_json(details).map_err(|_| invalid_details())?)
                .map_err(|_| invalid_details())?
        }
    };
    let authorization_details = match (param(form, "authorization_details"), &operation) {
        (None, _) => None,
        (Some(_), Some(request)) => Some(operation::stored_details(request)),
        (Some(details), None) => Some(
            grant_details(details, &par_id, client_id, redirect_uri, created_at)
                .map_err(|_| invalid_details())?,
        ),
    };
    let record = ParRecord {
        version: OAUTH_PAR_RECORD_VERSION,
        par_id,
        client_id: client_id.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        code_challenge: code_challenge.to_owned(),
        state: optional_bounded(form, "state")?,
        nonce: optional_bounded(form, "nonce")?,
        scope: scope.to_owned(),
        authorization_details,
        created_at,
        expires_at: created_at + request_ttl_ms,
    };
    let mut transaction = store.begin().await?;
    // An owner operation names its account: it must be a registry account.
    let bound = match &operation {
        Some(request) => operation::bound_account(&mut *transaction, request)
            .await
            .map(|_| ())
            .map_err(|_| invalid_details()),
        None => Ok(()),
    };
    let pushed = match bound {
        Ok(()) => push(&mut *transaction, &record).await,
        Err(failure) => Err(failure),
    };
    match pushed {
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

/// The redirect URI's `URL.origin`, as the grant's application origin.
pub fn redirect_origin(redirect_uri: &str) -> RelayResult<String> {
    Url::parse(redirect_uri)
        .map(|url| url.origin().ascii_serialization())
        .map_err(|_| INVALID)
}

/// Captures one `oaath_grant` detail and proves it composes into a protocol
/// request (with a stand-in account; the real one is chosen in the portal).
/// Answers its canonical stored form.
fn grant_details(
    text: &str,
    par_id: &str,
    client_id: &str,
    redirect_uri: &str,
    created_at: u64,
) -> RelayResult<String> {
    let detail = parse_grant_details(&parse_json(text).map_err(|_| INVALID)?)?;
    let stand_in = parse_kernel_account_profile(&json!({
        "version": "oaath.kernel-account-profile/v1",
        "kind": "kernel",
        "accountIndex": "0",
        "kernelVersion": "0.4.0",
        "factoryRoute": "kernel_factory",
        "entryPoint": { "version": "0.9" },
        "ownerCredential": {
            "version": "oaath.owner-credential-profile/v1",
            "kind": "ecdsa",
            "address": "0x0000000000000000000000000000000000000001",
        },
    }))
    .map_err(|_| RelayErrorCode::Internal)?;
    compose(
        &detail,
        &Composition {
            request_id: par_id,
            client_id,
            redirect_origin: &redirect_origin(redirect_uri)?,
            requested_at: created_at / 1_000,
            account_address: "0x0000000000000000000000000000000000000001",
            account: &stand_in,
        },
    )?;
    Ok(json!([detail.to_json()]).to_string())
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
        authorization_details: match &par.authorization_details {
            None => Vec::new(),
            Some(text) => match parse_json(text) {
                Ok(Value::Array(details)) => details,
                _ => return Err(RelayErrorCode::RecordUnreadable),
            },
        },
        expires_at: par.expires_at / 1_000,
    })
}

pub enum LoginDecision {
    Approved {
        signer_id: String,
        account_id: String,
    },
    /// A member asks the account's root to approve a grant transaction.
    RequestApproval {
        signer_id: String,
        account_id: String,
    },
    /// A root-signed grant approval artifact for a grant transaction.
    Grant {
        signer_id: String,
        account_id: String,
        artifact: String,
    },
    Cancelled,
}

/// `{outcome: "approved", signer_id, account_id, artifact?}`,
/// `{outcome: "request_approval", signer_id, account_id}` or
/// `{outcome: "cancelled"}`. The artifact is the root-signed grant approval.
pub fn login_decision(body: &Map<String, Value>) -> RelayResult<LoginDecision> {
    let text = |key| body.get(key).and_then(Value::as_str);
    let id = |key| canonical_str(text(key).ok_or(INVALID)?, INVALID).map(str::to_owned);
    match text("outcome") {
        Some("approved") if body.len() == 3 => Ok(LoginDecision::Approved {
            signer_id: id("signer_id")?,
            account_id: id("account_id")?,
        }),
        Some("approved") if body.len() == 4 => Ok(LoginDecision::Grant {
            signer_id: id("signer_id")?,
            account_id: id("account_id")?,
            artifact: bounded_str(
                text("artifact").ok_or(INVALID)?,
                limits::ARTIFACT_PLAINTEXT,
                INVALID,
            )?
            .to_owned(),
        }),
        Some("request_approval") if body.len() == 3 => Ok(LoginDecision::RequestApproval {
            signer_id: id("signer_id")?,
            account_id: id("account_id")?,
        }),
        Some("cancelled") if body.len() == 1 => Ok(LoginDecision::Cancelled),
        _ => Err(INVALID),
    }
}

#[derive(Debug, Serialize)]
pub struct LoginRedirect {
    pub redirect: String,
}

pub(crate) fn redirect_url(
    issuer: &str,
    par: &ParRecord,
    outcome: Result<&str, ()>,
) -> RelayResult<String> {
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
        LoginDecision::Grant { .. } | LoginDecision::RequestApproval { .. } => {
            return Err(RelayErrorCode::Internal);
        }
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
            // A grant needs the root's signed approval artifact.
            if par.authorization_details.is_some() {
                return Err(INVALID);
            }
            transaction
                .lock_signer(signer_id)
                .await?
                .ok_or(RelayErrorCode::NotFound)?;
            transaction
                .lock_account(account_id)
                .await?
                .ok_or(RelayErrorCode::NotFound)?;
            require_active_member(&mut *transaction, signer_id, account_id).await?;
            (account_id.as_str(), signer_id.as_str())
        }
        LoginDecision::Cancelled => (CANCELLED_SUBJECT, CANCELLED_SUBJECT),
        LoginDecision::Grant { .. } | LoginDecision::RequestApproval { .. } => {
            return Err(RelayErrorCode::Internal);
        }
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
        // A member's request redirects with its code before any decision.
        let pending = match decision {
            None => {
                pending::recover_pending_redirect(&mut *transaction, kms, issuer, &par, now).await?
            }
            Some(_) => None,
        };
        Ok((par, decision, pending))
    }
    .await;
    let (par, decision, pending) = settle(transaction, result).await?;
    if let Some(redirect) = pending {
        return Ok(redirect);
    }
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
    /// Opaque; stored as its hash. It reads and invalidates its own grant.
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<Value>>,
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
    /// Every account the signer is an active member of.
    oaath_accounts: Vec<Value>,
    signer: Value,
    verified: bool,
}

/// `grant_type=authorization_code` with PKCE for a public client.
pub async fn exchange_code(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    kms: &dyn RelayKms,
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
    // A member's request is redeemed only once its root decides.
    match pending::gate_exchange(store, clock, client_id, code, code_verifier, redirect_uri).await?
    {
        pending::PendingGate::Pending => return Err(RelayErrorCode::AuthorizationPending.into()),
        pending::PendingGate::Denied => return Err(RelayErrorCode::AccessDenied.into()),
        pending::PendingGate::Exchange => {}
    }
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
    let (par, account, signer, grant, memberships) = settle(transaction, result).await?;
    // A grant's sealed approval is released once, with the token.
    let authorization_details = match grant {
        Released::Login => None,
        Released::Grant(permission_request) => {
            let claimed =
                claim_encrypted_artifact(store, clock, kms, &caller, &consumed.artifact_id).await?;
            Some(vec![grant::grant_detail(
                &par.par_id,
                &permission_request,
                &claimed.artifact,
            )?])
        }
        Released::Operation => {
            let claimed =
                claim_encrypted_artifact(store, clock, kms, &caller, &consumed.artifact_id).await?;
            Some(vec![operation::operation_detail(&claimed.artifact)?])
        }
    };
    let access_token = grant::issue_access_token(store, clock, client_id, &par.par_id).await?;
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
        oaath_accounts: memberships,
        signer: json!({
            "id": signer.signer_id,
            "kind": credential.kind(),
            "profile": credential.to_json(),
        }),
        // Every approved decision required this signer's portal session, and
        // the decision checked its membership in the account.
        verified: true,
    })?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ID_TOKEN_TTL_SECONDS,
        id_token,
        scope: par.scope,
        authorization_details,
    })
}

/// What a redeemed code releases besides the login.
enum Released {
    Login,
    /// The composed permission request of a grant.
    Grant(Value),
    Operation,
}

async fn login_claims(
    transaction: &mut dyn RelayTransaction,
    request_id: &str,
) -> RelayResult<(
    ParRecord,
    crate::registry::AccountRecord,
    crate::registry::SignerRecord,
    Released,
    Vec<Value>,
)> {
    // Only a login's or an OAuth grant's code redeems here; any other code
    // was released by another flow and answers as invalid.
    let request = transaction
        .lock_authorization_request(request_id)
        .await?
        .ok_or(RelayErrorCode::CodeInvalid)?;
    let grant = if request.requested_scope == LOGIN_SELECTION_SCOPE {
        Released::Login
    } else if request.requested_scope == operation::OPERATION_SCOPE {
        Released::Operation
    } else {
        Released::Grant(
            stored_permission_request(&request.requested_scope, request_id)
                .ok_or(RelayErrorCode::CodeInvalid)?
                .to_json(),
        )
    };
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
    // A suspension between the decision and the exchange still refuses.
    require_active_member(transaction, &signer.signer_id, &account.account_id).await?;
    let memberships = active_accounts(transaction, &signer.signer_id).await?;
    Ok((par, account, signer, grant, memberships))
}

/// The `oaath_accounts` claim: one entry per account the signer actively
/// belongs to, in account creation order, as root when any active membership
/// is the root.
async fn active_accounts(
    transaction: &mut dyn RelayTransaction,
    signer_id: &str,
) -> RelayResult<Vec<Value>> {
    let mut accounts: Vec<(String, MembershipRole)> = Vec::new();
    for (account, membership) in transaction.list_signer_accounts(signer_id).await? {
        if !membership.is_active() {
            continue;
        }
        match accounts
            .iter_mut()
            .find(|(address, _)| *address == account.address)
        {
            Some((_, role)) if membership.role == MembershipRole::Root => {
                *role = MembershipRole::Root
            }
            Some(_) => {}
            None => accounts.push((account.address, membership.role)),
        }
    }
    Ok(accounts
        .into_iter()
        .map(|(address, role)| json!({ "address": address, "role": role, "status": "active" }))
        .collect())
}

#[derive(Debug, Serialize)]
pub struct PreparedGrant {
    /// The composed protocol request the decision must approve, byte for byte.
    pub permission_request: Value,
    pub request_hash: String,
    /// The policy the root approves: the request's, or the owner's narrowing.
    pub approved_policy: Value,
    /// The exact `kernel-enable` owner signing request the account root signs.
    pub signing_request: Value,
}

/// `{signer_id, account_id, approved_policy?}`.
pub fn prepare_selection(
    body: &Map<String, Value>,
) -> RelayResult<(String, String, Option<GrantPolicy>)> {
    let allowed = ["signer_id", "account_id", "approved_policy"];
    if body.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(INVALID);
    }
    let text = |key| {
        body.get(key)
            .and_then(Value::as_str)
            .and_then(|value| canonical_str(value, INVALID).ok())
            .map(str::to_owned)
            .ok_or(INVALID)
    };
    let approved = body
        .get("approved_policy")
        .map(|policy| parse_grant_policy(policy).map_err(|_| INVALID))
        .transpose()?;
    Ok((text("signer_id")?, text("account_id")?, approved))
}

/// Reads an undecided, unexpired grant transaction and the root's account,
/// and composes the one request a decision may approve.
pub async fn grant_selection(
    transaction: &mut dyn RelayTransaction,
    transaction_id: &str,
    signer_id: &str,
    account_id: &str,
    now: u64,
) -> RelayResult<(ParRecord, PermissionRequest, AccountRecord)> {
    let par = transaction
        .lock_par(transaction_id)
        .await?
        .ok_or(RelayErrorCode::NotFound)?;
    if par.authorization_details.is_none() {
        return Err(INVALID);
    }
    if transaction
        .lock_authorization_request(&par.par_id)
        .await?
        .is_some()
    {
        return Err(RelayErrorCode::AlreadyDecided);
    }
    if now >= par.expires_at {
        return Err(RelayErrorCode::Expired);
    }
    // Only the account's policy-free root approves a grant.
    let account = transaction
        .list_signer_accounts(signer_id)
        .await?
        .into_iter()
        .find(|(account, membership)| {
            account.account_id == account_id && membership.role == MembershipRole::Root
        })
        .map(|(account, _)| account)
        .ok_or(RelayErrorCode::Forbidden)?;
    let request = compose_par_grant(&par, &account)?;
    Ok((par, request, account))
}

/// The one request a grant PAR composes for `account`.
pub(crate) fn compose_par_grant(
    par: &ParRecord,
    account: &AccountRecord,
) -> RelayResult<PermissionRequest> {
    let details = par.authorization_details.as_deref().ok_or(INVALID)?;
    let detail = parse_grant_details(&parse_json(details).map_err(|_| INVALID)?)
        .map_err(|_| RelayErrorCode::RecordUnreadable)?;
    compose(
        &detail,
        &Composition {
            request_id: &par.par_id,
            client_id: &par.client_id,
            redirect_origin: &redirect_origin(&par.redirect_uri)?,
            requested_at: par.created_at / 1_000,
            account_address: &account.address,
            account: &account.account_profile()?,
        },
    )
}

/// What the account root must sign for this grant; nothing is persisted.
/// `session` is the request's proven signer; only it may prepare.
pub async fn prepare_grant(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    transaction_id: &str,
    body: &Map<String, Value>,
    session: &str,
) -> RelayResult<PreparedGrant> {
    let (signer_id, account_id, approved) = prepare_selection(body)?;
    if signer_id != session {
        return Err(RelayErrorCode::Forbidden);
    }
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = grant_selection(
        &mut *transaction,
        transaction_id,
        &signer_id,
        &account_id,
        now,
    )
    .await;
    let (_, request, account) = settle(transaction, result).await?;
    let policy = match approved {
        None => request.policy.clone(),
        // The owner may narrow, never widen.
        Some(policy) if is_captured_policy_attenuation(&request.policy, &policy) => policy,
        Some(_) => return Err(INVALID),
    };
    let signing = grant_signing_request(&request, &policy, &account.address)?;
    Ok(PreparedGrant {
        permission_request: request.to_json(),
        request_hash: format!("{:#x}", request.hash()),
        approved_policy: policy.to_json(),
        signing_request: signing.to_json(),
    })
}
