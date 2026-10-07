//! Portal sessions: a signer proves control of its credential once, and a
//! short-lived same-origin cookie then unlocks that signer's private portal
//! data.
//!
//! ```text
//! POST   /portal/sessions/challenge  {signer_id?}                 -> {nonce, expires_at, message?}
//! POST   /portal/sessions            {signer_id, nonce, signature} -> {signer_id, expires_at} + cookie
//! DELETE /portal/sessions                                          -> {} + cleared cookie
//! ```
//!
//! ```text
//! state and owner      challenge: issued -> consumed (one sign-in) | expired;
//!                      session: active -> expired | signed out
//! persisted evidence   oaath_portal_challenge_v1 (nonce), oaath_portal_session_v1
//!                      (SHA-256 of the cookie token, never the token)
//! resource occupied?   a consumed challenge never authorizes again
//! retry safe?          a sign-in is one transaction; a lost reply leaves the
//!                      nonce consumed and the user signs in again
//! forbidden            a consumed, expired, or unknown nonce; a proof by another
//!                      key or for another domain, URI, origin, or challenge; a
//!                      signed-out or expired session; another signer's session
//! crash/reload         records are durable; a restart keeps sessions and still
//!                      refuses consumed nonces
//! cleanup owner        expiry; sign-out ends the session it names
//! ```
//!
//! Proofs, by credential kind:
//!
//! - ECDSA: an ERC-4361 (Sign-In with Ethereum) message the relay builds
//!   itself: domain = the issuer's authority, URI = the issuer, the nonce, and
//!   the challenge's own issue and expiry times. The wallet's `personal_sign`
//!   must recover to the signer's address. ERC-4361 requires a chain ID; a
//!   session is not chain-bound, so it names the deployment's target chain.
//! - WebAuthn and P-256: the grant root verifier over the 32 nonce bytes as
//!   the digest, so a passkey asserts with `challenge = nonce`, rpId = the
//!   issuer host, origin = the issuer, and user verification.

use alloy_primitives::{Address, B256};
use axum::http::{HeaderMap, header};
use oaath_protocol::identity::OwnerCredentialProfile;
use rand::RngCore;
use serde::Serialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::authorization::challenge::{random_identifier, sha256_base64url};
use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::grant::signature::{RelyingParty, verify_ecdsa_message, verify_root_signature};
use crate::oauth::grant::relying_party;
use crate::records::{canonical_identifier, canonical_str, exact_record, timestamp};
use crate::store::{RelayStore, settle};

pub const PORTAL_CHALLENGE_RECORD_VERSION: &str = "oaath.portal-challenge-record/v1";
pub const PORTAL_SESSION_RECORD_VERSION: &str = "oaath.portal-session-record/v1";
pub const SESSION_COOKIE: &str = "oaath_portal_session";
pub const CHALLENGE_TTL_MS: u64 = 300_000;
pub const SESSION_TTL_MS: u64 = 1_800_000;
/// Arbitrum Sepolia, the portal's target chain.
pub const SIWE_CHAIN_ID: u64 = 421_614;
const SIWE_STATEMENT: &str = "Sign in to OAAth. This signature approves nothing.";
/// A WebAuthn assertion envelope stays well inside this many hex digits.
const MAX_SIGNATURE_HEX: usize = 16_384;

const INVALID: RelayErrorCode = RelayErrorCode::RequestInvalid;
const UNAUTHENTICATED: RelayErrorCode = RelayErrorCode::Unauthenticated;
const UNREADABLE: RelayErrorCode = RelayErrorCode::RecordUnreadable;

/// One sign-in challenge. Its nonce is public: it appears in the signed message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalChallengeRecord {
    pub version: &'static str,
    /// 32 random bytes as 64 lowercase hex digits.
    pub nonce: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// Set once, by the sign-in that used it. A non-null value is terminal.
    pub consumed_at: Option<u64>,
}

/// One portal session for one signer, stored only as its token's SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalSessionRecord {
    pub version: &'static str,
    pub token_hash: String,
    pub signer_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// Set once, by sign-out. A non-null value is terminal.
    pub signed_out_at: Option<u64>,
}

fn nullable_timestamp(value: Option<&Value>) -> RelayResult<Option<u64>> {
    match value {
        Some(Value::Null) => Ok(None),
        other => timestamp(other, UNREADABLE).map(Some),
    }
}

fn is_nonce(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl PortalChallengeRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &["version", "nonce", "createdAt", "expiresAt", "consumedAt"],
            UNREADABLE,
        )?;
        if r.get("version").and_then(Value::as_str) != Some(PORTAL_CHALLENGE_RECORD_VERSION) {
            return Err(UNREADABLE);
        }
        let nonce = r.get("nonce").and_then(Value::as_str).ok_or(UNREADABLE)?;
        if !is_nonce(nonce) {
            return Err(UNREADABLE);
        }
        Ok(Self {
            version: PORTAL_CHALLENGE_RECORD_VERSION,
            nonce: nonce.to_owned(),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            expires_at: timestamp(r.get("expiresAt"), UNREADABLE)?,
            consumed_at: nullable_timestamp(r.get("consumedAt"))?,
        })
    }
}

impl PortalSessionRecord {
    pub fn parse(value: &Value) -> RelayResult<Self> {
        let r = exact_record(
            value,
            &[
                "version",
                "tokenHash",
                "signerId",
                "createdAt",
                "expiresAt",
                "signedOutAt",
            ],
            UNREADABLE,
        )?;
        if r.get("version").and_then(Value::as_str) != Some(PORTAL_SESSION_RECORD_VERSION) {
            return Err(UNREADABLE);
        }
        Ok(Self {
            version: PORTAL_SESSION_RECORD_VERSION,
            token_hash: canonical_identifier(r.get("tokenHash"), UNREADABLE)?.to_owned(),
            signer_id: canonical_identifier(r.get("signerId"), UNREADABLE)?.to_owned(),
            created_at: timestamp(r.get("createdAt"), UNREADABLE)?,
            expires_at: timestamp(r.get("expiresAt"), UNREADABLE)?,
            signed_out_at: nullable_timestamp(r.get("signedOutAt"))?,
        })
    }
}

fn rfc3339(milliseconds: u64) -> RelayResult<String> {
    let seconds = i64::try_from(milliseconds / 1_000).map_err(|_| RelayErrorCode::Internal)?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .ok_or(RelayErrorCode::Internal)
}

/// The exact ERC-4361 message an ECDSA signer signs for `challenge`.
pub fn siwe_message(
    issuer: &str,
    address: &str,
    challenge: &PortalChallengeRecord,
) -> RelayResult<String> {
    let (_, origin) = relying_party(issuer)?;
    let authority = origin
        .split_once("://")
        .map(|(_, authority)| authority)
        .ok_or(RelayErrorCode::Internal)?;
    let address = address
        .parse::<Address>()
        .map_err(|_| RelayErrorCode::Internal)?
        .to_checksum(None);
    Ok(format!(
        "{authority} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         {SIWE_STATEMENT}\n\n\
         URI: {issuer}\n\
         Version: 1\n\
         Chain ID: {SIWE_CHAIN_ID}\n\
         Nonce: {nonce}\n\
         Issued At: {issued}\n\
         Expiration Time: {expires}",
        nonce = challenge.nonce,
        issued = rfc3339(challenge.created_at)?,
        expires = rfc3339(challenge.expires_at)?,
    ))
}

#[derive(Debug, Serialize)]
pub struct IssuedChallenge {
    pub nonce: String,
    /// Unix seconds.
    pub expires_at: u64,
    /// The sign-in message, when the named signer is an ECDSA wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Issues one challenge. Naming a signer only adds the SIWE message an ECDSA
/// signer must sign; the nonce itself is bound to nothing until it is used.
pub async fn issue_challenge(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    issuer: &str,
    body: &Map<String, Value>,
) -> RelayResult<IssuedChallenge> {
    let signer_id = match body.len() {
        0 => None,
        1 => Some(canonical_identifier(body.get("signer_id"), INVALID)?),
        _ => return Err(INVALID),
    };
    let now = relay_now(clock)?;
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let record = PortalChallengeRecord {
        version: PORTAL_CHALLENGE_RECORD_VERSION,
        nonce: hex::encode(nonce),
        created_at: now,
        expires_at: now + CHALLENGE_TTL_MS,
        consumed_at: None,
    };
    let mut transaction = store.begin().await?;
    let result = async {
        let signer = match signer_id {
            None => None,
            Some(id) => Some(
                transaction
                    .lock_signer(id)
                    .await?
                    .ok_or(RelayErrorCode::NotFound)?,
            ),
        };
        if !transaction.insert_portal_challenge(&record).await? {
            return Err(RelayErrorCode::Internal);
        }
        Ok(signer)
    }
    .await;
    let signer = settle(transaction, result).await?;
    let message = match signer.map(|signer| signer.credential()).transpose()? {
        Some(OwnerCredentialProfile::Ecdsa { address }) => {
            Some(siwe_message(issuer, &address, &record)?)
        }
        _ => None,
    };
    Ok(IssuedChallenge {
        nonce: record.nonce,
        expires_at: record.expires_at / 1_000,
        message,
    })
}

#[derive(Debug, Serialize)]
pub struct SignedIn {
    pub signer_id: String,
    /// Unix seconds.
    pub expires_at: u64,
}

/// A started session: the reply and the cookie token, which is never stored.
pub struct StartedSession {
    pub signed_in: SignedIn,
    pub token: String,
}

fn signature_bytes(value: Option<&Value>) -> RelayResult<Vec<u8>> {
    value
        .and_then(Value::as_str)
        .and_then(|text| text.strip_prefix("0x"))
        .filter(|digits| !digits.is_empty() && digits.len() <= MAX_SIGNATURE_HEX)
        .and_then(|digits| hex::decode(digits).ok())
        .ok_or(INVALID)
}

/// Verifies one proof against an unused, unexpired challenge, consumes the
/// challenge, and starts a session for the signer, in one transaction.
pub async fn sign_in(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    issuer: &str,
    body: &Map<String, Value>,
) -> RelayResult<StartedSession> {
    exact_record(
        &Value::Object(body.clone()),
        &["signer_id", "nonce", "signature"],
        INVALID,
    )?;
    let signer_id = canonical_identifier(body.get("signer_id"), INVALID)?;
    let nonce = body
        .get("nonce")
        .and_then(Value::as_str)
        .filter(|nonce| is_nonce(nonce))
        .ok_or(INVALID)?;
    let signature = signature_bytes(body.get("signature"))?;
    let (rp_id, origin) = relying_party(issuer)?;
    let now = relay_now(clock)?;
    let token = random_identifier();
    let session = PortalSessionRecord {
        version: PORTAL_SESSION_RECORD_VERSION,
        token_hash: sha256_base64url(&token),
        signer_id: signer_id.to_owned(),
        created_at: now,
        expires_at: now + SESSION_TTL_MS,
        signed_out_at: None,
    };
    let mut transaction = store.begin().await?;
    let result = async {
        let challenge = transaction
            .lock_portal_challenge(nonce)
            .await?
            .ok_or(UNAUTHENTICATED)?;
        if challenge.consumed_at.is_some() {
            return Err(UNAUTHENTICATED);
        }
        if now >= challenge.expires_at {
            return Err(RelayErrorCode::Expired);
        }
        let signer = transaction
            .lock_signer(signer_id)
            .await?
            .ok_or(RelayErrorCode::NotFound)?;
        let proven = match signer.credential()? {
            OwnerCredentialProfile::Ecdsa { address } => verify_ecdsa_message(
                &address,
                siwe_message(issuer, &address, &challenge)?.as_bytes(),
                &signature,
            ),
            owner => verify_root_signature(
                &owner,
                nonce.parse::<B256>().map_err(|_| INVALID)?,
                &signature,
                &RelyingParty {
                    rp_id: &rp_id,
                    origin: &origin,
                },
            ),
        };
        if !proven {
            return Err(UNAUTHENTICATED);
        }
        if !transaction.consume_portal_challenge(nonce, now).await? {
            return Err(UNAUTHENTICATED);
        }
        if !transaction.insert_portal_session(&session).await? {
            return Err(RelayErrorCode::Internal);
        }
        Ok(())
    }
    .await;
    settle(transaction, result).await?;
    Ok(StartedSession {
        signed_in: SignedIn {
            signer_id: session.signer_id,
            expires_at: session.expires_at / 1_000,
        },
        token,
    })
}

/// The `Set-Cookie` value carrying a new session token.
pub fn session_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Max-Age={}; Path=/portal; HttpOnly; Secure; SameSite=Strict",
        SESSION_TTL_MS / 1_000
    )
}

/// The `Set-Cookie` value that removes the session cookie.
pub fn cleared_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Max-Age=0; Path=/portal; HttpOnly; Secure; SameSite=Strict")
}

/// The one session token the request carries; none, several, or a malformed
/// one reads as absent.
fn session_token(headers: &HeaderMap) -> Option<&str> {
    let mut tokens = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, token)| token);
    let token = tokens.next()?;
    if tokens.next().is_some() {
        return None;
    }
    canonical_str(token, INVALID).ok()
}

/// The signer of the request's active session, or `relay_unauthenticated`.
pub async fn session_signer(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    headers: &HeaderMap,
) -> RelayResult<String> {
    let token = session_token(headers).ok_or(UNAUTHENTICATED)?;
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = transaction
        .lock_portal_session(&sha256_base64url(token))
        .await;
    let session = settle(transaction, result).await?.ok_or(UNAUTHENTICATED)?;
    if session.signed_out_at.is_some() || now >= session.expires_at {
        return Err(UNAUTHENTICATED);
    }
    Ok(session.signer_id)
}

/// Requires the request's active session to be `signer_id`'s: no session is
/// `relay_unauthenticated`, another signer's is `relay_forbidden`.
pub async fn require_signer(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    headers: &HeaderMap,
    signer_id: &str,
) -> RelayResult<()> {
    if session_signer(store, clock, headers).await? == signer_id {
        Ok(())
    } else {
        Err(RelayErrorCode::Forbidden)
    }
}

/// Ends the request's session, if it carries an active one.
pub async fn sign_out(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    headers: &HeaderMap,
) -> RelayResult<()> {
    let Some(token) = session_token(headers) else {
        return Ok(());
    };
    let now = relay_now(clock)?;
    let mut transaction = store.begin().await?;
    let result = transaction
        .end_portal_session(&sha256_base64url(token), now)
        .await;
    settle(transaction, result).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_erc_4361_message_for_the_issuer() {
        let challenge = PortalChallengeRecord {
            version: PORTAL_CHALLENGE_RECORD_VERSION,
            nonce: "ab".repeat(32),
            created_at: 1_700_000_000_123,
            expires_at: 1_700_000_300_123,
            consumed_at: None,
        };
        let message = siwe_message(
            "http://localhost:5173",
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            &challenge,
        )
        .unwrap();
        assert_eq!(
            message,
            format!(
                "localhost:5173 wants you to sign in with your Ethereum account:\n\
                 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\n\n\
                 Sign in to OAAth. This signature approves nothing.\n\n\
                 URI: http://localhost:5173\n\
                 Version: 1\n\
                 Chain ID: 421614\n\
                 Nonce: {}\n\
                 Issued At: 2023-11-14T22:13:20Z\n\
                 Expiration Time: 2023-11-14T22:18:20Z",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn reads_exactly_one_well_formed_session_cookie() {
        let headers = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(header::COOKIE, value.parse().unwrap());
            }
            headers
        };
        assert_eq!(
            session_token(&headers(&["a=1; oaath_portal_session=tok-1"])),
            Some("tok-1")
        );
        assert_eq!(session_token(&headers(&["a=1"])), None);
        assert_eq!(
            session_token(&headers(&[
                "oaath_portal_session=tok-1",
                "oaath_portal_session=tok-2"
            ])),
            None
        );
        assert_eq!(
            session_token(&headers(&["oaath_portal_session=not canonical"])),
            None
        );
    }
}
