//! The relay's hard per-client budget for public writes: client registration,
//! PAR, signer registration and sign-in challenges.
//!
//! ```text
//! OAATH_WRITES_PER_MINUTE   writes per route and client per minute (default 30)
//! ```
//!
//! The portal Worker (`portal/worker/index.ts`) spends its own soft Cloudflare
//! budget first, then sets `x-oaath-client-ip` from `cf-connecting-ip`; the
//! client's own copy never reaches the relay, because the Worker forwards only
//! allow-listed headers. A request without the header did not pass the
//! Worker: it comes from inside the relay's network boundary (local
//! operators, tests) and is not budgeted. A malformed value is refused.
//!
//! Each route and client address has a fixed one-minute window counter,
//! spent in its own transaction before the request is handled, so a failed
//! request still spends. Past windows are deleted as new ones are spent.

use std::net::IpAddr;

use axum::http::{HeaderMap, Method};

use crate::clock::{RelayClock, relay_now};
use crate::error::{RelayErrorCode, RelayResult};
use crate::store::{RelayStore, settle};

pub const CLIENT_IP_HEADER: &str = "x-oaath-client-ip";
pub const DEFAULT_WRITES_PER_MINUTE: u64 = 30;
pub const WINDOW_MS: u64 = 60_000;

/// The budgeted route a request spends on, if any.
pub fn budgeted_route(method: &Method, path: &str) -> Option<&'static str> {
    if method != Method::POST {
        return None;
    }
    match path.trim_end_matches('/') {
        "/oauth/clients" => Some("clients"),
        "/oauth/par" => Some("par"),
        "/portal/signers" => Some("signers"),
        "/portal/sessions/challenge" => Some("challenge"),
        _ => None,
    }
}

/// Spends one write for the Worker-attested client on `route`, or refuses
/// with `relay_rate_limited` once this window's budget is spent.
pub async fn spend(
    store: &dyn RelayStore,
    clock: &dyn RelayClock,
    headers: &HeaderMap,
    route: &str,
    limit: u64,
) -> RelayResult<()> {
    let Some(value) = headers.get(CLIENT_IP_HEADER) else {
        return Ok(());
    };
    let address: IpAddr = value
        .to_str()
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or(RelayErrorCode::RequestInvalid)?;
    let now = relay_now(clock)?;
    let window = now - now % WINDOW_MS;
    let mut transaction = store.begin().await?;
    let result = transaction
        .spend_write_budget(&format!("{route}:{address}"), window)
        .await;
    let spent = settle(transaction, result).await?;
    if spent > limit {
        return Err(RelayErrorCode::RateLimited);
    }
    Ok(())
}
