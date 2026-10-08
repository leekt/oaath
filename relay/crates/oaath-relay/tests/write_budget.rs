//! The hard per-client budget for public writes: spent per route and
//! Worker-attested client address in one-minute windows.

mod support;

use axum::body::Body;
use axum::http::Request;
use oaath_relay::error::RelayErrorCode as E;
use serde_json::{Value, json};
use support::*;

fn from(ip: Option<&str>, mut request: Request<Body>) -> Request<Body> {
    if let Some(ip) = ip {
        request
            .headers_mut()
            .insert("x-oaath-client-ip", ip.parse().unwrap());
    }
    request
}

fn client(ip: Option<&str>) -> Request<Body> {
    from(
        ip,
        post(
            "/oauth/clients",
            None,
            Some(json!({ "client_name": "Dapp", "redirect_uris": [REDIRECT_URI] })),
        ),
    )
}

fn signer(ip: Option<&str>) -> Request<Body> {
    from(
        ip,
        portal_call(
            "POST",
            "/portal/signers",
            None,
            Some(json!({ "profile": {} })),
        ),
    )
}

#[tokio::test]
async fn refuses_a_client_past_its_budget_until_the_window_turns() {
    let h = harness_with(|options| options.writes_per_minute = Some(2));
    let ip = Some("203.0.113.9");
    h.send(client(ip)).await.ok(201);
    h.send(client(ip)).await.ok(201);
    let refused = h.send(client(ip)).await;
    assert_eq!(refused.status, 429);
    assert_eq!(
        refused.body,
        json!({ "error": "temporarily_unavailable", "error_code": "relay_rate_limited" })
    );
    // Other clients, and other routes, keep their own budgets.
    h.send(client(Some("2001:db8::1"))).await.ok(201);
    assert_ne!(h.send(signer(ip)).await.status, 429);
    // The next window starts afresh.
    h.clock.advance(60_000);
    h.send(client(ip)).await.ok(201);
}

#[tokio::test]
async fn spends_on_refused_requests_and_answers_the_portal_envelope() {
    let h = harness_with(|options| options.writes_per_minute = Some(2));
    let ip = Some("198.51.100.7");
    // An invalid profile is refused, and still spends.
    h.send(signer(ip)).await.failure(E::RequestInvalid);
    h.send(signer(ip)).await.failure(E::RequestInvalid);
    h.send(signer(ip)).await.failure(E::RateLimited);
    let challenge = from(
        ip,
        portal_call(
            "POST",
            "/portal/sessions/challenge",
            None,
            Some(json!({ "signer_id": "unknown" })),
        ),
    );
    assert_ne!(h.send(challenge).await.status, 429);
}

#[tokio::test]
async fn refuses_a_malformed_client_address_and_budgets_only_attested_clients() {
    let h = harness_with(|options| options.writes_per_minute = Some(1));
    // Only the Worker sets the header; a value that is not an address is refused.
    for spoofed in ["203.0.113.9, 10.0.0.1", "unknown", "203.0.113.9:443"] {
        let reply = h.send(client(Some(spoofed))).await;
        assert_eq!(reply.status, 400, "{spoofed}");
        assert_eq!(
            reply.body["error_code"],
            Value::from("relay_request_invalid")
        );
    }
    // Without the header the request came from inside the relay's network.
    for _ in 0..3 {
        h.send(client(None)).await.ok(201);
    }
    h.send(client(Some("203.0.113.9"))).await.ok(201);
    assert_eq!(h.send(client(Some("203.0.113.9"))).await.status, 429);
}
