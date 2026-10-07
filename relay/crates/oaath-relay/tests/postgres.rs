//! PostgreSQL store and process-restart proofs
//! (ported from `packages/server/test/{postgres,restart}.test.ts`).
//!
//! Every step recreates the pool, store, and relay, so the durable rows alone
//! decide what may still happen. Requires `OAATH_TEST_POSTGRES=1` and
//! `OAATH_TEST_POSTGRES_URL`; `relay/scripts/test-postgres.sh` provides both
//! with a throwaway cluster. Skipped otherwise.

mod support;

use std::sync::Arc;

use oaath_relay::error::RelayErrorCode as E;
use oaath_relay::store::RelayStore;
use oaath_relay::store::postgres::{PostgresRelayStore, create_relay_schema};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use support::*;

fn database() -> Option<String> {
    if std::env::var("OAATH_TEST_POSTGRES").as_deref() != Ok("1") {
        eprintln!("skipped: set OAATH_TEST_POSTGRES=1 (relay/scripts/test-postgres.sh)");
        return None;
    }
    Some(std::env::var("OAATH_TEST_POSTGRES_URL").expect("OAATH_TEST_POSTGRES_URL"))
}

/// One disposable schema per test, selected through `search_path`.
struct Fixture {
    url: String,
    schema: String,
}

impl Fixture {
    async fn create(url: String) -> Self {
        let schema = format!(
            "oaath_test_{}",
            oaath_relay::authorization::challenge::random_identifier()
                .to_ascii_lowercase()
                .replace(['-', '_'], "")
                .chars()
                .take(16)
                .collect::<String>()
        );
        let admin = PgPool::connect(&url).await.expect("admin pool");
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("schema");
        admin.close().await;
        let fixture = Self { url, schema };
        let pool = fixture.pool().await;
        create_relay_schema(&pool).await.expect("relay schema");
        pool.close().await;
        fixture
    }

    async fn pool(&self) -> PgPool {
        let options: PgConnectOptions = self.url.parse().expect("url");
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options.options([("search_path", self.schema.as_str())]))
            .await
            .expect("pool")
    }

    /// A fresh process: new pool, store, and relay over the same rows.
    async fn process(&self, clock: Arc<TestClock>) -> Harness {
        let store: Arc<dyn RelayStore> = Arc::new(PostgresRelayStore::owning(self.pool().await));
        harness_on(store, clock, |_| {})
    }
}

async fn shutdown(h: Harness) {
    h.store.close().await.unwrap();
}

#[tokio::test]
async fn keeps_the_distinct_approving_device_after_a_restart_and_routing_change() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let store: Arc<dyn RelayStore> = Arc::new(PostgresRelayStore::owning(fixture.pool().await));
    let before = harness_on(store, clock.clone(), |options| {
        options.owner_routing = TestOwnerRouting::new(Some(("team-phone", "subject-2")));
    });
    let request_id = before.create_request().await;
    shutdown(before).await;

    let after = fixture.process(clock).await;
    let mut transaction = after.store.begin().await.unwrap();
    let stored = transaction
        .lock_authorization_request(&request_id)
        .await
        .unwrap()
        .unwrap();
    transaction.rollback().await;
    assert_eq!(stored.subject, "subject-1");
    assert_eq!(stored.owner_device_id, "team-phone");
    assert_eq!(stored.owner_subject, "subject-2");
    after
        .fetch(&request_id, OWNER_TOKEN)
        .await
        .failure(E::NotFound);
    let state = after
        .fetch(&request_id, OTHER_OWNER_TOKEN)
        .await
        .ok(200)
        .clone();
    assert_eq!(state["decision"], Value::Null);
    let decision = after
        .decide(
            &request_id,
            OTHER_OWNER_TOKEN,
            json!({ "outcome": "approved", "artifact": permission_artifact(&request_id) }),
        )
        .await
        .ok(200)
        .clone();
    after.consume(text(&decision, "code")).await.ok(200);
    shutdown(after).await;
}

#[tokio::test]
async fn keeps_a_code_and_an_artifact_one_shot_across_a_restart() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let before = fixture.process(clock.clone()).await;
    let request_id = before.create_request().await;
    let decision = before.approve(&request_id).await;
    before.consume(text(&decision, "code")).await.ok(200);
    shutdown(before).await;

    let after = fixture.process(clock.clone()).await;
    after
        .consume(text(&decision, "code"))
        .await
        .failure(E::CodeAlreadyConsumed);
    let claimed = after
        .claim(text(&decision, "artifactId"))
        .await
        .ok(200)
        .clone();
    assert_eq!(claimed["artifact"], json!(permission_artifact(&request_id)));
    shutdown(after).await;

    let last = fixture.process(clock).await;
    last.claim(text(&decision, "artifactId"))
        .await
        .failure(E::ArtifactAlreadyClaimed);
    shutdown(last).await;
}

#[tokio::test]
async fn keeps_a_decision_terminal_and_invalidation_stable_across_a_restart() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let before = fixture.process(clock.clone()).await;
    let request_id = before.create_request().await;
    before.approve(&request_id).await;
    let invalidation =
        json!({ "grantId": "grant-1", "capabilityHash": format!("0x{}", "ab".repeat(32)) });
    let evidence = before
        .send(post(
            "/invalidations",
            Some(CLIENT_TOKEN),
            Some(invalidation.clone()),
        ))
        .await
        .ok(200)
        .clone();
    shutdown(before).await;

    clock.advance(5_000);
    let after = fixture.process(clock).await;
    after
        .decide(&request_id, OWNER_TOKEN, json!({ "outcome": "rejected" }))
        .await
        .failure(E::AlreadyDecided);
    assert_eq!(
        *after
            .send(post(
                "/invalidations",
                Some(CLIENT_TOKEN),
                Some(invalidation)
            ))
            .await
            .ok(200),
        evidence
    );
    shutdown(after).await;
}

#[tokio::test]
async fn releases_exactly_one_consume_across_independent_connections() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let first = fixture.process(clock.clone()).await;
    let second = fixture.process(clock.clone()).await;
    let third = fixture.process(clock).await;
    let request_id = first.create_request().await;
    let decision = first.approve(&request_id).await;
    let code = text(&decision, "code");
    let (a, b, c) = tokio::join!(
        first.consume(code),
        second.consume(code),
        third.consume(code)
    );
    let mut statuses = [a.status, b.status, c.status];
    statuses.sort();
    assert_eq!(statuses, [200, 409, 409]);
    shutdown(first).await;
    shutdown(second).await;
    shutdown(third).await;
}

#[tokio::test]
async fn reads_a_row_of_another_record_version_as_unreadable() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let clock = TestClock::new();
    let h = fixture.process(clock).await;
    let request_id = h.create_request().await;
    let pool = fixture.pool().await;
    sqlx::query(
        "UPDATE oaath_relay_authorization_request_v2 SET record_version = $2 WHERE request_id = $1",
    )
    .bind(&request_id)
    .bind("oaath.authorization-request-record/v1")
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    h.fetch(&request_id, OWNER_TOKEN)
        .await
        .failure(E::RecordUnreadable);
    shutdown(h).await;
}

#[tokio::test]
async fn refuses_to_create_the_schema_over_existing_objects() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let pool = fixture.pool().await;
    assert!(create_relay_schema(&pool).await.is_err());
    let version: String =
        sqlx::query_scalar("SELECT version FROM oaath_relay_schema_v5 WHERE schema_id = 'oaath'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(version, "oaath.relay-postgres-schema/v5");
    pool.close().await;
}

#[tokio::test]
async fn projects_an_unreachable_database_to_store_unavailable() {
    let Some(url) = database() else { return };
    let fixture = Fixture::create(url).await;
    let pool = fixture.pool().await;
    let store: Arc<dyn RelayStore> = Arc::new(PostgresRelayStore::borrowing(pool.clone()));
    let h = harness_on(store, TestClock::new(), |_| {});
    pool.close().await;
    h.send(post(
        "/authorization/requests",
        Some(CLIENT_TOKEN),
        Some(json!({
            "redirectUri": REDIRECT_URI,
            "codeChallenge": code_challenge(),
            "requestedScope": "{}",
        })),
    ))
    .await
    .failure(E::StoreUnavailable);
}
