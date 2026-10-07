use crate::{
    http::{self, App, Config},
    model::Terms,
    scheduler,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;
fn vector() -> (Terms, Value) {
    let v: Value = serde_json::from_str(include_str!("../testdata/terms.json")).unwrap();
    (serde_json::from_value(v["terms"].clone()).unwrap(), v)
}
#[test]
fn protocol_vectors_match() {
    let (t, v) = vector();
    assert_eq!(t.commitment().unwrap(), v["commitment"]);
    assert_eq!(t.slot_digest(0).unwrap(), v["slots"][0]);
    assert_eq!(t.slot_digest(29).unwrap(), v["slots"][1]);
    let mut changed = t.clone();
    changed.max_slippage_bps += 1;
    assert_ne!(changed.commitment().unwrap(), t.commitment().unwrap());
    changed.version = "oaath.dca-terms/v2".into();
    assert!(changed.commitment().is_err());
}
async fn database() -> PgPool {
    let url = std::env::var("DCA_TEST_DATABASE_URL").expect("owned PostgreSQL fixture required");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("proof_{}", hex::encode(rand::random::<[u8; 8]>()));
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |c, _| {
            let q = format!("SET search_path TO {schema}");
            Box::pin(async move {
                sqlx::query(&q).execute(c).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}
async fn seed(pool: &PgPool, status: &str, start: u64) -> Terms {
    let (mut t, _) = vector();
    t.plan_id = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    t.start_at = start;
    t.end_at = start + 29 * 86400 + 900;
    sqlx::query("INSERT INTO dca_plans(id,app_id,account,creation_key,input_digest,terms,status,next_at,created_at) VALUES($1,'app',$2,$1,'digest',$3,$4,$5,$5)").bind(&t.plan_id).bind(&t.account).bind(serde_json::to_value(&t).unwrap()).bind(status).bind(start as i64).execute(pool).await.unwrap();
    t
}
#[tokio::test]
#[ignore = "owned PostgreSQL"]
async fn duplicate_ticks_and_closed_admission() {
    let pool = database().await;
    let active = seed(&pool, "active", 1000).await;
    let paused = seed(&pool, "paused", 1000).await;
    let cancelling = seed(&pool, "cancelling", 1000).await;
    let draft = seed(&pool, "draft", 1000).await;
    let (a, b) = tokio::join!(scheduler::admit(&pool, 1001), scheduler::admit(&pool, 1001));
    a.unwrap();
    b.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dca_runs WHERE plan_id=$1")
        .bind(&active.plan_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    for t in [paused, cancelling, draft] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM dca_runs WHERE plan_id=$1")
            .bind(t.plan_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }
    pool.close().await;
}
#[tokio::test]
#[ignore = "owned PostgreSQL"]
async fn missed_slots_skip_and_unresolved_blocks() {
    let pool = database().await;
    let t = seed(&pool, "active", 1000).await;
    scheduler::admit(&pool, 1001).await.unwrap();
    scheduler::admit(&pool, 87401).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dca_runs WHERE plan_id=$1")
        .bind(&t.plan_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    scheduler::admit(&pool, 88301).await.unwrap();
    let status: String =
        sqlx::query_scalar("SELECT status FROM dca_runs WHERE plan_id=$1 AND slot=1")
            .bind(&t.plan_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "skipped");
    scheduler::admit(&pool, t.end_at as i64).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM dca_plans WHERE id=$1")
        .bind(t.plan_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "expired");
    pool.close().await;
}
fn app(pool: PgPool) -> App {
    let (t, _) = vector();
    App {
        pool,
        config: Config {
            chain_id: 31337,
            sell_token: t.sell_token,
            buy_token: t.buy_token,
            router: t.router,
            pool_fee: t.pool_fee,
            sell_feed: t.sell_feed,
            buy_feed: t.buy_feed,
            factory: t.account,
            max_price_age_seconds: 3600,
            max_fee_per_gas: "1".into(),
            max_gas_cost: "1".into(),
            origin: "https://app.example".into(),
        },
        apps: Arc::new(vec![("app".into(), hex::encode(Sha256::digest(b"secret")))]),
        runtime: "http://127.0.0.1:1".into(),
        runtime_token: "internal".into(),
        client: reqwest::Client::new(),
        hosts: Arc::new(vec!["api.example".into()]),
    }
}
#[tokio::test]
#[ignore = "owned PostgreSQL"]
async fn api_auth_origin_and_idempotency() {
    let pool = database().await;
    let a = app(pool.clone());
    let routes = http::router(a);
    let (t, _) = vector();
    let input = json!({"account":t.account,"chainId":31337,"sell":{"token":t.sell_token,"amount":"25"},"buy":{"token":t.buy_token},"intervalSeconds":86400,"maxRuns":30,"maxSlippageBps":50,"idempotencyKey":"customer-plan"});
    let request = |token: &str, origin: &str, body: &Value| {
        Request::builder()
            .method("POST")
            .uri("/v1/plans")
            .header("host", "api.example")
            .header("origin", origin)
            .header("authorization", token)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    assert_eq!(
        routes
            .clone()
            .oneshot(request("", "https://app.example", &input))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        routes
            .clone()
            .oneshot(request("Bearer secret", "https://evil.example", &input))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let (r1, r2) = tokio::join!(
        routes
            .clone()
            .oneshot(request("Bearer secret", "https://app.example", &input)),
        routes
            .clone()
            .oneshot(request("Bearer secret", "https://app.example", &input))
    );
    assert!(r1.unwrap().status().is_success());
    assert!(r2.unwrap().status().is_success());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dca_plans")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let mut changed = input.clone();
    changed["maxRuns"] = json!(31);
    assert_eq!(
        routes
            .oneshot(request("Bearer secret", "https://app.example", &changed))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "owned PostgreSQL"]
async fn paused_opportunities_expire_without_admission() {
    let pool = database().await;
    let t = seed(&pool, "paused", 1000).await;
    scheduler::admit(&pool, t.end_at as i64).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dca_runs WHERE plan_id=$1 AND status='skipped'")
            .bind(&t.plan_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 30);
    let state: String = sqlx::query_scalar("SELECT status FROM dca_plans WHERE id=$1")
        .bind(&t.plan_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "expired");
    pool.close().await;
}

#[test]
fn malformed_plan_identity_is_rejected() {
    let (mut t, _) = vector();
    t.plan_id = "1".repeat(66);
    assert!(t.commitment().is_err());
}
