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
    let url =
        std::env::var("AUTOMATION_TEST_DATABASE_URL").expect("owned PostgreSQL fixture required");
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
    sqlx::query("INSERT INTO automation_plans(id,app_id,account,creation_key,input_digest,terms,status,next_at,created_at,user_id,key_scope,recipe,fee_terms) VALUES($1,'app',$2,$1,'digest',$3,$4,$5,$5,'alice','user','dca.v1','{}')").bind(&t.plan_id).bind(&t.account).bind(serde_json::to_value(&t).unwrap()).bind(status).bind(start as i64).execute(pool).await.unwrap();
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
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_runs WHERE plan_id=$1")
        .bind(&active.plan_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    for t in [paused, cancelling, draft] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_runs WHERE plan_id=$1")
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
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_runs WHERE plan_id=$1")
        .bind(&t.plan_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    scheduler::admit(&pool, 88301).await.unwrap();
    let status: String =
        sqlx::query_scalar("SELECT status FROM automation_runs WHERE plan_id=$1 AND slot=1")
            .bind(&t.plan_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "skipped");
    scheduler::admit(&pool, t.end_at as i64).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM automation_plans WHERE id=$1")
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
    let input = json!({"recipe":"dca.v1","amount":"25","opportunities":30,"maxSlippageBps":50,"idempotencyKey":"customer-plan"});
    let session = call(
        &routes,
        "secret",
        "POST",
        "/v1/sessions",
        json!({"userId":"alice","account":t.account}),
    )
    .await;
    assert_eq!(session.0, StatusCode::OK);
    let token = format!("Bearer {}", session.1["token"].as_str().unwrap());
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
            .oneshot(request(&token, "https://app.example", &input)),
        routes
            .clone()
            .oneshot(request(&token, "https://app.example", &input))
    );
    assert!(r1.unwrap().status().is_success());
    assert!(r2.unwrap().status().is_success());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_plans")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let mut changed = input.clone();
    changed["opportunities"] = json!(31);
    assert_eq!(
        routes
            .oneshot(request(&token, "https://app.example", &changed))
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
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM automation_runs WHERE plan_id=$1 AND status='skipped'",
    )
    .bind(&t.plan_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 30);
    let state: String = sqlx::query_scalar("SELECT status FROM automation_plans WHERE id=$1")
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

async fn call(
    routes: &axum::Router,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = routes
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", "api.example")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 32768)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
#[tokio::test]
#[ignore = "owned PostgreSQL"]
async fn user_boundaries_and_signing_scope_are_server_owned() {
    let pool = database().await;
    let routes = http::router(app(pool.clone()));
    let (t, _) = vector();
    let mut tokens = vec![];
    for user in ["alice", "bob"] {
        let (status, session) = call(
            &routes,
            "secret",
            "POST",
            "/v1/sessions",
            json!({"userId":user,"account":t.account}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        tokens.push(session["token"].as_str().unwrap().to_string());
    }
    let input = json!({"recipe":"dca.v1","amount":"25","opportunities":30,"maxSlippageBps":50,"idempotencyKey":"a"});
    assert_eq!(
        call(&routes, "secret", "POST", "/v1/plans", input.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, plan) = call(&routes, &tokens[0], "POST", "/v1/plans", input.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(plan["keyScope"], "user");
    let path = format!("/v1/plans/{}", plan["id"].as_str().unwrap());
    for suffix in [
        "",
        "/runs",
        "/pause",
        "/resume",
        "/cancel",
        "/authorize",
        "/refresh",
    ] {
        let method = if suffix == "" || suffix == "/runs" {
            "GET"
        } else {
            "POST"
        };
        assert_eq!(
            call(
                &routes,
                &tokens[1],
                method,
                &format!("{path}{suffix}"),
                json!({})
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        call(&routes, &tokens[1], "GET", "/v1/plans", json!({}))
            .await
            .1["plans"],
        json!([])
    );
    assert_eq!(
        call(
            &routes,
            &tokens[0],
            "POST",
            "/v1/application",
            json!({"keyScope":"application"})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &routes,
            &tokens[0],
            "POST",
            "/v1/sessions",
            json!({"userId":"bob","account":t.account})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let mut injected = input.clone();
    injected["keyScope"] = json!("application");
    assert_eq!(
        call(&routes, &tokens[0], "POST", "/v1/plans", injected)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call(
            &routes,
            "secret",
            "POST",
            "/v1/application",
            json!({"keyScope":"application"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&routes, &tokens[0], "GET", &path, json!({})).await.1["keyScope"],
        "user"
    );
    let mut next = input;
    next["idempotencyKey"] = json!("b");
    assert_eq!(
        call(&routes, &tokens[0], "POST", "/v1/plans", next).await.1["keyScope"],
        "application"
    );
    sqlx::query("UPDATE automation_sessions SET expires_at=0")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(&routes, &tokens[0], "GET", &path, json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    pool.close().await;
}
