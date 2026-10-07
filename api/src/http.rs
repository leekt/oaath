use crate::{
    model::{self, Create, Terms},
    scheduler,
};
use axum::{
    Json, Router,
    extract::Request,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::sync::Arc;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub chain_id: u64,
    pub sell_token: String,
    pub buy_token: String,
    pub router: String,
    pub pool_fee: u32,
    pub sell_feed: String,
    pub buy_feed: String,
    pub factory: String,
    pub max_price_age_seconds: u32,
    pub max_fee_per_gas: String,
    pub max_gas_cost: String,
    pub origin: String,
}
#[derive(Clone)]
pub struct App {
    pub pool: PgPool,
    pub config: Config,
    pub apps: Arc<Vec<(String, String)>>,
    pub runtime: String,
    pub runtime_token: String,
    pub client: reqwest::Client,
    pub hosts: Arc<Vec<String>>,
}
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":{"code":self.1}}))).into_response()
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
    }
}
impl From<&'static str> for ApiError {
    fn from(s: &'static str) -> Self {
        Self(StatusCode::UNPROCESSABLE_ENTITY, s)
    }
}
pub type Result<T> = std::result::Result<T, ApiError>;
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn app_id(app: &App, headers: &HeaderMap) -> Result<String> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        ))?;
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    app.apps
        .iter()
        .find(|(_, hash)| hash == &digest)
        .map(|(id, _)| id.clone())
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        ))
}
async fn guard(State(app): State<App>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !app.hosts.iter().any(|h| h == host) {
        return ApiError(StatusCode::MISDIRECTED_REQUEST, "host_denied").into_response();
    }
    if let Some(origin) = req.headers().get("origin")
        && origin.to_str().ok() != Some(app.config.origin.as_str())
    {
        return ApiError(StatusCode::FORBIDDEN, "origin_denied").into_response();
    }
    let cors = req.headers().contains_key("origin");
    let mut response = if req.method() == axum::http::Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    if cors {
        response.headers_mut().insert(
            "access-control-allow-origin",
            app.config.origin.parse().unwrap(),
        );
        response
            .headers_mut()
            .insert("vary", "origin".parse().unwrap());
        response.headers_mut().insert(
            "access-control-allow-methods",
            "GET, POST, OPTIONS".parse().unwrap(),
        );
        response.headers_mut().insert(
            "access-control-allow-headers",
            "authorization, content-type".parse().unwrap(),
        );
    }

    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}
pub fn router(app: App) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"status":"ok","version":"dca.api/v1"})) }),
        )
        .route("/v1/config", get(config))
        .route("/v1/plans", post(create).get(list))
        .route("/v1/plans/{id}", get(status))
        .route("/v1/plans/{id}/runs", get(history))
        .route("/v1/plans/{id}/authorize", post(authorize))
        .route("/v1/plans/{id}/approve", post(approve))
        .route("/v1/plans/{id}/pause", post(pause))
        .route("/v1/plans/{id}/resume", post(resume))
        .route("/v1/plans/{id}/cancel", post(cancel))
        .route("/v1/plans/{id}/refresh", post(refresh))
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}
async fn config(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    app_id(&a, &h)?;
    Ok(Json(
        json!({"chainId":a.config.chain_id,"sell":{"token":a.config.sell_token,"symbol":"USDC","decimals":6},"buy":{"token":a.config.buy_token,"symbol":"WETH","decimals":18},"intervalSeconds":86400,"graceSeconds":900,"serviceFee":"0","maxFeePerGas":a.config.max_fee_per_gas,"maxGasCost":a.config.max_gas_cost,"factory":a.config.factory}),
    ))
}
async fn own(a: &App, h: &HeaderMap, id: &str) -> Result<Value> {
    let app = app_id(a, h)?;
    let row = sqlx::query("SELECT to_jsonb(p) AS value FROM dca_plans p WHERE id=$1 AND app_id=$2")
        .bind(id)
        .bind(app)
        .fetch_optional(&a.pool)
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "plan_not_found"))?;
    Ok(row.get("value"))
}
async fn bridge(a: &App, action: &str, id: &str, body: Value) -> Result<Value> {
    let r = a
        .client
        .post(format!("{}/{}", a.runtime, action))
        .bearer_auth(&a.runtime_token)
        .json(&json!({"planId":id,"input":body}))
        .send()
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable"))?;
    let code = r.status();
    let v = r
        .json::<Value>()
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "runtime_unreadable"))?;
    if !code.is_success() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "runtime_action_pending_or_rejected",
        ));
    }
    Ok(v)
}
async fn create(
    State(a): State<App>,
    h: HeaderMap,
    Json(c): Json<Create>,
) -> Result<(StatusCode, Json<Value>)> {
    let app = app_id(&a, &h)?;
    let account = model::address(&c.account)?;
    if c.idempotency_key.is_empty()
        || c.idempotency_key.len() > 128
        || c.idempotency_key.trim() != c.idempotency_key
        || c.chain_id != a.config.chain_id
        || model::address(&c.sell.token)? != a.config.sell_token
        || model::address(&c.buy.token)? != a.config.buy_token
        || c.buy.amount.is_some()
        || c.interval_seconds != 86400
        || c.max_runs == 0
        || c.max_runs > 365
        || c.max_slippage_bps > 1000
    {
        return Err("plan_invalid".into());
    }
    let amount = model::base_units(c.sell.amount.as_deref().ok_or("amount_required")?)?;
    let canonical = json!({"account":account,"chainId":c.chain_id,"amountIn":amount,"maxRuns":c.max_runs,"maxSlippageBps":c.max_slippage_bps,"startAt":c.start_at,"profile":serde_json::json!([&a.config.sell_token,&a.config.buy_token,&a.config.router,a.config.pool_fee,&a.config.sell_feed,&a.config.buy_feed,a.config.max_price_age_seconds,&a.config.max_fee_per_gas,&a.config.max_gas_cost])});
    let digest = model::hash(canonical.to_string().as_bytes());
    let existing = sqlx::query(
        "SELECT id,input_digest FROM dca_plans WHERE app_id=$1 AND account=$2 AND creation_key=$3",
    )
    .bind(&app)
    .bind(&account)
    .bind(&c.idempotency_key)
    .fetch_optional(&a.pool)
    .await?;
    if let Some(row) = existing {
        if row.get::<String, _>("input_digest") != digest {
            return Err(ApiError(StatusCode::CONFLICT, "idempotency_conflict"));
        }
        return Ok((
            StatusCode::OK,
            Json(project(&a, &row.get::<String, _>("id")).await?),
        ));
    }
    let start = c.start_at.unwrap_or((now() + 300) as u64);
    if start < now() as u64 || start > now() as u64 + 31_536_000 {
        return Err("start_invalid".into());
    }
    let id = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    let terms = Terms {
        version: model::VERSION.into(),
        plan_id: id.clone(),
        account: account.clone(),
        chain_id: c.chain_id,
        sell_token: a.config.sell_token.clone(),
        buy_token: a.config.buy_token.clone(),
        amount_in: amount.clone(),
        total_input_cap: (amount.parse::<BigUint>().unwrap() * c.max_runs).to_string(),
        start_at: start,
        interval_seconds: 86400,
        grace_seconds: 900,
        max_runs: c.max_runs,
        end_at: start + u64::from(c.max_runs - 1) * 86400 + 900,
        recipient: account.clone(),
        router: a.config.router.clone(),
        pool_fee: a.config.pool_fee,
        sell_feed: a.config.sell_feed.clone(),
        buy_feed: a.config.buy_feed.clone(),
        max_price_age_seconds: a.config.max_price_age_seconds,
        max_slippage_bps: c.max_slippage_bps,
    };
    terms.validate()?;
    let inserted=sqlx::query("INSERT INTO dca_plans(id,app_id,account,creation_key,input_digest,terms,status,next_at,created_at,fee_terms) VALUES($1,$2,$3,$4,$5,$6,'draft',$7,$8,$9) ON CONFLICT(app_id,account,creation_key) DO NOTHING RETURNING id").bind(&id).bind(&app).bind(&account).bind(&c.idempotency_key).bind(&digest).bind(serde_json::to_value(&terms).unwrap()).bind(start as i64).bind(now()).bind(json!({"serviceFee":"0","payer":"account","maxFeePerGas":a.config.max_fee_per_gas,"maxGasCost":a.config.max_gas_cost})).fetch_optional(&a.pool).await?;
    if inserted.is_none() {
        let row=sqlx::query("SELECT id,input_digest FROM dca_plans WHERE app_id=$1 AND account=$2 AND creation_key=$3").bind(app).bind(account).bind(c.idempotency_key).fetch_one(&a.pool).await?;
        if row.get::<String, _>("input_digest") != digest {
            return Err(ApiError(StatusCode::CONFLICT, "idempotency_conflict"));
        }
        return Ok((
            StatusCode::OK,
            Json(project(&a, &row.get::<String, _>("id")).await?),
        ));
    }
    Ok((StatusCode::CREATED, Json(project(&a, &id).await?)))
}
const PROJECTION: &str = "SELECT to_jsonb(p) AS value,COALESCE((SELECT jsonb_object_agg(status,n) FROM (SELECT status,count(*)::integer AS n FROM dca_runs WHERE plan_id=p.id GROUP BY status) counts),'{}'::jsonb) AS progress FROM dca_plans p";
fn projection(_a: &App, r: sqlx::postgres::PgRow) -> Value {
    let p: Value = r.get("value");
    let counts: Value = r.get("progress");
    let mut progress =
        json!({"succeeded":0,"failed":0,"skipped":0,"reserved":0,"observing":0,"unresolved":0});
    for (k, v) in counts.as_object().unwrap() {
        progress[k] = v.clone();
    }
    json!({"id":p["id"],"status":p["status"],"revision":p["revision"],"terms":p["terms"],"executor":p["executor"],"signer":p["signer"],"commitment":p["commitment"],"progress":progress,"nextSlot":p["next_slot"],"nextAt":p["next_at"],"setup":p["setup"],"cancellation":p["cancellation"],"diagnostic":p["diagnostic"],"fees":p["fee_terms"],"asOf":now()})
}
pub async fn project(a: &App, id: &str) -> Result<Value> {
    let r = sqlx::query(&format!("{PROJECTION} WHERE id=$1"))
        .bind(id)
        .fetch_one(&a.pool)
        .await?;
    Ok(projection(a, r))
}
async fn status(State(a): State<App>, h: HeaderMap, Path(id): Path<String>) -> Result<Json<Value>> {
    own(&a, &h, &id).await?;
    Ok(Json(project(&a, &id).await?))
}
#[derive(Deserialize)]
struct Page {
    after: Option<i32>,
    limit: Option<i64>,
}
async fn history(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<Page>,
) -> Result<Json<Value>> {
    own(&a, &h, &id).await?;
    let rows=sqlx::query("SELECT to_jsonb(r) - 'generation' - 'lease_until' AS value FROM dca_runs r WHERE plan_id=$1 AND slot>$2 ORDER BY slot LIMIT $3").bind(id).bind(q.after.unwrap_or(-1)).bind(q.limit.unwrap_or(50).clamp(1,100)).fetch_all(&a.pool).await?;
    Ok(Json(
        json!({"runs":rows.iter().map(|r|r.get::<Value,_>("value")).collect::<Vec<_>>() }),
    ))
}
async fn list(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let app = app_id(&a, &h)?;
    let rows = sqlx::query(&format!(
        "{PROJECTION} WHERE app_id=$1 ORDER BY created_at DESC,id LIMIT 100"
    ))
    .bind(app)
    .fetch_all(&a.pool)
    .await?;
    Ok(Json(
        json!({"plans":rows.into_iter().map(|r|projection(&a,r)).collect::<Vec<_>>()}),
    ))
}
async fn authorize(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let p = own(&a, &h, &id).await?;
    if !matches!(
        p["status"].as_str(),
        Some("draft" | "awaiting_consent" | "authorized")
    ) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "authorization_state_conflict",
        ));
    }
    let mut result = bridge(&a, "authorize", &id, json!({})).await?;
    result["plan"] = project(&a, &id).await?;
    Ok(Json(result))
}
async fn approve(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>> {
    own(&a, &h, &id).await?;
    let mut result = bridge(&a, "approve", &id, body).await?;
    result["plan"] = project(&a, &id).await?;
    Ok(Json(result))
}
async fn pause(State(a): State<App>, h: HeaderMap, Path(id): Path<String>) -> Result<Json<Value>> {
    own(&a, &h, &id).await?;
    let n = sqlx::query(
        "UPDATE dca_plans SET status='paused',revision=revision+1 WHERE id=$1 AND status='active'",
    )
    .bind(&id)
    .execute(&a.pool)
    .await?
    .rows_affected();
    if n == 0 && project(&a, &id).await?["status"] != "paused" {
        return Err(ApiError(StatusCode::CONFLICT, "plan_not_active"));
    }
    Ok(Json(project(&a, &id).await?))
}
async fn resume(State(a): State<App>, h: HeaderMap, Path(id): Path<String>) -> Result<Json<Value>> {
    own(&a, &h, &id).await?;
    bridge(&a, "resume", &id, json!({})).await?;
    Ok(Json(project(&a, &id).await?))
}
async fn cancel(State(a): State<App>, h: HeaderMap, Path(id): Path<String>) -> Result<Json<Value>> {
    own(&a, &h, &id).await?;
    sqlx::query("UPDATE dca_plans SET status='cancelling',revision=revision+1 WHERE id=$1 AND status IN ('draft','awaiting_consent','authorized','active','paused','completed','expired')").bind(&id).execute(&a.pool).await?;
    let _ = bridge(&a, "cancel", &id, json!({})).await;
    Ok(Json(project(&a, &id).await?))
}
async fn refresh(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Value>)> {
    own(&a, &h, &id).await?;
    sqlx::query("UPDATE dca_runs SET next_observe_at=LEAST(next_observe_at,$2) WHERE plan_id=$1 AND status IN ('observing','unresolved') AND next_observe_at>$2+10").bind(&id).bind(now()+10).execute(&a.pool).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"status":"queued","planId":id})),
    ))
}
pub async fn tick(a: &App) -> Result<()> {
    scheduler::admit(&a.pool, now()).await?;
    Ok(())
}
