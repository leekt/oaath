use crate::http::{ApiError, App, Result, now};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

pub struct Principal {
    pub app_id: String,
    pub user_id: Option<String>,
    pub account: Option<String>,
}
fn token_hash(headers: &HeaderMap) -> Result<String> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() <= 512)
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        ))?;
    Ok(hex::encode(Sha256::digest(token.as_bytes())))
}
pub fn admin(app: &App, headers: &HeaderMap) -> Result<String> {
    let digest = token_hash(headers)?;
    app.apps
        .iter()
        .find(|(_, h)| h == &digest)
        .map(|(id, _)| id.clone())
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "application_credential_required",
        ))
}
pub async fn authenticate(app: &App, headers: &HeaderMap) -> Result<Principal> {
    let digest = token_hash(headers)?;
    if let Some((id, _)) = app.apps.iter().find(|(_, h)| h == &digest) {
        return Ok(Principal {
            app_id: id.clone(),
            user_id: None,
            account: None,
        });
    }
    let r=sqlx::query("SELECT app_id,user_id,account FROM automation_sessions WHERE token_hash=$1 AND expires_at>$2")
        .bind(digest).bind(now()).fetch_optional(&app.pool).await?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED,"session_expired_or_invalid"))?;
    // Removing an application credential also closes its sessions.
    let id: String = r.get("app_id");
    if !app.apps.iter().any(|(a, _)| a == &id) {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "application_unavailable",
        ));
    }
    Ok(Principal {
        app_id: id,
        user_id: Some(r.get("user_id")),
        account: Some(r.get("account")),
    })
}
pub async fn scope(app: &App, id: &str) -> Result<String> {
    Ok(
        sqlx::query_scalar("SELECT key_scope FROM automation_applications WHERE app_id=$1")
            .bind(id)
            .fetch_optional(&app.pool)
            .await?
            .unwrap_or("user".into()),
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    key_scope: String,
}
pub async fn configure(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Settings>,
) -> Result<Json<Value>> {
    let id = admin(&app, &h)?;
    if !["user", "application"].contains(&body.key_scope.as_str()) {
        return Err("key_scope_invalid".into());
    }
    sqlx::query("INSERT INTO automation_applications(app_id,key_scope) VALUES($1,$2) ON CONFLICT(app_id) DO UPDATE SET key_scope=EXCLUDED.key_scope")
        .bind(&id).bind(&body.key_scope).execute(&app.pool).await?;
    Ok(Json(json!({"keyScope":body.key_scope})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartSession {
    user_id: String,
    account: String,
}
/// Only the integrating application's authenticated backend can assert a customer identity.
pub async fn create(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<StartSession>,
) -> Result<Json<Value>> {
    let id = admin(&app, &h)?;
    if body.user_id.is_empty() || body.user_id.len() > 256 || body.user_id.trim() != body.user_id {
        return Err("user_id_invalid".into());
    }
    let account = crate::model::address(&body.account)?;
    let token = hex::encode(rand::random::<[u8; 32]>());
    let expires = now() + 3600;
    sqlx::query("INSERT INTO automation_sessions(token_hash,app_id,user_id,account,expires_at) VALUES($1,$2,$3,$4,$5)")
        .bind(hex::encode(Sha256::digest(token.as_bytes()))).bind(&id).bind(body.user_id).bind(&account).bind(expires)
        .execute(&app.pool).await?;
    Ok(Json(
        json!({"token":token,"expiresAt":expires,"account":account,"keyScope":scope(&app,&id).await?}),
    ))
}
