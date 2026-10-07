mod http;
mod model;
mod recipes;
mod scheduler;
mod sessions;
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: http::Config = serde_json::from_str(&std::fs::read_to_string(std::env::var(
        "AUTOMATION_CONFIG",
    )?)?)?;
    let applications: Vec<(String, String)> =
        serde_json::from_str(&std::env::var("AUTOMATION_APPLICATION_HASHES")?)?;
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&std::env::var("AUTOMATION_DATABASE_URL")?)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    let app = http::App {
        pool,
        config,
        apps: Arc::new(applications),
        runtime: std::env::var("AUTOMATION_RUNTIME_URL")?,
        runtime_token: std::env::var("AUTOMATION_RUNTIME_TOKEN")?,
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
        hosts: Arc::new(
            std::env::var("AUTOMATION_ALLOWED_HOSTS")?
                .split(',')
                .map(str::to_owned)
                .collect(),
        ),
    };
    let scheduler = app.clone();
    let scheduler_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if http::tick(&scheduler).await.is_err() {
                eprintln!("scheduler_storage_unavailable");
            }
        }
    });
    let bind = std::env::var("AUTOMATION_BIND").unwrap_or("127.0.0.1:4317".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("Automation API listening on {bind}");
    axum::serve(listener, http::router(app.clone()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    scheduler_task.abort();
    app.pool.close().await;
    Ok(())
}

#[cfg(test)]
mod tests;
