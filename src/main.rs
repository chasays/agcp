use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use agcp_mvp::api::{build_router, AppState};
use agcp_mvp::crypto::{signing_key_from_b64, signing_key_to_b64};
use agcp_mvp::gateway::ToolGateway;
use agcp_mvp::governor::Governor;
use agcp_mvp::ledger::AuditLedger;
use agcp_mvp::policy::PolicyEngine;
use agcp_mvp::token::TokenService;
use axum::serve;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("data")?;

    let policy = PolicyEngine::from_file("config/policy.devops.toml")?;
    let signing_key = load_or_create_signing_key("data/policy_signing_key.b64")?;

    let token_service = TokenService::new("policy-engine".to_string(), signing_key);
    let gateway = ToolGateway::new(token_service.clone());
    let governor = Governor::new();
    let ledger = AuditLedger::new("data/audit.wal")?;

    let state = Arc::new(AppState::new(policy, governor, token_service, gateway, ledger));
    let app = build_router(state);

    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let listener = TcpListener::bind(addr).await?;

    println!("AGCP MVP listening on http://{addr}");
    serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn load_or_create_signing_key(path: impl AsRef<Path>) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let path = path.as_ref();

    if path.exists() {
        let b64 = fs::read_to_string(path)?;
        let key = signing_key_from_b64(b64.trim())?;
        return Ok(key);
    }

    let key = SigningKey::generate(&mut OsRng);
    fs::write(path, format!("{}\n", signing_key_to_b64(&key)))?;
    Ok(key)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    println!("shutdown signal received");
}
