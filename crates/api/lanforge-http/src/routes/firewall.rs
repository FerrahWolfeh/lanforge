use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_types::network::firewall::{FirewallCommitRequest, FirewallConfig};
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Deserialize)]
pub struct TxPayload {
    pub tx_id: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(handle_status))
        .route("/config", get(handle_get_config).post(handle_update_config))
        .route("/reload", post(handle_reload))
        .route("/propose", post(handle_propose))
        .route("/commit", post(handle_commit))
        .route("/confirm", post(handle_confirm))
        .route("/abort", post(handle_abort))
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_firewall_status().await, FirewallStatus)
}

async fn handle_get_config(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_firewall_config().await, FirewallConfig)
}

async fn handle_update_config(
    State(state): State<AppState>,
    Json(config): Json<FirewallConfig>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_update_firewall_config(config).await, Success)
}

async fn handle_reload(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_firewall_reload().await, Success)
}

async fn handle_propose(
    State(state): State<AppState>,
    Json(candidate): Json<FirewallConfig>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_firewall_propose(candidate).await,
        FirewallValidation
    )
}

async fn handle_commit(
    State(state): State<AppState>,
    Json(req): Json<FirewallCommitRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_firewall_commit(req).await, FirewallCommit)
}

async fn handle_confirm(
    State(state): State<AppState>,
    Json(payload): Json<TxPayload>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_firewall_confirm(payload.tx_id).await, Success)
}

async fn handle_abort(
    State(state): State<AppState>,
    Json(payload): Json<TxPayload>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_firewall_abort(payload.tx_id).await, Success)
}
