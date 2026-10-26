use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_types::network::pppoe::PppoeConfig;

use crate::routes::create_client_ctx;
use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(handle_status))
        .route("/config", get(handle_get_config).post(handle_update_config))
        .route("/reconnect", post(handle_reconnect))
        .route("/disconnect", post(handle_disconnect))
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_pppoe_status().await, PppoeStatus)
}

async fn handle_get_config(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_pppoe_config().await, PppoeConfig)
}

async fn handle_update_config(
    State(state): State<AppState>,
    Json(config): Json<PppoeConfig>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_update_pppoe_config(config).await, Success)
}

async fn handle_reconnect(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_pppoe_reconnect().await, Success)
}

async fn handle_disconnect(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_pppoe_disconnect().await, Success)
}
