use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_types::network::firewall::FirewallConfig;

use crate::routes::create_client_ctx;
use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(handle_status))
        .route(
            "/config",
            get(handle_get_config).post(handle_update_config),
        )
        .route("/reload", post(handle_reload))
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
