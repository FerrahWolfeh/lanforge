use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_types::network::ra::RaServerConfig;

use crate::routes::create_client_ctx;
use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(handle_status))
        .route(
            "/config",
            get(handle_get_config).post(handle_update_config),
        )
        .route("/trigger", post(handle_trigger))
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ra_status().await, RaStatus)
}

async fn handle_get_config(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ra_config().await, RaConfig)
}

async fn handle_update_config(
    State(state): State<AppState>,
    Json(config): Json<RaServerConfig>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_update_ra_config(config).await, Success)
}

async fn handle_trigger(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ra_trigger().await, Success)
}
