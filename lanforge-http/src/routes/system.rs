use axum::{Router, routing::get, extract::{State, Query}, Json};
use crate::server::AppState;
use lanforge_api::api::Response;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ContextDumpQuery {
    #[serde(default)]
    pub only_devices: bool,
    #[serde(default)]
    pub only_orphans: bool,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(handle_status))
        .route("/reload", axum::routing::post(handle_reload))
        .route("/shutdown", axum::routing::post(handle_shutdown))
        .route("/topology", get(handle_topology))
        .route("/context", get(handle_context_dump))
}

use crate::routes::create_client_ctx;

async fn handle_status(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_status().await)
}

async fn handle_reload(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_reload().await)
}

async fn handle_shutdown(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_shutdown().await)
}

async fn handle_topology(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_topology().await)
}

async fn handle_context_dump(
    State(state): State<AppState>,
    Query(params): Query<ContextDumpQuery>,
) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_context_dump(params.only_devices, params.only_orphans).await)
}
