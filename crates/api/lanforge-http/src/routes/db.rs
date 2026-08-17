use std::sync::atomic::Ordering;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};

use crate::routes::create_client_ctx;
use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vacuum", post(handle_vacuum))
        .route("/prune", post(handle_prune))
        .route("/log-clean", post(handle_log_clean))
        .route("/stats", get(handle_stats))
        .route("/", delete(handle_reset))
}

async fn handle_stats(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.ctx.db_metrics();
    let metrics_json = serde_json::json!({
        "last_flush_ts": metrics.last_flush_ts.load(Ordering::Relaxed),
        "flush_count": metrics.flush_count.load(Ordering::Relaxed),
        "devices_written": metrics.devices_written.load(Ordering::Relaxed),
        "last_error": metrics.last_error.load(Ordering::Relaxed),
    });
    (StatusCode::OK, Json(metrics_json)).into_response()
}

async fn handle_vacuum(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_db_vacuum().await, Success => NoContent)
}

async fn handle_prune(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_db_prune().await, Success => NoContent)
}

async fn handle_log_clean(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_db_log_clean().await, Success => NoContent)
}

async fn handle_reset(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let confirm = headers.get("x-confirm").and_then(|v| v.to_str().ok());
    if confirm != Some("wipe") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Missing or invalid X-Confirm header. Must be 'wipe'." })),
        )
            .into_response();
    }

    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_db_reset().await, Success => NoContent)
}
