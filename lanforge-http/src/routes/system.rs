use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
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
        .route("/scan", post(handle_scan))
        .route("/reload", post(handle_reload))
        .route("/shutdown", post(handle_shutdown))
        .route("/topology", get(handle_topology))
        .route("/context", get(handle_context_dump))
}

use crate::routes::create_client_ctx;

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_status().await {
        Response::Status(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_scan(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_scan().await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_reload(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_reload().await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_shutdown(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_shutdown().await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_topology(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_topology().await {
        Response::Topology(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_context_dump(
    State(state): State<AppState>,
    Query(params): Query<ContextDumpQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx
        .handle_context_dump(params.only_devices, params.only_orphans)
        .await
    {
        Response::ContextDump(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}
