use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, post},
};
use lanforge_api::api::Response;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vacuum", post(handle_vacuum))
        .route("/prune", post(handle_prune))
        .route("/log-clean", post(handle_log_clean))
        .route("/", delete(handle_reset))
}

async fn handle_vacuum(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_db_vacuum().await {
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

async fn handle_prune(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_db_prune().await {
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

async fn handle_log_clean(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_db_log_clean().await {
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
    match ctx.handle_db_reset().await {
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
