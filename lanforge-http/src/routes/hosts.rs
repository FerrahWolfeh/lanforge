use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use lanforge_api::api::{HostConfigEntry, Response};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_list_hosts).post(handle_add_host))
        .route("/{mac}", delete(handle_remove_host))
        .route("/export", get(handle_export_hosts))
        .route("/import", post(handle_import_hosts))
}

async fn handle_list_hosts(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_hosts().await {
        Response::Hosts(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": res.hosts })),
        )
            .into_response(),
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

async fn handle_add_host(
    State(state): State<AppState>,
    Json(payload): Json<HostConfigEntry>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_host_add(payload).await {
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

async fn handle_remove_host(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_host_remove(mac).await {
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

async fn handle_export_hosts(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_hosts().await {
        Response::Hosts(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": res.hosts })),
        )
            .into_response(),
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

async fn handle_import_hosts(
    State(state): State<AppState>,
    Json(hosts): Json<Vec<HostConfigEntry>>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_host_import(hosts).await {
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
