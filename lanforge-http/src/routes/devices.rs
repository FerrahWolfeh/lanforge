use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_api::api::Response;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DeviceListQuery {
    pub filter: Option<String>,
    pub sort: Option<String>,
    pub vendor: Option<String>,
    pub method: Option<String>,
    pub format: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_list_devices))
        .route("/{target}", get(handle_whois).delete(handle_purge))
        .route("/{target}/wol", post(handle_wake))
}

async fn handle_list_devices(
    State(state): State<AppState>,
    Query(params): Query<DeviceListQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx
        .handle_devices(
            params.filter,
            params.vendor,
            params.method.or(params.sort),
            params.format,
            params.limit,
            params.offset,
        )
        .await
    {
        Response::Devices(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": res.devices, "meta": res.meta })),
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

async fn handle_wake(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_wol(target).await {
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

async fn handle_whois(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_whois(target.clone()).await {
        Response::Whois(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => {
            let status = if error.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({ "error": error }))).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_purge(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_purge(target).await {
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
