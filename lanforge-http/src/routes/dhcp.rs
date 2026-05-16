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
use lanforge_types::update::LeaseTarget;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct LeasesQuery {
    #[serde(default)]
    pub count: bool,
}

#[derive(Debug, Deserialize)]
pub struct LeaseActionRequest {
    pub target: Option<LeaseTarget>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/pools", get(handle_pools))
        .route("/leases", get(handle_leases))
        .route("/leases/{mac}/renew", post(handle_renew))
        .route("/leases/{mac}/release", post(handle_release))
}

async fn handle_pools(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dhcp_pools().await {
        Response::DhcpPools(res) => {
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

async fn handle_leases(
    State(state): State<AppState>,
    Query(params): Query<LeasesQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_leases(params.count).await {
        Response::Leases(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": res.leases })),
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

async fn handle_renew(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(payload): Json<LeaseActionRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_lease_renew(mac, payload.target).await {
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

async fn handle_release(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(payload): Json<LeaseActionRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_lease_release(mac, payload.target).await {
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
