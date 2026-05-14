use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use lanforge_api::api::Response;
use lanforge_core::types::LeaseTarget;
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

async fn handle_pools(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_dhcp_pools().await)
}

async fn handle_leases(
    State(state): State<AppState>,
    Query(params): Query<LeasesQuery>,
) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_leases(params.count).await)
}

async fn handle_renew(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(payload): Json<LeaseActionRequest>,
) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_lease_renew(mac, payload.target).await)
}

async fn handle_release(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(payload): Json<LeaseActionRequest>,
) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_lease_release(mac, payload.target).await)
}
