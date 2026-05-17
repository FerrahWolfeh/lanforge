use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::{get, post},
};
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
    crate::http_response!(ctx.handle_dhcp_pools().await, DhcpPools)
}

async fn handle_leases(
    State(state): State<AppState>,
    Query(params): Query<LeasesQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_leases(params.count).await, Leases)
}

async fn handle_renew(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(payload): Json<LeaseActionRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_lease_renew(mac, payload.target).await, Success => NoContent)
}

async fn handle_release(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(payload): Json<LeaseActionRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_lease_release(mac, payload.target).await, Success => NoContent)
}
