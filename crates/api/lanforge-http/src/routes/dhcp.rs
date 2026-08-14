use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
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

#[derive(Debug, Deserialize)]
pub struct UpdateDhcpPoolsConfigRequest {
    pub v4_pools: Vec<Dhcpv4Pool>,
    pub v6_pools: Vec<Dhcpv6Pool>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/pools", get(handle_pools))
        .route(
            "/pools/config",
            get(handle_get_pools_config).put(handle_update_pools_config),
        )
        .route(
            "/options",
            get(handle_get_options).put(handle_update_options),
        )
        .route("/leases", get(handle_leases))
        .route("/leases/{mac}/renew", post(handle_renew))
        .route("/leases/{mac}/release", post(handle_release))
}

async fn handle_pools(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dhcp_pools().await, DhcpPools)
}

async fn handle_get_pools_config(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_get_dhcp_pools_config().await, DhcpPoolsConfig)
}

async fn handle_update_pools_config(
    State(state): State<AppState>,
    Json(payload): Json<UpdateDhcpPoolsConfigRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_update_dhcp_pools_config(payload.v4_pools, payload.v6_pools).await, Success => NoContent)
}

async fn handle_get_options(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_get_dhcp_options().await, DhcpOptions)
}

async fn handle_update_options(
    State(state): State<AppState>,
    Json(payload): Json<DhcpOptionsConfig>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_update_dhcp_options(payload).await, Success => NoContent)
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
    Path(mac): Path<lanforge_types::identifiers::MacAddr>,
    Json(payload): Json<LeaseActionRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_lease_renew(mac, payload.target).await, Success => NoContent)
}

async fn handle_release(
    State(state): State<AppState>,
    Path(mac): Path<lanforge_types::identifiers::MacAddr>,
    Json(payload): Json<LeaseActionRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_lease_release(mac, payload.target).await, Success => NoContent)
}
