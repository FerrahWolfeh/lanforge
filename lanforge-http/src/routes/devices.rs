use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Router,
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::{get, post},
};
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
    crate::http_response!(
        ctx.handle_devices(
            params.filter,
            params.vendor,
            params.method.or(params.sort),
            params.format,
            params.limit,
            params.offset,
        )
        .await,
        Devices,
        res => serde_json::json!({ "data": res.devices, "meta": res.meta })
    )
}

async fn handle_wake(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_wol(target).await, Success => NoContent)
}

async fn handle_whois(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_whois(target.clone()).await, Whois, res => serde_json::json!({ "data": res }))
}

async fn handle_purge(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_purge(target).await, Success => NoContent)
}
