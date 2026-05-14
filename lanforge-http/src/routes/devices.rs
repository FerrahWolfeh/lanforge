use axum::{Router, routing::{get, post, delete}, extract::{State, Query, Path}, Json};
use crate::server::AppState;
use crate::routes::create_client_ctx;
use lanforge_api::api::Response;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DeviceListQuery {
    pub filter: Option<String>,
    pub vendor: Option<String>,
    pub method: Option<String>,
    pub format: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_list_devices))
        .route("/:mac/wake", post(handle_wake))
        .route("/:mac/whois", get(handle_whois))
        .route("/:mac", delete(handle_purge))
}

async fn handle_list_devices(
    State(state): State<AppState>,
    Query(params): Query<DeviceListQuery>,
) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_devices(params.filter, params.vendor, params.method, params.format).await)
}

async fn handle_wake(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_wol(mac).await)
}

async fn handle_whois(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_whois(mac).await)
}

async fn handle_purge(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_purge(mac).await)
}
