use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use lanforge_api::api::HostConfigEntry;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_list_hosts).post(handle_add_host))
        .route(
            "/{mac}",
            delete(handle_remove_host).patch(handle_set_host),
        )
        .route("/export", get(handle_export_hosts))
        .route("/import", post(handle_import_hosts))
}

async fn handle_list_hosts(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_hosts().await, Hosts, res => serde_json::json!({ "data": res.hosts }))
}

async fn handle_add_host(
    State(state): State<AppState>,
    Json(payload): Json<HostConfigEntry>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_host_add(payload).await, Success => NoContent)
}

#[derive(serde::Deserialize)]
pub struct HostSetPayload {
    pub field: String,
    pub value: String,
}

async fn handle_set_host(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Json(payload): Json<HostSetPayload>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_host_set(mac, payload.field, payload.value).await, Success => NoContent)
}

async fn handle_remove_host(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_host_remove(mac).await, Success => NoContent)
}

async fn handle_export_hosts(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_hosts().await, Hosts, res => serde_json::json!({ "data": res.hosts }))
}

async fn handle_import_hosts(
    State(state): State<AppState>,
    Json(hosts): Json<Vec<HostConfigEntry>>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_host_import(hosts).await, Success => NoContent)
}
