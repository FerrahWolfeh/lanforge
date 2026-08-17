use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_api::api::SystemConfigExport;
use lanforge_types::system::ServiceAction;
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct ContextDumpQuery {
    #[serde(default)]
    pub only_devices: bool,
    #[serde(default)]
    pub only_orphans: bool,
}

#[derive(Debug, Deserialize)]
pub struct ServiceControlPayload {
    pub action: ServiceAction,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(handle_status))
        .route("/service_banners", get(handle_service_banners))
        .route("/service/{id}/control", post(handle_service_control))
        .route("/reload", post(handle_reload))
        .route("/shutdown", post(handle_shutdown))
        .route("/context", get(handle_context_dump))
        .route(
            "/config",
            get(handle_export_config).post(handle_import_config),
        )
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_status().await, Status)
}

async fn handle_service_banners(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_service_banners().await, ServiceBanners)
}

async fn handle_reload(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_reload().await, Success => NoContent)
}

async fn handle_shutdown(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_shutdown().await, Success => NoContent)
}

async fn handle_context_dump(
    State(state): State<AppState>,
    Query(params): Query<ContextDumpQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_context_dump(params.only_devices, params.only_orphans)
            .await,
        ContextDump
    )
}

async fn handle_export_config(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_system_config_export().await, SystemConfig)
}

async fn handle_import_config(
    State(state): State<AppState>,
    Json(config): Json<SystemConfigExport>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_system_config_import(config).await,
        SystemConfigImport
    )
}

async fn handle_service_control(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<ServiceControlPayload>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_service_control(id, payload.action).await,
        Success => NoContent
    )
}
