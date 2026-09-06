use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::header,
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

#[derive(Debug, Deserialize)]
pub struct ConfigExportQuery {
    #[serde(default)]
    pub format: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(handle_status))
        .route("/setup-status", get(handle_setup_status))
        .route("/setup", post(handle_setup))
        .route("/service_banners", get(handle_service_banners))
        .route("/service/{id}/control", post(handle_service_control))
        .route("/reload", post(handle_reload))
        .route("/shutdown", post(handle_shutdown))
        .route("/context", get(handle_context_dump))
        .route(
            "/config",
            get(handle_export_config).post(handle_import_config),
        )
        .route("/config/toml", get(handle_export_config_toml))
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

async fn handle_export_config(
    State(state): State<AppState>,
    Query(params): Query<ConfigExportQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    if params.format.as_deref() == Some("toml") {
        let toml_str = ctx.export_system_config_toml().await;
        return (
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"lanforge.toml\"",
                ),
            ],
            toml_str,
        )
            .into_response();
    }
    crate::http_response!(ctx.handle_system_config_export().await, SystemConfig)
}

async fn handle_export_config_toml(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    let toml_str = ctx.export_system_config_toml().await;
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"lanforge.toml\"",
            ),
        ],
        toml_str,
    )
        .into_response()
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

async fn handle_setup_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_setup_status().await, SetupStatus)
}

async fn handle_setup(
    State(state): State<AppState>,
    Json(payload): Json<lanforge_types::system::SetupPayload>,
) -> impl IntoResponse {
    let is_provisioned = state.db.is_provisioned().unwrap_or(false)
        || (state.db.count_users().await.unwrap_or(0) > 0);
    if is_provisioned {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Forbidden: Lanforge has already completed first-run setup. This endpoint is permanently locked."
            })),
        )
            .into_response();
    }

    let ctx = create_client_ctx(&state);
    let username = payload.admin_username.clone();
    let res = ctx.handle_setup(payload).await;

    match res {
        lanforge_api::api::Response::Setup(mut setup_res) => {
            let token = state
                .auth
                .generate_token_with_ttl(&username, "admin", 2_592_000)
                .unwrap_or_default();
            setup_res.token.clone_from(&token);

            let cookie_header =
                format!("session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000");
            let mut headers = axum::http::HeaderMap::new();
            if let Ok(v) = axum::http::HeaderValue::from_str(&cookie_header) {
                headers.insert(axum::http::header::SET_COOKIE, v);
            }

            (
                axum::http::StatusCode::OK,
                headers,
                Json(lanforge_api::api::HttpDataResponse { data: setup_res }),
            )
                .into_response()
        }
        lanforge_api::api::Response::Error { error } => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Unexpected setup response" })),
        )
            .into_response(),
    }
}
