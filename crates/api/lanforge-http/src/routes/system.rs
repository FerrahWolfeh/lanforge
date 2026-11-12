use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{self, SET_COOKIE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use lanforge_api::api::{HttpDataResponse, Response as ApiResponse, SystemConfigExport};
use lanforge_api_dispatch::ClientContext;
use lanforge_types::system::{ServiceAction, SetupPayload};
use serde::Deserialize;

use crate::routes::auth::{REMEMBER_ME_TTL_SECS, issue_session};
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
        .route("/capabilities", get(handle_capabilities))
        .route("/setup-status", get(handle_setup_status))
        .route("/setup", post(handle_setup))
        .route("/service_banners", get(handle_service_banners))
        .route("/service/{id}/control", post(handle_service_control))
        .route("/service/{id}/stop-impact", get(handle_service_stop_impact))
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

async fn handle_capabilities(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    (
        StatusCode::OK,
        Json(HttpDataResponse {
            data: ctx.server_capabilities(),
        }),
    )
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
        return config_toml_download(&ctx);
    }
    crate::http_response!(ctx.handle_system_config_export().await, SystemConfig)
}

async fn handle_export_config_toml(State(state): State<AppState>) -> impl IntoResponse {
    config_toml_download(&create_client_ctx(&state))
}

/// The config file as a download; no file to read is a 404, not an invented one.
fn config_toml_download(ctx: &ClientContext) -> Response {
    match ctx.export_system_config_toml() {
        Ok(toml_str) => (
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"lanforge.toml\"",
                ),
            ],
            toml_str,
        )
            .into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e).into_response(),
    }
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

async fn handle_service_stop_impact(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_service_stop_impact(id).await, ServiceStopImpact)
}

async fn handle_setup_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_setup_status().await, SetupStatus)
}

async fn handle_setup(
    State(state): State<AppState>,
    Json(payload): Json<SetupPayload>,
) -> impl IntoResponse {
    // Fails closed: an unreadable flag or user table must not reopen first-run setup.
    let is_provisioned = match (state.db.is_provisioned(), state.db.count_users()) {
        (Ok(provisioned), Ok(users)) => provisioned || users > 0,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "persistence unavailable" })),
            )
                .into_response();
        }
    };
    if is_provisioned || state.ctx.is_recovery_mode() {
        return (
            StatusCode::FORBIDDEN,
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
        ApiResponse::Setup(mut setup_res) => {
            // Setup stores the name trimmed and lowercased.
            let token = match state
                .db
                .get_user_by_username(&username.trim().to_lowercase())
            {
                Ok(Some(admin)) => {
                    issue_session(&state, &admin, REMEMBER_ME_TTL_SECS).unwrap_or_default()
                }
                _ => String::new(),
            };
            setup_res.token.clone_from(&token);

            let cookie_header = format!(
                "session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={REMEMBER_ME_TTL_SECS}"
            );
            let mut headers = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&cookie_header) {
                headers.insert(SET_COOKIE, v);
            }

            (
                StatusCode::OK,
                headers,
                Json(HttpDataResponse { data: setup_res }),
            )
                .into_response()
        }
        ApiResponse::Error { error } => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Unexpected setup response" })),
        )
            .into_response(),
    }
}
