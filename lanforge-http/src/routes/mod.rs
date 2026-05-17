pub mod auth;
pub mod db;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod events;
pub mod hosts;
pub mod system;

use crate::server::AppState;
use axum::Router;
use lanforge_api_dispatch::ClientContext;

pub fn router() -> Router<AppState> {
    let v1 = Router::new()
        .merge(system::router())
        .nest("/auth", auth::router())
        .nest("/devices", devices::router())
        .nest("/dhcp", dhcp::router())
        .nest("/dns", dns::router())
        .nest("/db", db::router())
        .nest("/events", events::router())
        .nest("/hosts", hosts::router());

    Router::new().nest("/v1", v1)
}

#[must_use]
pub fn create_client_ctx(state: &AppState) -> ClientContext {
    ClientContext {
        current_gua: None,
        uptime_secs: state.start_time.elapsed().as_secs(),
        last_scan_secs_ago: state.ctx.last_scan_secs_ago(),
        ctx: state.ctx.clone(),
        db: state.db.clone(),
        log_db: state.log_db.clone(),
        active_clients: state.ctx.active_clients(),
    }
}

#[macro_export]
macro_rules! http_response {
    // 1. Success => 204 No Content
    ($expr:expr, Success => NoContent) => {
        match $expr {
            lanforge_api::api::Response::Success(_) => {
                axum::http::StatusCode::NO_CONTENT.into_response()
            }
            lanforge_api::api::Response::Error { error } => {
                let status = if error.contains("not found") {
                    axum::http::StatusCode::NOT_FOUND
                } else {
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                };
                (
                    status,
                    axum::Json(lanforge_api::api::HttpErrorResponse { error }),
                )
                    .into_response()
            }
            _ => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(lanforge_api::api::HttpErrorResponse {
                    error: "Invalid response type".into(),
                }),
            )
                .into_response(),
        }
    };
    // 2. Standard wrapper for any variant (e.g. Status)
    ($expr:expr, $variant:ident) => {
        match $expr {
            lanforge_api::api::Response::$variant(res) => (
                axum::http::StatusCode::OK,
                axum::Json(lanforge_api::api::HttpDataResponse { data: res }),
            )
                .into_response(),
            lanforge_api::api::Response::Error { error } => {
                let status = if error.contains("not found") {
                    axum::http::StatusCode::NOT_FOUND
                } else {
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                };
                (
                    status,
                    axum::Json(lanforge_api::api::HttpErrorResponse { error }),
                )
                    .into_response()
            }
            _ => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(lanforge_api::api::HttpErrorResponse {
                    error: "Invalid response type".into(),
                }),
            )
                .into_response(),
        }
    };
    // 3. Paginated wrapper (e.g. Devices, res => res.devices, res.meta)
    ($expr:expr, $variant:ident, $res:ident => $data:expr, $meta:expr) => {
        match $expr {
            lanforge_api::api::Response::$variant($res) => (
                axum::http::StatusCode::OK,
                axum::Json(lanforge_api::api::HttpPaginatedResponse {
                    data: $data,
                    meta: $meta,
                }),
            )
                .into_response(),
            lanforge_api::api::Response::Error { error } => {
                let status = if error.contains("not found") {
                    axum::http::StatusCode::NOT_FOUND
                } else {
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                };
                (
                    status,
                    axum::Json(lanforge_api::api::HttpErrorResponse { error }),
                )
                    .into_response()
            }
            _ => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(lanforge_api::api::HttpErrorResponse {
                    error: "Invalid response type".into(),
                }),
            )
                .into_response(),
        }
    };
}
