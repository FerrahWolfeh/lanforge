pub mod auth;
pub mod db;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod events;
pub mod firewall;
pub mod hosts;
pub mod pppoe;
pub mod ra;
pub mod system;
pub mod traffic;
pub mod users;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response as AxumResponse},
    routing::post,
};
use lanforge_api::api::{HttpErrorResponse, Response};
use lanforge_api_dispatch::ClientContext;

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    let v1 = Router::new()
        .merge(system::router())
        .nest("/system", system::router())
        .nest("/auth", auth::router())
        .nest("/users", users::router())
        .nest("/devices", devices::router())
        .nest("/dhcp", dhcp::router())
        .nest("/dns", dns::router())
        .nest("/db", db::router())
        .nest("/events", events::router())
        .nest("/firewall", firewall::router())
        .nest("/hosts", hosts::router())
        .nest("/pppoe", pppoe::router())
        .nest("/ra", ra::router())
        .nest("/traffic", traffic::router());

    Router::new()
        .nest("/v1", v1)
        .route("/auth/login", post(auth::handle_login))
}

#[must_use]
pub fn create_client_ctx(state: &AppState) -> ClientContext {
    ClientContext {
        current_gua: None,
        uptime_secs: state.start_time.elapsed().as_secs(),
        ctx: state.ctx.clone(),
        active_clients: state.ctx.active_clients(),
    }
}

/// The HTTP reply for a handler's failure `response`: 400 for a refusal, 404 for a missing item,
/// a generic error by [`response_error_to_http`]; any other variant is not a failure here.
#[must_use]
pub fn failure_to_http(response: Response) -> AxumResponse {
    match response {
        Response::Rejected { error } => {
            (StatusCode::BAD_REQUEST, Json(HttpErrorResponse { error })).into_response()
        }
        Response::NotFound { error } => {
            (StatusCode::NOT_FOUND, Json(HttpErrorResponse { error })).into_response()
        }
        Response::Error { error } => response_error_to_http(error),
        _ => invalid_response_to_http(),
    }
}

#[must_use]
pub fn response_error_to_http(error: String) -> AxumResponse {
    let status = if error.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, Json(HttpErrorResponse { error })).into_response()
}

#[must_use]
pub fn invalid_response_to_http() -> AxumResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(HttpErrorResponse {
            error: "Invalid response type".into(),
        }),
    )
        .into_response()
}

#[macro_export]
macro_rules! http_response {
    // 1. Success => 204 No Content
    ($expr:expr, Success => NoContent) => {
        match $expr {
            lanforge_api::api::Response::Success(_) => {
                axum::http::StatusCode::NO_CONTENT.into_response()
            }
            other => $crate::routes::failure_to_http(other),
        }
    };
    // 2. Standard wrapper for any variant (e.g. Status, Success)
    ($expr:expr, $variant:ident) => {
        match $expr {
            lanforge_api::api::Response::$variant(res) => (
                axum::http::StatusCode::OK,
                axum::Json(lanforge_api::api::HttpWrappedResponse::wrap(res)),
            )
                .into_response(),
            other => $crate::routes::failure_to_http(other),
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
            other => $crate::routes::failure_to_http(other),
        }
    };
}
