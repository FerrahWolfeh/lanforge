use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_api::api::{HttpErrorResponse, HttpPaginatedResponse, Response, group_devices};
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
    pub grouped: Option<bool>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_list_devices))
        .route("/transient", get(handle_transient_devices))
        .route("/{target}", get(handle_whois).delete(handle_purge))
        .route("/{target}/wol", post(handle_wake))
}

async fn handle_list_devices(
    State(state): State<AppState>,
    Query(params): Query<DeviceListQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    let res = ctx
        .handle_devices(
            params.filter,
            params.vendor,
            params.method.or(params.sort),
            params.format,
            params.limit,
            params.offset,
        )
        .await;

    match res {
        Response::Devices(devices_resp) => {
            if params.grouped.unwrap_or(false) {
                let grouped_list = group_devices(&devices_resp.devices);
                (
                    StatusCode::OK,
                    axum::Json(HttpPaginatedResponse {
                        data: grouped_list,
                        meta: devices_resp.meta,
                    }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    axum::Json(HttpPaginatedResponse {
                        data: devices_resp.devices,
                        meta: devices_resp.meta,
                    }),
                )
                    .into_response()
            }
        }
        Response::Error { error } => {
            let status = if error.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, axum::Json(HttpErrorResponse { error })).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(HttpErrorResponse {
                error: "Invalid response type".into(),
            }),
        )
            .into_response(),
    }
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
    crate::http_response!(ctx.handle_whois(target.clone()).await, Whois)
}

async fn handle_purge(
    State(state): State<AppState>,
    Path(target): Path<lanforge_types::identifiers::MacAddr>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_purge(target).await, Success => NoContent)
}

async fn handle_transient_devices(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_transient_host_list().await, TransientHosts)
}
