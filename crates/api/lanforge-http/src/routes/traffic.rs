use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::get,
};
use lanforge_types::network::TrafficConfig;

use crate::routes::create_client_ctx;
use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(handle_status))
        .route(
            "/config",
            get(handle_get_config).post(handle_update_config),
        )
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_traffic_status().await, TrafficStatus)
}

async fn handle_get_config(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_traffic_config().await, TrafficConfig)
}

async fn handle_update_config(
    State(state): State<AppState>,
    Json(config): Json<TrafficConfig>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_update_traffic_config(config).await, Success)
}
