use axum::{Router, routing::post, extract::State, Json};
use crate::server::AppState;
use crate::routes::create_client_ctx;
use lanforge_api::api::Response;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vacuum", post(handle_vacuum))
        .route("/prune", post(handle_prune))
        .route("/log_clean", post(handle_log_clean))
        .route("/reset", post(handle_reset))
}

async fn handle_vacuum(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_db_vacuum().await)
}

async fn handle_prune(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_db_prune().await)
}

async fn handle_log_clean(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_db_log_clean().await)
}

async fn handle_reset(State(state): State<AppState>) -> Json<Response> {
    let ctx = create_client_ctx(&state);
    Json(ctx.handle_db_reset().await)
}
