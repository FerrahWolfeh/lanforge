use axum::{Router, routing::{get, post, delete}, extract::{State, Path}, Json, response::IntoResponse, http::StatusCode};
use crate::server::AppState;
use crate::routes::create_client_ctx;
use lanforge_api::api::Response;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub token: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/tokens", get(handle_list_tokens).post(handle_generate_token))
        .route("/tokens/{id}", delete(handle_delete_token))
        .route("/tokens/{id}/renew", post(handle_renew_token))
        .route("/validate", post(handle_validate))
}

async fn handle_list_tokens(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_ak_list().await {
        Response::AuthTokens(res) => (StatusCode::OK, Json(serde_json::json!({ "data": res.tokens }))).into_response(),
        Response::Error { error } => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": error }))).into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Invalid response type" }))).into_response(),
    }
}

async fn handle_generate_token() -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "This operation is only available via local socket" })),
    )
}

async fn handle_delete_token(Path(_id): Path<String>) -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "This operation is only available via local socket" })),
    )
}

async fn handle_renew_token(Path(_id): Path<String>) -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "This operation is only available via local socket" })),
    )
}

async fn handle_validate(
    State(state): State<AppState>,
    Json(payload): Json<ValidateRequest>,
) -> impl IntoResponse {
    let valid = match state.db.validate_api_token(&payload.token).await {
        Ok(Some(_)) => true,
        _ => state.auth.validate_token(&payload.token).is_ok(),
    };
    Json(serde_json::json!({ "data": { "valid": valid } }))
}
