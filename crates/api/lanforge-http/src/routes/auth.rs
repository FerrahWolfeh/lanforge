use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub token: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/tokens",
            get(handle_list_tokens).post(handle_generate_token),
        )
        .route("/tokens/{id}", delete(handle_delete_token))
        .route("/tokens/{id}/renew", post(handle_renew_token))
        .route("/validate", post(handle_validate))
}

async fn handle_list_tokens(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ak_list().await, AuthTokens)
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

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub token: String,
}

pub async fn handle_login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> crate::error::Result<impl IntoResponse> {
    if let Some(hash) = &state.cfg.auth_password_hash {
        if lanforge_core::utils::auth::verify_password(hash, &payload.password) {
            let token = state.auth.generate_token("admin")?;
            Ok((StatusCode::OK, Json(LoginResponse { token })).into_response())
        } else {
            Err(crate::error::HttpError::Auth(
                "Invalid password".to_string(),
            ))
        }
    } else {
        let token = state.auth.generate_token("admin")?;
        Ok((StatusCode::OK, Json(LoginResponse { token })).into_response())
    }
}
