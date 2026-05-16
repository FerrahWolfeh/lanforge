use axum::{Router, routing::post, extract::State, Json, response::IntoResponse, http::StatusCode};
use crate::server::AppState;
use crate::error::Result as HttpResult;
use crate::routes::create_client_ctx;
use lanforge_core::utils::auth::verify_password;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordUpdateRequest {
    pub password: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(handle_login))
        .route("/password", post(handle_password_update))
}

async fn handle_login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> HttpResult<impl IntoResponse> {
    let Some(hash) = &state.cfg.auth_password_hash else {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Authentication not configured on this daemon" })),
        )
            .into_response());
    };

    if verify_password(hash, &payload.password) {
        let token = state.auth.generate_token("admin")?;
        Ok((StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response())
    } else {
        Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid password" })),
        )
            .into_response())
    }
}

async fn handle_password_update(
    State(_state): State<AppState>,
    Json(_payload): Json<PasswordUpdateRequest>,
) -> impl IntoResponse {
    Json(lanforge_api::api::Response::Error {
        error: "Password-based authentication is deprecated in V3. Use API tokens (ak_*) instead.".to_string(),
    })
}

