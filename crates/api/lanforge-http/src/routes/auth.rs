use std::time::SystemTime;

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

use lanforge_db::UserStore;

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

#[derive(serde::Serialize)]
pub struct LoginResponseData {
    pub token: String,
    pub username: String,
    pub method: String,
    pub auth_required: bool,
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub data: LoginResponseData,
}

#[derive(serde::Serialize)]
pub struct AuthStatusData {
    pub auth_required: bool,
    pub authenticated: bool,
}

#[derive(serde::Serialize)]
pub struct AuthStatusResponse {
    pub data: AuthStatusData,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: Option<String>,
    pub new_password: String,
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
        .route("/login", post(handle_login))
        .route("/status", get(handle_status))
        .route("/me", get(handle_me))
        .route("/change-password", post(handle_change_password))
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

pub async fn handle_login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> crate::error::Result<impl IntoResponse> {
    let user_count = state.db.count_users().await.unwrap_or(0);
    let auth_required = state.cfg.auth_password_hash.is_some() || user_count > 0;
    let username = payload
        .username
        .unwrap_or_else(|| "admin".to_string())
        .trim()
        .to_lowercase();

    // 1. If explicit API token or password matching API token format is provided
    let candidate_token = payload.token.or_else(|| {
        payload.password.as_ref().and_then(|p| {
            if p.starts_with("ak_") || p.starts_with("lf_ak_") {
                Some(p.clone())
            } else {
                None
            }
        })
    });

    if let Some(token_str) = candidate_token {
        match state.db.validate_api_token(&token_str).await {
            Ok(Some((name, _scopes))) => {
                let session_token = state.auth.generate_token(&name, "admin")?;
                return Ok((
                    StatusCode::OK,
                    Json(LoginResponse {
                        data: LoginResponseData {
                            token: session_token,
                            username: name,
                            method: "api_token".to_string(),
                            auth_required,
                        },
                    }),
                )
                    .into_response());
            }
            Ok(None) => {
                return Err(crate::error::HttpError::Auth(
                    "Invalid API token".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!("Database error during login token validation: {e}");
                return Err(crate::error::HttpError::Internal("Auth DB error".into()));
            }
        }
    }

    // 2. Database User Password Authentication
    let password = payload.password.unwrap_or_default();
    if password.is_empty() {
        return Err(crate::error::HttpError::Auth(
            "Password is required".to_string(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed();

    if let Ok(Some(db_user)) = state.db.get_user_by_username(&username).await {
        if lanforge_core::utils::auth::verify_password(&db_user.password_hash, &password) {
            let _ = state
                .db
                .update_user_last_login(&db_user.username, now)
                .await;
            let session_token = state
                .auth
                .generate_token(&db_user.username, &db_user.role)?;
            return Ok((
                StatusCode::OK,
                Json(LoginResponse {
                    data: LoginResponseData {
                        token: session_token,
                        username: db_user.username,
                        method: "password".to_string(),
                        auth_required,
                    },
                }),
            )
                .into_response());
        }
        return Err(crate::error::HttpError::Auth(
            "Invalid credentials".to_string(),
        ));
    }

    // 3. Bootstrapping / Fallback Admin seeding if no DB users exist
    if user_count == 0
        && let Some(hash) = &state.cfg.auth_password_hash
        && lanforge_core::utils::auth::verify_password(hash, &password)
    {
        let _ = state.db.create_user("admin", hash, "admin", now).await;
        let session_token = state.auth.generate_token("admin", "admin")?;
        return Ok((
            StatusCode::OK,
            Json(LoginResponse {
                data: LoginResponseData {
                    token: session_token,
                    username: "admin".to_string(),
                    method: "password".to_string(),
                    auth_required,
                },
            }),
        )
            .into_response());
    }

    Err(crate::error::HttpError::Auth(
        "Invalid credentials".to_string(),
    ))
}

async fn handle_status(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let user_count = state.db.count_users().await.unwrap_or(0);
    let auth_required = state.cfg.auth_password_hash.is_some() || user_count > 0;
    let authenticated = if let Some(token) = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
    {
        match state.db.validate_api_token(token).await {
            Ok(Some(_)) => true,
            _ => state.auth.validate_token(token).is_ok(),
        }
    } else {
        false
    };

    Json(AuthStatusResponse {
        data: AuthStatusData {
            auth_required,
            authenticated,
        },
    })
}

async fn handle_me(
    axum::Extension(user): axum::Extension<crate::auth::AuthenticatedUser>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "data": {
            "username": user.name,
            "role": user.role,
            "scopes": user.scopes,
        }
    }))
}

async fn handle_change_password(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<crate::auth::AuthenticatedUser>,
    Json(payload): Json<ChangePasswordRequest>,
) -> crate::error::Result<impl IntoResponse> {
    if payload.new_password.len() < 8 {
        return Err(crate::error::HttpError::Validation(
            "New password must be at least 8 characters long".to_string(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed();

    if let Ok(Some(db_user)) = state.db.get_user_by_username(&user.name).await {
        if let Some(old_pw) = &payload.old_password
            && !lanforge_core::utils::auth::verify_password(&db_user.password_hash, old_pw)
        {
            return Err(crate::error::HttpError::Auth(
                "Invalid current password".to_string(),
            ));
        }
        let new_hash = lanforge_core::utils::auth::hash_password(&payload.new_password);
        state
            .db
            .update_user_password(&user.name, &new_hash, now)
            .await
            .map_err(|e| crate::error::HttpError::Internal(e.to_string()))?;
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({ "data": { "message": "Password updated successfully" } })),
        ))
    } else {
        Err(crate::error::HttpError::NotFound(format!(
            "User '{}' not found",
            user.name
        )))
    }
}
