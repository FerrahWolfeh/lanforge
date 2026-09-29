use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Extension, Json, Router,
    extract::{Path, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::SET_COOKIE,
    },
    response::IntoResponse,
    routing::{delete, get, post},
};
use lanforge_crypto::{hash_password, verify_password};
use lanforge_types::auth::UserRole;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::auth::{AuthenticatedUser, extract_token, looks_like_jwt};
use crate::error::{HttpError, Result as HttpResult};
use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub remember_me: Option<bool>,
}

#[derive(Serialize)]
pub struct LoginResponseData {
    pub token: String,
    pub username: String,
    pub method: String,
    pub auth_required: bool,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub data: LoginResponseData,
}

#[derive(Serialize)]
pub struct AuthStatusData {
    pub auth_required: bool,
    pub authenticated: bool,
}

#[derive(Serialize)]
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
        .route("/logout", post(handle_logout).get(handle_logout))
        .route("/status", get(handle_status))
        .route("/me", get(handle_me))
        .route("/change-password", post(handle_change_password))
}

pub(crate) async fn handle_logout() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str("session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0") {
        headers.append(SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str("lanforge_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0") {
        headers.append(SET_COOKIE, v);
    }
    (
        StatusCode::OK,
        headers,
        Json(serde_json::json!({ "data": { "message": "Logged out successfully" } })),
    )
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ScopesPayload {
    List(Vec<String>),
    Single(String),
}

#[derive(Debug, Deserialize)]
pub struct GenerateTokenRequest {
    pub name: String,
    pub scopes: Option<ScopesPayload>,
    pub expires_at: Option<i64>,
}

async fn handle_list_tokens(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ak_list().await, AuthTokens)
}

async fn handle_generate_token(
    State(state): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Json(payload): Json<GenerateTokenRequest>,
) -> impl IntoResponse {
    if let Some(Extension(u)) = user
        && u.role != "admin"
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Admin role required to generate API tokens" })),
        )
            .into_response();
    }

    let parsed_scopes = payload.scopes.and_then(|s| {
        let mut vec = lanforge_types::auth::ApiScopes::new();
        match s {
            ScopesPayload::List(items) => {
                for item in items {
                    if let Ok(sc) = item.parse() {
                        vec.push(sc);
                    }
                }
            }
            ScopesPayload::Single(str_val) => {
                for part in str_val.split(',') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty()
                        && let Ok(sc) = trimmed.parse()
                    {
                        vec.push(sc);
                    }
                }
            }
        }
        if vec.is_empty() { None } else { Some(vec) }
    });

    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_ak_generate(payload.name, parsed_scopes, payload.expires_at)
            .await,
        AuthToken
    )
}

async fn handle_delete_token(
    State(state): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(Extension(u)) = user
        && u.role != "admin"
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Admin role required to delete API tokens" })),
        )
            .into_response();
    }
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ak_delete(id).await, Success)
}

async fn handle_renew_token(
    State(state): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(Extension(u)) = user
        && u.role != "admin"
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Admin role required to renew API tokens" })),
        )
            .into_response();
    }
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ak_renew(id).await, AuthToken)
}

async fn handle_validate(
    State(state): State<AppState>,
    Json(payload): Json<ValidateRequest>,
) -> impl IntoResponse {
    let valid = if looks_like_jwt(&payload.token) && state.auth.validate_token(&payload.token).is_ok() {
        true
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .cast_signed();
        match state.db.validate_api_token(&payload.token, now).await {
            Ok(Some(_)) => true,
            _ => state.auth.validate_token(&payload.token).is_ok(),
        }
    };
    Json(serde_json::json!({ "data": { "valid": valid } }))
}

#[allow(clippy::too_many_lines)]
pub async fn handle_login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> HttpResult<impl IntoResponse> {
    let auth_required = state.cfg.auth_password_hash.is_some()
        || state.auth.has_users_cached()
        || {
            let count = state.db.count_users().await.unwrap_or(0);
            if count > 0 {
                state.auth.set_has_users(true);
                true
            } else {
                false
            }
        };
    let username = payload
        .username
        .unwrap_or_else(|| "admin".to_string())
        .trim()
        .to_lowercase();

    let ttl_secs = if payload.remember_me.unwrap_or(false) {
        2_592_000 // 30 days
    } else {
        86_400 // 24 hours
    };

    let build_login_response = |token: String, user_name: String, method: &str| {
        let cookie_header =
            format!("session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl_secs}");
        let mut headers = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&cookie_header) {
            headers.insert(SET_COOKIE, v);
        }
        (
            StatusCode::OK,
            headers,
            Json(LoginResponse {
                data: LoginResponseData {
                    token,
                    username: user_name,
                    method: method.to_string(),
                    auth_required,
                },
            }),
        )
            .into_response()
    };

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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .cast_signed();
        match state.db.validate_api_token(&token_str, now).await {
            Ok(Some((name, _scopes))) => {
                let session_token = state.auth.generate_token_with_ttl(&name, "admin", ttl_secs)?;
                return Ok(build_login_response(
                    session_token,
                    name,
                    "api_token",
                ));
            }
            Ok(None) => {
                return Err(HttpError::Auth("Invalid API token".to_string()));
            }
            Err(e) => {
                error!("Database error during login token validation: {e}");
                return Err(HttpError::Internal("Auth DB error".into()));
            }
        }
    }

    // 2. Database User Password Authentication
    let password = payload.password.unwrap_or_default();
    if password.is_empty() {
        return Err(HttpError::Auth("Password is required".to_string()));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed();

    if let Ok(Some(db_user)) = state.db.get_user_by_username(&username).await {
        if verify_password(&db_user.password_hash, &password) {
            let _ = state
                .db
                .update_user_last_login(&db_user.username, now)
                .await;
            let session_token =
                state
                    .auth
                    .generate_token_with_ttl(&db_user.username, db_user.role.as_str(), ttl_secs)?;
            return Ok(build_login_response(
                session_token,
                db_user.username,
                "password",
            ));
        }
        return Err(HttpError::Auth("Invalid credentials".to_string()));
    }

    // 3. Bootstrapping / Fallback Admin seeding if no DB users exist
    let user_count = state.db.count_users().await.unwrap_or(0);
    if user_count == 0
        && let Some(hash) = &state.cfg.auth_password_hash
        && verify_password(hash, &password)
    {
        let _ = state.db.create_user("admin", hash, UserRole::Admin, now).await;
        let session_token = state
            .auth
            .generate_token_with_ttl("admin", "admin", ttl_secs)?;
        return Ok(build_login_response(
            session_token,
            "admin".to_string(),
            "password",
        ));
    }

    Err(HttpError::Auth("Invalid credentials".to_string()))
}

async fn handle_status(State(state): State<AppState>, req: Request) -> impl IntoResponse {
    let auth_required = state.cfg.auth_password_hash.is_some()
        || state.auth.has_users_cached()
        || {
            let count = state.db.count_users().await.unwrap_or(0);
            if count > 0 {
                state.auth.set_has_users(true);
                true
            } else {
                false
            }
        };

    let authenticated = if let Some(token) = extract_token(req.headers(), req.uri().query()) {
        if looks_like_jwt(&token) && state.auth.validate_token(&token).is_ok() {
            true
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .cast_signed();
            match state.db.validate_api_token(&token, now).await {
                Ok(Some(_)) => true,
                _ => state.auth.validate_token(&token).is_ok(),
            }
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

async fn handle_me(Extension(user): Extension<AuthenticatedUser>) -> impl IntoResponse {
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
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<ChangePasswordRequest>,
) -> HttpResult<impl IntoResponse> {
    if payload.new_password.len() < 8 {
        return Err(HttpError::Validation(
            "New password must be at least 8 characters long".to_string(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed();

    if let Ok(Some(db_user)) = state.db.get_user_by_username(&user.name).await {
        if let Some(old_pw) = &payload.old_password
            && !verify_password(&db_user.password_hash, old_pw)
        {
            return Err(HttpError::Auth("Invalid current password".to_string()));
        }
        let new_hash = hash_password(&payload.new_password);
        state
            .db
            .update_user_password(&user.name, &new_hash, now)
            .await
            .map_err(|e| HttpError::Internal(e.to_string()))?;
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({ "data": { "message": "Password updated successfully" } })),
        ))
    } else {
        Err(HttpError::NotFound(format!(
            "User '{}' not found",
            user.name
        )))
    }
}
