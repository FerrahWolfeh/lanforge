use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Extension, Json, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response as AxumResponse},
    routing::{delete, get, post},
};
use lanforge_crypto::hash_password;
use lanforge_db_core::UserEntry;
use lanforge_types::auth::{ApiScopes, UserRole};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::auth::{
    AuthMethod, AuthenticatedUser, ELEVATION_TTL_SECS, auth_required, authenticate_token,
    extract_token,
};
use crate::authz::{self, Permission};
use crate::error::{HttpError, Result as HttpResult};
use crate::routes::create_client_ctx;
use crate::server::AppState;
use crate::throttle::ClientIp;

/// Session lifetime (24 h), and with "remember me" (30 days).
pub(crate) const SESSION_TTL_SECS: u64 = 86_400;
pub(crate) const REMEMBER_ME_TTL_SECS: u64 = 2_592_000;

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
pub struct ElevateRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(alias = "old_password")]
    pub current_password: Option<String>,
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
        .route("/elevate", post(handle_elevate))
}

pub(crate) async fn handle_logout() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str("session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0") {
        headers.append(SET_COOKIE, v);
    }
    if let Ok(v) =
        HeaderValue::from_str("lanforge_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
    {
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
    Json(payload): Json<GenerateTokenRequest>,
) -> impl IntoResponse {
    let parsed_scopes = payload.scopes.and_then(|s| {
        let mut vec = ApiScopes::new();
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
    Path(id): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ak_delete(id).await, Success)
}

async fn handle_renew_token(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_ak_renew(id).await, AuthToken)
}

async fn handle_validate(
    State(state): State<AppState>,
    Json(payload): Json<ValidateRequest>,
) -> impl IntoResponse {
    let valid = authenticate_token(&payload.token, &state.auth, state.db.as_ref()).is_ok();
    Json(serde_json::json!({ "data": { "valid": valid } }))
}

fn check_auth_required(state: &AppState) -> bool {
    auth_required(
        &state.cfg,
        &state.auth,
        state.db.as_ref(),
        state.ctx.is_recovery_mode(),
    )
    .unwrap_or(true)
}

fn build_login_response(
    token: String,
    user_name: String,
    method: &str,
    ttl_secs: u64,
    auth_required: bool,
) -> AxumResponse {
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
}

fn authenticate_via_api_token(
    state: &AppState,
    payload: &LoginRequest,
) -> HttpResult<Option<(String, String, &'static str)>> {
    let candidate_token = payload.token.clone().or_else(|| {
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
        match state.db.validate_api_token(&token_str, now) {
            // The token itself is the session: it keeps its scopes and expiry. Minting a
            // JWT here made any token (even monitoring-only) an admin session.
            Ok(Some((name, _scopes))) => return Ok(Some((token_str, name, "api_token"))),
            Ok(None) => return Err(HttpError::Auth("Invalid API token".to_string())),
            Err(e) => {
                error!("Database error during login token validation: {e}");
                return Err(HttpError::ServiceUnavailable(
                    "persistence unavailable".into(),
                ));
            }
        }
    }
    Ok(None)
}

/// Issues a session bound to the user's current credential version (see `Claims::uv`).
pub(crate) fn issue_session(
    state: &AppState,
    user: &UserEntry,
    ttl_secs: u64,
) -> HttpResult<String> {
    state.auth.generate_token_with_ttl(
        &user.username,
        user.role.as_str(),
        user.updated_at,
        ttl_secs,
    )
}

async fn authenticate_via_password(
    state: &AppState,
    username: &str,
    password: &str,
    ttl_secs: u64,
) -> HttpResult<(String, String, &'static str)> {
    if password.is_empty() {
        return Err(HttpError::Auth("Password is required".to_string()));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed();

    match state.db.get_user_by_username(username) {
        Ok(Some(db_user)) => {
            if state
                .auth
                .throttle
                .verify(&db_user.password_hash, password)
                .await
            {
                let _ = state.db.update_user_last_login(&db_user.username, now);
                let session_token = issue_session(state, &db_user, ttl_secs)?;
                return Ok((session_token, db_user.username, "password"));
            }
            return Err(HttpError::Auth("Invalid credentials".to_string()));
        }
        Ok(None) => {}
        Err(e) => {
            error!("Database error looking up user {username}: {e}");
            return Err(HttpError::ServiceUnavailable(
                "persistence unavailable".into(),
            ));
        }
    }

    // Bootstrapping / Fallback Admin seeding if no DB users exist
    let user_count = match state.db.count_users() {
        Ok(c) => c,
        Err(e) => {
            error!("Database error counting users: {e}");
            return Err(HttpError::ServiceUnavailable(
                "persistence unavailable".into(),
            ));
        }
    };
    if user_count == 0
        && let Some(hash) = &state.cfg.auth_password_hash
        && state.auth.throttle.verify(hash, password).await
    {
        let admin = state
            .db
            .create_user("admin", hash, UserRole::Admin, now)
            .map_err(|e| {
                error!("Database error seeding the admin user: {e}");
                HttpError::ServiceUnavailable("persistence unavailable".into())
            })?;
        let session_token = issue_session(state, &admin, ttl_secs)?;
        return Ok((session_token, admin.username, "password"));
    }

    // Recovery mode without a password hash file: the real users are in the database that
    // did not open, so no login can succeed here. Say so instead of "invalid credentials".
    if user_count == 0 && state.ctx.is_recovery_mode() {
        return Err(HttpError::ServiceUnavailable(
            "persistence unavailable".into(),
        ));
    }

    Err(HttpError::Auth("Invalid credentials".to_string()))
}

pub async fn handle_login(
    State(state): State<AppState>,
    client: ClientIp,
    Json(payload): Json<LoginRequest>,
) -> HttpResult<impl IntoResponse> {
    let throttle = Arc::clone(&state.auth.throttle);
    throttle.guard(client, login(state, payload)).await
}

async fn login(state: AppState, payload: LoginRequest) -> HttpResult<impl IntoResponse> {
    let auth_required = check_auth_required(&state);
    let username = payload
        .username
        .as_deref()
        .unwrap_or("admin")
        .trim()
        .to_lowercase();

    let ttl_secs = if payload.remember_me.unwrap_or(false) {
        REMEMBER_ME_TTL_SECS
    } else {
        SESSION_TTL_SECS
    };

    if let Some((session_token, name, method)) = authenticate_via_api_token(&state, &payload)? {
        return Ok(build_login_response(
            session_token,
            name,
            method,
            ttl_secs,
            auth_required,
        ));
    }

    let password = payload.password.as_deref().unwrap_or_default();
    let (session_token, authed_user, method) =
        authenticate_via_password(&state, &username, password, ttl_secs).await?;

    Ok(build_login_response(
        session_token,
        authed_user,
        method,
        ttl_secs,
        auth_required,
    ))
}

async fn handle_status(State(state): State<AppState>, req: Request) -> impl IntoResponse {
    let auth_required = check_auth_required(&state);

    let authenticated = extract_token(req.headers(), req.uri().query())
        .is_some_and(|token| authenticate_token(&token, &state.auth, state.db.as_ref()).is_ok());

    Json(AuthStatusResponse {
        data: AuthStatusData {
            auth_required,
            authenticated,
        },
    })
}

/// The caller, with the permissions its role (session) or scopes (API token) grant, so the
/// web UI can hide what the server would refuse.
async fn handle_me(Extension(user): Extension<AuthenticatedUser>) -> impl IntoResponse {
    let permissions: Vec<&str> = Permission::ALL
        .into_iter()
        .filter(|&p| authz::grants(&user, p))
        .map(Permission::as_str)
        .collect();
    Json(serde_json::json!({
        "data": {
            "username": user.name,
            "role": user.role,
            "scopes": user.scopes,
            "permissions": permissions,
        }
    }))
}

/// Re-authenticates a password session: returns a short-lived elevation token that sensitive
/// actions (users, token creation, database reset) take in the `X-Lanforge-Elevation` header.
async fn handle_elevate(
    State(state): State<AppState>,
    client: ClientIp,
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<ElevateRequest>,
) -> HttpResult<impl IntoResponse> {
    let throttle = Arc::clone(&state.auth.throttle);
    throttle.guard(client, elevate(state, user, payload)).await
}

async fn elevate(
    state: AppState,
    user: AuthenticatedUser,
    payload: ElevateRequest,
) -> HttpResult<impl IntoResponse> {
    if !matches!(user.method, AuthMethod::Jwt) {
        return Err(HttpError::Forbidden(
            "API tokens cannot re-authenticate".to_string(),
        ));
    }
    let db_user = match state.db.get_user_by_username(&user.name) {
        Ok(Some(u)) => u,
        Ok(None) => return Err(HttpError::Forbidden("Invalid password".to_string())),
        Err(e) => {
            error!("Database error looking up user {}: {e}", user.name);
            return Err(HttpError::ServiceUnavailable(
                "persistence unavailable".into(),
            ));
        }
    };
    if !state
        .auth
        .throttle
        .verify(&db_user.password_hash, &payload.password)
        .await
    {
        return Err(HttpError::Forbidden("Invalid password".to_string()));
    }
    let token = state
        .auth
        .generate_elevation_token(&db_user.username, db_user.role.as_str())?;
    Ok(Json(serde_json::json!({
        "data": { "elevation_token": token, "expires_in": ELEVATION_TTL_SECS }
    })))
}

/// Changes the session user's own password. Requires a password session (an API token's
/// name is not a username) and the current password, so a stolen session cannot take the
/// account over. A wrong current password is 403, not 401: a 401 logs the `WebUI` out.
async fn handle_change_password(
    State(state): State<AppState>,
    client: ClientIp,
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<ChangePasswordRequest>,
) -> HttpResult<impl IntoResponse> {
    let throttle = Arc::clone(&state.auth.throttle);
    throttle
        .guard(client, change_password(state, user, payload))
        .await
}

async fn change_password(
    state: AppState,
    user: AuthenticatedUser,
    payload: ChangePasswordRequest,
) -> HttpResult<impl IntoResponse> {
    if !matches!(user.method, AuthMethod::Jwt) {
        return Err(HttpError::Forbidden(
            "API tokens cannot change a user password".to_string(),
        ));
    }
    let current = payload
        .current_password
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| HttpError::Validation("Current password is required".to_string()))?;
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

    let db_user = match state.db.get_user_by_username(&user.name) {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Err(HttpError::NotFound(format!(
                "User '{}' not found",
                user.name
            )));
        }
        Err(e) => {
            error!("Database error looking up user {}: {e}", user.name);
            return Err(HttpError::ServiceUnavailable(
                "persistence unavailable".into(),
            ));
        }
    };
    if !state
        .auth
        .throttle
        .verify(&db_user.password_hash, current)
        .await
    {
        return Err(HttpError::Forbidden("Invalid current password".to_string()));
    }
    let new_hash = hash_password(&payload.new_password);
    state
        .db
        .update_user_password(&user.name, &new_hash, now)
        .map_err(|e| {
            error!("Database error updating password for {}: {e}", user.name);
            HttpError::ServiceUnavailable("persistence unavailable".into())
        })?;
    // Every session of this user just ended (other devices too): hand this one a new token.
    let db_user = UserEntry {
        password_hash: new_hash,
        updated_at: now,
        ..db_user
    };
    let token = issue_session(&state, &db_user, SESSION_TTL_SECS)?;
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&format!(
        "session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECS}"
    )) {
        headers.insert(SET_COOKIE, v);
    }
    Ok((
        StatusCode::OK,
        headers,
        Json(serde_json::json!({
            "data": { "message": "Password updated successfully", "token": token }
        })),
    ))
}
