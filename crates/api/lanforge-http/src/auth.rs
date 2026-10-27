use std::future::{Future, ready};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{FromRef, FromRequestParts, State},
    http::{
        Method, Request,
        header::{AUTHORIZATION, COOKIE},
        request::Parts,
    },
    middleware::Next,
    response::Response as AxumResponse,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lanforge_core::context::LanforgeContext;
use lanforge_db_core::DatabaseStore;
use lanforge_types::auth::ApiScopes;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::authz;
use crate::config::HttpConfig;
use crate::error::{HttpError, Result as HttpResult};

/// JWT Claims.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,  // Username
    pub role: String, // User role ("admin", "operator", "viewer")
    pub exp: usize,   // Expiration
    /// Elevation token (re-authentication for sensitive actions), never a session.
    #[serde(default)]
    pub elev: bool,
    /// The user's credential version (`updated_at`) when the session was issued: a password
    /// or role change bumps it and ends the session. Compared for equality, so a wrong
    /// clock (an SBC without RTC before NTP) cannot lock users out.
    #[serde(default)]
    pub uv: i64,
}

/// Header carrying the elevation token that sensitive actions require.
pub const ELEVATION_HEADER: &str = "x-lanforge-elevation";

/// How long an elevation token lasts.
pub const ELEVATION_TTL_SECS: u64 = 300;

/// Represents an authenticated user (either via JWT or API Token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub name: String,
    pub role: String,
    pub method: AuthMethod,
    pub scopes: ApiScopes,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuthMethod {
    Jwt,
    ApiToken,
}

#[derive(Clone)]
pub struct AuthManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    has_users: Arc<AtomicBool>,
}

impl AuthManager {
    #[must_use]
    pub fn new() -> Self {
        let secret = rand::random::<[u8; 32]>();
        Self::from_secret(&secret)
    }

    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            has_users: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub fn has_users_cached(&self) -> bool {
        self.has_users.load(Ordering::Relaxed)
    }

    pub fn set_has_users(&self, val: bool) {
        self.has_users.store(val, Ordering::Relaxed);
    }

    pub fn generate_token(&self, username: &str, role: &str, version: i64) -> HttpResult<String> {
        self.generate_token_with_ttl(username, role, version, 86400) // Default 24 hours
    }

    pub fn generate_token_with_ttl(
        &self,
        username: &str,
        role: &str,
        version: i64,
        ttl_secs: u64,
    ) -> HttpResult<String> {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| HttpError::Time(e.to_string()))?
            .as_secs()
            + ttl_secs;

        let claims = Claims {
            sub: username.to_string(),
            role: role.to_string(),
            exp: usize::try_from(expiration)
                .map_err(|_| HttpError::Time("Expiration timestamp too large".into()))?,
            elev: false,
            uv: version,
        };

        Ok(encode(&Header::default(), &claims, &self.encoding_key)?)
    }

    /// Issues a short-lived elevation token for `username`, after it re-entered its password.
    pub fn generate_elevation_token(&self, username: &str, role: &str) -> HttpResult<String> {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| HttpError::Time(e.to_string()))?
            .as_secs()
            + ELEVATION_TTL_SECS;
        let claims = Claims {
            sub: username.to_string(),
            role: role.to_string(),
            exp: usize::try_from(expiration)
                .map_err(|_| HttpError::Time("Expiration timestamp too large".into()))?,
            elev: true,
            uv: 0,
        };
        Ok(encode(&Header::default(), &claims, &self.encoding_key)?)
    }

    /// Whether `token` is a valid elevation token for `username`.
    #[must_use]
    pub fn is_elevated(&self, token: &str, username: &str) -> bool {
        self.validate_token(token)
            .is_ok_and(|c| c.elev && c.sub == username)
    }

    /// Validates a session token: an elevation token is not one.
    fn validate_session(&self, token: &str) -> HttpResult<Claims> {
        let claims = self.validate_token(token)?;
        if claims.elev {
            return Err(HttpError::Auth("Invalid or expired token".into()));
        }
        Ok(claims)
    }

    pub fn validate_token(&self, token: &str) -> HttpResult<Claims> {
        let validation = Validation::default();
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}

pub fn extract_token_str(headers: &axum::http::HeaderMap) -> Option<&str> {
    if let Some(auth_header) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
            return Some(stripped);
        }
        if !auth_header.contains(' ') {
            return Some(auth_header);
        }
    }
    if let Some(cookie_header) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(val) = cookie.strip_prefix("lanforge_session=") {
                return Some(val);
            }
            if let Some(val) = cookie.strip_prefix("session=") {
                return Some(val);
            }
        }
    }
    None
}

/// Extract authentication token from headers (Authorization, Cookie) or query string (`token`, `access_token`).
#[must_use]
pub fn extract_token(headers: &axum::http::HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(tok) = extract_token_str(headers) {
        return Some(tok.to_string());
    }
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && (k == "token" || k == "access_token")
                && !v.is_empty()
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
    AuthManager: FromRef<S>,
{
    type Rejection = HttpError;

    fn from_request_parts(parts: &mut Parts, state: &S) -> impl Future<Output = HttpResult<Self>> {
        let auth_manager = AuthManager::from_ref(state);
        let result = extract_token(&parts.headers, parts.uri.query())
            .ok_or_else(|| {
                HttpError::Auth(
                    "Missing Authorization header, session cookie, or token parameter".into(),
                )
            })
            .and_then(|token| {
                auth_manager
                    .validate_token(&token)
                    .map_err(|_| HttpError::Auth("Invalid or expired token".into()))
            });

        ready(result)
    }
}

#[inline]
#[must_use]
pub fn looks_like_jwt(token: &str) -> bool {
    let mut dots = 0;
    for &b in token.as_bytes() {
        if b == b'.' {
            dots += 1;
            if dots > 2 {
                return false;
            }
        }
    }
    dots == 2
}

/// Resolves a valid session to its user as stored now: a deleted user, or one whose
/// password or role changed since the session was issued, is no longer signed in, and the
/// role is the current one, not the one in the token.
fn session_user(claims: &Claims, db: &dyn DatabaseStore) -> HttpResult<AuthenticatedUser> {
    match db.get_user_by_username(&claims.sub) {
        Ok(Some(user)) if user.updated_at == claims.uv => Ok(AuthenticatedUser {
            name: user.username,
            role: user.role.as_str().to_string(),
            method: AuthMethod::Jwt,
            scopes: ApiScopes::new(),
        }),
        Ok(_) => Err(HttpError::Auth(
            "Session expired, please log in again".into(),
        )),
        Err(e) => {
            error!("Database error during session validation: {e}");
            Err(HttpError::ServiceUnavailable(
                "persistence unavailable".into(),
            ))
        }
    }
}

pub fn authenticate_token(
    token: &str,
    auth_manager: &AuthManager,
    db: &dyn DatabaseStore,
) -> HttpResult<AuthenticatedUser> {
    // 1. Fast-path JWT validation (sub-microsecond in-memory HMAC, zero disk I/O)
    if looks_like_jwt(token)
        && let Ok(claims) = auth_manager.validate_session(token)
    {
        return session_user(&claims, db);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed();

    // 2. Validate against database API tokens
    match db.validate_api_token(token, now) {
        // A token is not a user: no role, only its scopes (see `authz`).
        Ok(Some((name, scopes))) => Ok(AuthenticatedUser {
            name,
            role: "token".to_string(),
            method: AuthMethod::ApiToken,
            scopes,
        }),
        Ok(None) => {
            // If not previously attempted as JWT, try as fallback
            if !looks_like_jwt(token)
                && let Ok(claims) = auth_manager.validate_session(token)
            {
                return session_user(&claims, db);
            }
            Err(HttpError::Auth("Invalid or expired token".into()))
        }
        Err(e) => {
            error!("Database error during token validation: {e}");
            Err(HttpError::ServiceUnavailable(
                "persistence unavailable".into(),
            ))
        }
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    AuthManager: FromRef<S>,
    Arc<dyn DatabaseStore>: FromRef<S>,
{
    type Rejection = HttpError;

    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> HttpResult<Self> {
        let auth_manager = AuthManager::from_ref(state);
        let db = Arc::<dyn DatabaseStore>::from_ref(state);
        let token = extract_token(&parts.headers, parts.uri.query()).ok_or_else(|| {
            HttpError::Auth(
                "Missing Authorization header, session cookie, or token parameter".into(),
            )
        })?;

        authenticate_token(&token, &auth_manager, db.as_ref())
    }
}

#[inline]
fn is_public_auth_path(path: &str) -> bool {
    matches!(
        path,
        "/api/auth/login"
            | "/api/v1/auth/login"
            | "/api/auth/logout"
            | "/api/v1/auth/logout"
            | "/api/auth/status"
            | "/api/v1/auth/status"
            | "/api/v1/auth/validate"
            | "/api/system/setup-status"
            | "/api/v1/system/setup-status"
            | "/api/system/setup"
            | "/api/v1/system/setup"
            | "/api/capabilities"
            | "/api/v1/capabilities"
            | "/api/system/capabilities"
            | "/api/v1/system/capabilities"
            | "/auth/login"
            | "/v1/auth/login"
            | "/auth/logout"
            | "/v1/auth/logout"
            | "/auth/status"
            | "/v1/auth/status"
            | "/v1/auth/validate"
            | "/system/setup-status"
            | "/v1/system/setup-status"
            | "/system/setup"
            | "/v1/system/setup"
            | "/capabilities"
            | "/v1/capabilities"
            | "/system/capabilities"
            | "/v1/system/capabilities"
    )
}

/// Whether requests must carry credentials. Fails closed (D-11).
///
/// Authentication is off only when no password hash is configured and the user table is
/// readable and empty. Recovery mode (an in-memory stand-in for a database that did not
/// open) never counts as empty.
pub fn auth_required(
    cfg: &HttpConfig,
    auth_manager: &AuthManager,
    db: &dyn DatabaseStore,
    recovery: bool,
) -> HttpResult<bool> {
    if cfg.auth_password_hash.is_some() || auth_manager.has_users_cached() || recovery {
        return Ok(true);
    }
    match db.count_users() {
        Ok(0) => Ok(false),
        Ok(_) => {
            auth_manager.set_has_users(true);
            Ok(true)
        }
        Err(e) => {
            error!("Database error counting users: {e}");
            Err(HttpError::ServiceUnavailable(
                "persistence unavailable".into(),
            ))
        }
    }
}

/// Sensitive actions need a password session that re-authenticated recently: a stolen
/// session (or any API token) alone cannot take an account over or mint lasting access.
fn check_elevation(
    user: &AuthenticatedUser,
    headers: &axum::http::HeaderMap,
    auth_manager: &AuthManager,
) -> HttpResult<()> {
    if !matches!(user.method, AuthMethod::Jwt) {
        return Err(HttpError::Forbidden(
            "API tokens cannot manage users, tokens or the database".into(),
        ));
    }
    let elevated = headers
        .get(ELEVATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| auth_manager.is_elevated(t, &user.name));
    if elevated {
        Ok(())
    } else {
        Err(HttpError::Forbidden("Re-authentication required".into()))
    }
}

pub async fn middleware(
    State(cfg): State<Arc<HttpConfig>>,
    State(db): State<Arc<dyn DatabaseStore>>,
    State(auth_manager): State<AuthManager>,
    State(ctx): State<LanforgeContext>,
    mut req: Request<Body>,
    next: Next,
) -> HttpResult<AxumResponse> {
    if req.method() == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    if is_public_auth_path(req.uri().path()) {
        return Ok(next.run(req).await);
    }

    if !auth_required(&cfg, &auth_manager, db.as_ref(), ctx.is_recovery_mode())? {
        return Ok(next.run(req).await);
    }

    let token = extract_token(req.headers(), req.uri().query()).ok_or_else(|| {
        HttpError::Auth("Missing Authorization header, session cookie, or token parameter".into())
    })?;

    let user = authenticate_token(&token, &auth_manager, db.as_ref())?;

    let need = authz::requirement(req.method(), req.uri().path());
    if !authz::grants(&user, need.permission) {
        return Err(HttpError::Forbidden("Insufficient permissions".into()));
    }
    if need.sensitive {
        check_elevation(&user, req.headers(), &auth_manager)?;
    }

    req.extensions_mut().insert(user);

    Ok(next.run(req).await)
}
