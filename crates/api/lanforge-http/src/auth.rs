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
use lanforge_db_core::DatabaseStore;
use lanforge_types::auth::{ApiScope, ApiScopes};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::config::HttpConfig;
use crate::error::{HttpError, Result as HttpResult};

/// JWT Claims.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,  // Username
    pub role: String, // User role ("admin", "operator", "viewer")
    pub exp: usize,   // Expiration
}

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

    pub fn generate_token(&self, username: &str, role: &str) -> HttpResult<String> {
        self.generate_token_with_ttl(username, role, 86400) // Default 24 hours
    }

    pub fn generate_token_with_ttl(
        &self,
        username: &str,
        role: &str,
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
        };

        Ok(encode(&Header::default(), &claims, &self.encoding_key)?)
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
            .ok_or_else(|| HttpError::Auth("Missing Authorization header, session cookie, or token parameter".into()))
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

pub async fn authenticate_token(
    token: &str,
    auth_manager: &AuthManager,
    db: &dyn DatabaseStore,
) -> HttpResult<AuthenticatedUser> {
    // 1. Fast-path JWT validation (sub-microsecond in-memory HMAC, zero disk I/O)
    if looks_like_jwt(token)
        && let Ok(claims) = auth_manager.validate_token(token)
    {
        return Ok(AuthenticatedUser {
            name: claims.sub,
            role: claims.role,
            method: AuthMethod::Jwt,
            scopes: ApiScopes::from_slice(&[ApiScope::Admin]),
        });
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed();

    // 2. Validate against database API tokens
    match db.validate_api_token(token, now).await {
        Ok(Some((name, scopes))) => Ok(AuthenticatedUser {
            name,
            role: "admin".to_string(),
            method: AuthMethod::ApiToken,
            scopes,
        }),
        Ok(None) => {
            // If not previously attempted as JWT, try as fallback
            if !looks_like_jwt(token)
                && let Ok(claims) = auth_manager.validate_token(token)
            {
                return Ok(AuthenticatedUser {
                    name: claims.sub,
                    role: claims.role,
                    method: AuthMethod::Jwt,
                    scopes: ApiScopes::from_slice(&[ApiScope::Admin]),
                });
            }
            Err(HttpError::Auth("Invalid or expired token".into()))
        }
        Err(e) => {
            error!("Database error during token validation: {e}");
            Err(HttpError::Internal("Auth database error".into()))
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

    async fn from_request_parts(parts: &mut Parts, state: &S) -> HttpResult<Self> {
        let auth_manager = AuthManager::from_ref(state);
        let db = Arc::<dyn DatabaseStore>::from_ref(state);
        let token = extract_token(&parts.headers, parts.uri.query()).ok_or_else(|| {
            HttpError::Auth("Missing Authorization header, session cookie, or token parameter".into())
        })?;

        authenticate_token(&token, &auth_manager, db.as_ref()).await
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

pub async fn middleware(
    State(cfg): State<Arc<HttpConfig>>,
    State(db): State<Arc<dyn DatabaseStore>>,
    State(auth_manager): State<AuthManager>,
    mut req: Request<Body>,
    next: Next,
) -> HttpResult<AxumResponse> {
    if req.method() == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    if is_public_auth_path(req.uri().path()) {
        return Ok(next.run(req).await);
    }

    // If no password hash is set AND no DB users exist, authentication is globally disabled.
    if cfg.auth_password_hash.is_none()
        && !auth_manager.has_users_cached()
    {
        let count = db.count_users().await.unwrap_or(0);
        if count == 0 {
            return Ok(next.run(req).await);
        }
        auth_manager.set_has_users(true);
    }

    let token = extract_token(req.headers(), req.uri().query())
        .ok_or_else(|| HttpError::Auth("Missing Authorization header, session cookie, or token parameter".into()))?;

    let user = authenticate_token(&token, &auth_manager, db.as_ref()).await?;

    req.extensions_mut().insert(user);

    Ok(next.run(req).await)
}
