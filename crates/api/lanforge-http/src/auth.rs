use crate::error::{HttpError, Result as HttpResult};
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response as AxumResponse;
use axum::{
    body::Body,
    extract::{FromRef, FromRequestParts},
    http::{Request, request::Parts},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use lanforge_db::UserStore;
use lanforge_db::engine::LanforgeDb;
use std::sync::Arc;

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
    pub scopes: lanforge_types::auth::ApiScopes,
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
        }
    }

    pub fn generate_token(&self, username: &str, role: &str) -> HttpResult<String> {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| HttpError::Time(e.to_string()))?
            .as_secs()
            + 86400; // 24 hours

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

    async fn from_request_parts(parts: &mut Parts, state: &S) -> HttpResult<Self> {
        let auth_manager = AuthManager::from_ref(state);

        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| HttpError::Auth("Missing Authorization header".into()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(HttpError::Auth("Invalid Authorization header".into()));
        }

        let token = &auth_header[7..];

        auth_manager
            .validate_token(token)
            .map_err(|_| HttpError::Auth("Invalid or expired token".into()))
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    AuthManager: FromRef<S>,
    Arc<LanforgeDb>: FromRef<S>,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> HttpResult<Self> {
        let auth_manager = AuthManager::from_ref(state);
        let db = Arc::<LanforgeDb>::from_ref(state);

        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| HttpError::Auth("Missing Authorization header".into()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(HttpError::Auth("Invalid Authorization header".into()));
        }

        let token = &auth_header[7..];

        // 1. Try validating as API Token from DB
        match db.validate_api_token(token).await {
            Ok(Some((name, scopes))) => {
                return Ok(Self {
                    name,
                    role: "admin".to_string(),
                    method: AuthMethod::ApiToken,
                    scopes,
                });
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("Database error during token validation: {e}");
                return Err(HttpError::Internal("Auth database error".into()));
            }
        }

        // 2. Try validating as JWT
        match auth_manager.validate_token(token) {
            Ok(claims) => Ok(Self {
                name: claims.sub,
                role: claims.role,
                method: AuthMethod::Jwt,
                scopes: lanforge_types::auth::ApiScopes::from_slice(&[
                    lanforge_types::auth::ApiScope::Admin,
                ]),
            }),
            Err(_) => Err(HttpError::Auth("Invalid or expired token".into())),
        }
    }
}

use crate::config::HttpConfig;

pub async fn middleware(
    State(cfg): State<Arc<HttpConfig>>,
    State(db): State<Arc<LanforgeDb>>,
    State(auth_manager): State<AuthManager>,
    mut req: Request<Body>,
    next: Next,
) -> HttpResult<AxumResponse> {
    let user_count = db.count_users().await.unwrap_or(0);
    // If no password hash is set AND no DB users exist, authentication is globally disabled.
    if cfg.auth_password_hash.is_none() && user_count == 0 {
        return Ok(next.run(req).await);
    }

    if req.method() == axum::http::Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    let path = req.uri().path();
    if path == "/api/v1/auth/validate"
        || path == "/v1/auth/validate"
        || path == "/api/auth/login"
        || path == "/auth/login"
        || path == "/api/v1/auth/login"
        || path == "/v1/auth/login"
        || path == "/api/v1/auth/status"
        || path == "/v1/auth/status"
        || path == "/api/auth/status"
        || path == "/auth/status"
    {
        return Ok(next.run(req).await);
    }

    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpError::Auth("Missing Authorization header".into()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(HttpError::Auth("Invalid Authorization header".into()));
    }

    let token = &auth_header[7..];

    let user = match db.validate_api_token(token).await {
        Ok(Some((name, scopes))) => AuthenticatedUser {
            name,
            role: "admin".to_string(),
            method: AuthMethod::ApiToken,
            scopes,
        },
        Ok(None) => match auth_manager.validate_token(token) {
            Ok(claims) => AuthenticatedUser {
                name: claims.sub,
                role: claims.role,
                method: AuthMethod::Jwt,
                scopes: lanforge_types::auth::ApiScopes::from_slice(&[
                    lanforge_types::auth::ApiScope::Admin,
                ]),
            },
            Err(_) => return Err(HttpError::Auth("Invalid or expired token".into())),
        },
        Err(e) => {
            tracing::error!("Database error during token validation: {e}");
            return Err(HttpError::Internal("Auth database error".into()));
        }
    };

    req.extensions_mut().insert(user);

    Ok(next.run(req).await)
}
