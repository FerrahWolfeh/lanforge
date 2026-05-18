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

/// JWT Claims (Legacy/Internal).
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (e.g., "admin")
    pub exp: usize,  // Expiration
}

/// Represents an authenticated user (either via JWT or API Token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub name: String,
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
        // Generate a random 32-byte secret for this session.
        // Tokens will not survive a daemon restart.
        let secret = rand::random::<[u8; 32]>();
        Self {
            encoding_key: EncodingKey::from_secret(&secret),
            decoding_key: DecodingKey::from_secret(&secret),
        }
    }

    pub fn generate_token(&self, username: &str) -> HttpResult<String> {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| HttpError::Time(e.to_string()))?
            .as_secs()
            + 86400; // 24 hours

        let claims = Claims {
            sub: username.to_string(),
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

        // Extract the token from the Authorization header
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

use lanforge_db::engine::LeaseDb;
use std::sync::Arc;

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    AuthManager: FromRef<S>,
    Arc<LeaseDb>: FromRef<S>,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> HttpResult<Self> {
        let auth_manager = AuthManager::from_ref(state);
        let db = Arc::<LeaseDb>::from_ref(state);

        // Extract the token from the Authorization header
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
                    method: AuthMethod::ApiToken,
                    scopes,
                });
            }
            Ok(None) => {} // Continue to JWT
            Err(e) => {
                tracing::error!("Database error during token validation: {e}");
                return Err(HttpError::Internal("Auth database error".into()));
            }
        }

        // 2. Try validating as JWT
        match auth_manager.validate_token(token) {
            Ok(claims) => Ok(Self {
                name: claims.sub,
                method: AuthMethod::Jwt,
                scopes: lanforge_types::auth::ApiScopes::from_slice(&[lanforge_types::auth::ApiScope::Admin]),
            }),
            Err(_) => Err(HttpError::Auth("Invalid or expired token".into())),
        }
    }
}

use crate::config::HttpConfig;

pub async fn middleware(
    State(cfg): State<Arc<HttpConfig>>,
    State(db): State<Arc<LeaseDb>>,
    State(auth_manager): State<AuthManager>,
    mut req: Request<Body>,
    next: Next,
) -> HttpResult<AxumResponse> {
    // If no password hash is set, authentication is globally disabled.
    if cfg.auth_password_hash.is_none() {
        return Ok(next.run(req).await);
    }

    if req.method() == axum::http::Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    let path = req.uri().path();
    if path == "/api/v1/auth/validate" || path == "/api/auth/login" || path == "/api/v1/auth/login" {
        return Ok(next.run(req).await);
    }

    // Extract token
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpError::Auth("Missing Authorization header".into()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(HttpError::Auth("Invalid Authorization header".into()));
    }

    let token = &auth_header[7..];

    // Validate
    let user = match db.validate_api_token(token).await {
        Ok(Some((name, scopes))) => AuthenticatedUser {
            name,
            method: AuthMethod::ApiToken,
            scopes,
        },
        Ok(None) => {
            // Try JWT
            match auth_manager.validate_token(token) {
                Ok(claims) => AuthenticatedUser {
                    name: claims.sub,
                    method: AuthMethod::Jwt,
                    scopes: lanforge_types::auth::ApiScopes::from_slice(&[lanforge_types::auth::ApiScope::Admin]),
                },
                Err(_) => return Err(HttpError::Auth("Invalid or expired token".into())),
            }
        }
        Err(e) => {
            tracing::error!("Database error during token validation: {e}");
            return Err(HttpError::Internal("Auth database error".into()));
        }
    };

    // Store user in extensions for handlers to use if needed
    req.extensions_mut().insert(user);

    Ok(next.run(req).await)
}
