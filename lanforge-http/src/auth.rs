use crate::error::{HttpError, Result as HttpResult};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT Claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (e.g., "admin")
    pub exp: usize,  // Expiration
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

// Using lanforge_core::utils::auth::hash_password
// Using lanforge_core::utils::auth::verify_password

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

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
            .get(axum::http::header::AUTHORIZATION)
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
