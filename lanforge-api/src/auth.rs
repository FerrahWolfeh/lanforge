use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
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
    pub fn new() -> Self {
        // Generate a random 32-byte secret for this session.
        // Tokens will not survive a daemon restart.
        let secret = rand::random::<[u8; 32]>();
        Self {
            encoding_key: EncodingKey::from_secret(&secret),
            decoding_key: DecodingKey::from_secret(&secret),
        }
    }

    pub fn generate_token(&self, username: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86400; // 24 hours

        let claims = Claims {
            sub: username.to_string(),
            exp: expiration as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
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

/// Hashes a plaintext password using Argon2id.
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

/// Verifies a plaintext password against an Argon2id hash.
pub fn verify_password(hash: &str, password: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
};

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
    AuthManager: FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_manager = AuthManager::from_ref(state);

        // Extract the token from the Authorization header
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED, "Invalid Authorization header"));
        }

        let token = &auth_header[7..];

        auth_manager
            .validate_token(token)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))
    }
}
