use lanforge_types::auth::ApiScopes;
use serde::{Deserialize, Serialize};

/// Response containing a generated API token.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthTokenResponse {
    pub id: i64,
    /// The plaintext API token (only shown once upon generation).
    pub token: String,
    /// Human-readable name/label for this token.
    pub name: String,
    pub scopes: ApiScopes,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthTokenEntry {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub scopes: ApiScopes,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthTokensResponse {
    pub tokens: Vec<AuthTokenEntry>,
}
