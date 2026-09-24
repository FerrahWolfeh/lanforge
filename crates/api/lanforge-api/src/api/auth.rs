use lanforge_types::auth::ApiScopes;

use super::common::{HttpDataResponse, HttpWrappedResponse};
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

impl HttpWrappedResponse for AuthTokenResponse {
    type Wrapper = HttpDataResponse<AuthTokenResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for AuthTokensResponse {
    type Wrapper = HttpDataResponse<AuthTokensResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

/// Payload for creating a new user account.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CreateUserPayload {
    pub username: String,
    pub password: String,
    pub role: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserResponse {
    pub user: lanforge_types::auth::UserInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserListResponse {
    pub users: Vec<lanforge_types::auth::UserInfo>,
}

impl HttpWrappedResponse for UserResponse {
    type Wrapper = HttpDataResponse<UserResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for UserListResponse {
    type Wrapper = HttpDataResponse<UserListResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}
