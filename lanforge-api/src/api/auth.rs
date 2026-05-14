use serde::{Deserialize, Serialize};

/// Response containing a generated API token.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthTokenResponse {
    /// The plaintext API token (only shown once upon generation).
    pub token: String,
    /// Human-readable name/label for this token.
    pub name: String,
}
