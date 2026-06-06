use thiserror::Error;

/// Unified error type for the `lanforge-http` crate.
#[derive(Error, Debug)]
pub enum HttpError {
    /// Standard I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Core logic error from `lanforge-core`.
    #[cfg(feature = "server")]
    #[error("Core error: {0}")]
    Core(#[from] lanforge_core::error::CoreError),

    /// JWT error (server-side).
    #[cfg(feature = "server")]
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// HTTP client error (remote-side).
    #[cfg(feature = "client")]
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    /// URL parse error (remote-side).
    #[cfg(feature = "client")]
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// Authentication failure.
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// RPC or remote API failure.
    #[error("Remote RPC failed (status {status}): {message}")]
    Rpc {
        /// HTTP status code returned by the server.
        status: u16,
        /// Error message from the server.
        message: String,
    },

    /// System time or duration calculation error.
    #[error("Time error: {0}")]
    Time(String),

    /// Generic internal error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Client-provided value could not be parsed or is invalid.
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Generic catch-all error.
    #[error("Error: {0}")]
    Generic(String),
}

/// A specialized Result type for `lanforge-http`.
pub type Result<T> = std::result::Result<T, HttpError>;
