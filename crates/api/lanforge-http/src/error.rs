#[cfg(feature = "server")]
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response as AxumResponse},
};
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
    Http(String),

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

    /// Service unavailable (e.g. database down).
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Client-provided value could not be parsed or is invalid.
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Generic catch-all error.
    #[error("Error: {0}")]
    Generic(String),
}

/// A specialized Result type for `lanforge-http`.
pub type Result<T> = std::result::Result<T, HttpError>;

#[cfg(feature = "server")]
impl IntoResponse for HttpError {
    fn into_response(self) -> AxumResponse {
        let (status, message) = match self {
            Self::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Rpc { status, message } => {
                let code =
                    StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                (code, message)
            }
            Self::Jwt(e) => (StatusCode::UNAUTHORIZED, e.to_string()),
            Self::Core(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            Self::BadRequest(msg) | Self::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(serde_json::json!({
            "error": message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}
