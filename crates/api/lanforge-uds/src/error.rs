use lanforge_db::error::LanforgeDbError;
use lanforge_db::log_engine::LogBufError;
use thiserror::Error;

/// Errors that can occur during API operations.
#[derive(Error, Debug)]
pub enum UdsError {
    /// Standard I/O error (e.g., socket communication issues).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Error during data encoding.
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Error during database operations.
    #[error("Database error: {0}")]
    Database(#[from] LanforgeDbError),

    /// Error during transient log buffer operations.
    #[error("Log buffer error: {0}")]
    LogBuf(#[from] LogBufError),
}

/// A specialized Result type for API operations.
pub type Result<T> = std::result::Result<T, UdsError>;
