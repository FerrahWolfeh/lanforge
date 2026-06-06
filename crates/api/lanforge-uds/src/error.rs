use lanforge_db::error::LanforgeDbError;
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
}

/// A specialized Result type for API operations.
pub type Result<T> = std::result::Result<T, UdsError>;
