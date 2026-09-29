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

    /// Error during database or storage operations.
    #[error("Storage error: {0}")]
    Storage(String),
}

/// A specialized Result type for API operations.
pub type Result<T> = std::result::Result<T, UdsError>;
