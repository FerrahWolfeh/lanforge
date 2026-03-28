use thiserror::Error;

/// Errors that can occur during API operations.
#[derive(Error, Debug)]
pub enum ApiError {
    /// Standard I/O error (e.g., socket communication issues).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Error during JSON serialization or deserialization.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Error receiving an event from the internal broadcast bus.
    #[error("Bus receive error: {0}")]
    Bus(#[from] tokio::sync::broadcast::error::RecvError),

    /// Failed to clean up an old stale socket file.
    #[error("Failed to remove old socket at {path}: {source}")]
    SocketCleanup {
        /// The path that failed cleanup.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to create the directory containing the Unix socket.
    #[error("Failed to create socket directory {path}: {source}")]
    DirCreation {
        /// The directory path that failed creation.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to bind the Unix listener to the specified path.
    #[error("Failed to bind Unix socket at {path}: {source}")]
    Bind {
        /// The path where binding was attempted.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// A specialized Result type for API operations.
pub type Result<T> = std::result::Result<T, ApiError>;
