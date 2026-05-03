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

    /// Error during Bincode serialization or deserialization.
    #[error("Bincode error: {0}")]
    Bincode(String),

    /// Error during Zstd compression or decompression.
    #[error("Zstd error: {0}")]
    Zstd(String),

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

    /// Failed to bind the Unix listener or TCP listener.
    #[error("Failed to bind socket at {path}: {source}")]
    Bind {
        /// The path or address where binding was attempted.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Configuration error (e.g., invalid address).
    #[error("API Configuration error: {message}")]
    Config { message: String },
    /// Generic internal server error.
    #[error("Internal API error: {message}")]
    Internal { message: String },
    /// TLS configuration or handshake error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Generic error string.
    #[error("API error: {0}")]
    Generic(String),
}

/// A specialized Result type for API operations.
pub type Result<T> = std::result::Result<T, ApiError>;
