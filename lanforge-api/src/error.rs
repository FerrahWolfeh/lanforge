use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Bus receive error: {0}")]
    Bus(#[from] tokio::sync::broadcast::error::RecvError),

    #[error("Failed to remove old socket at {path}: {source}")]
    SocketCleanup {
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to create socket directory {path}: {source}")]
    DirCreation {
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to bind Unix socket at {path}: {source}")]
    Bind {
        path: String,
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, ApiError>;
