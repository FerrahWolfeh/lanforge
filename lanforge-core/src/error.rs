use thiserror::Error;

/// Central error type for the `lanforge-core` crate.
///
/// This error is used for shared logic, state management, and service orchestration.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Service error: {0}")]
    ServiceError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Generic error: {0}")]
    Generic(String),

    #[error("Internal bus error: {0}")]
    BusError(String),

    #[error("Shutdown requested")]
    Shutdown,
}

pub type Result<T> = std::result::Result<T, CoreError>;
