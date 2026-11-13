//! Error types for the `lanforge-core` crate.
//!
//! This module defines the central error enum [`CoreError`], which covers all failure modes
//! across shared logic, state management, and service orchestration.
//!
//! # Example
//!
//! ```rust
//! use lanforge_core::error::CoreError;
//!
//! fn do_something() -> Result<(), CoreError> {
//!     // ...
//!     Err(CoreError::Generic("something went wrong".into()))
//! }
//! ```

use std::io;

use lanforge_types::network::bind::BindError;

use thiserror::Error;

/// Central error type for the `lanforge-core` crate.
///
/// This error is used for shared logic, state management, and service orchestration.
/// All variants implement [`std::fmt::Display`] via `thiserror`.
///
/// # Variants
///
/// - **[`ServiceError`](CoreError::ServiceError)**: Failures in service execution or lifecycle.
/// - **[`Io`](CoreError::Io)**: Wraps [`std::io::Error`] for filesystem/network errors.
/// - **[`Internal`](CoreError::Internal)**: Unrecoverable internal state inconsistencies.
/// - **[`Generic`](CoreError::Generic)**: Catch-all for uncategorized errors.
/// - **[`BusError`](CoreError::BusError)**: Event bus communication failures.
/// - **[`Shutdown`](CoreError::Shutdown)**: Graceful shutdown was requested.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Error originating from a service's execution.
    #[error("Service error: {0}")]
    ServiceError(String),

    /// Wraps standard I/O errors (e.g., file access, network).
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// A socket could not be opened; the supervisor acts on its kind.
    #[error(transparent)]
    Bind(#[from] BindError),

    /// Indicates an internal invariant was violated.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Generic uncategorized error.
    #[error("Generic error: {0}")]
    Generic(String),

    /// Event bus communication failure.
    #[error("Internal bus error: {0}")]
    BusError(String),

    /// Graceful shutdown was requested; operations should halt.
    #[error("Shutdown requested")]
    Shutdown,
}

impl CoreError {
    /// The socket that could not be opened, whether it came as a [`CoreError::Bind`] or inside
    /// an `io::Error` from a caller that speaks io.
    #[must_use]
    pub fn bind_error(&self) -> Option<&BindError> {
        match self {
            Self::Bind(e) => Some(e),
            Self::Io(e) => e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<BindError>()),
            _ => None,
        }
    }
}
