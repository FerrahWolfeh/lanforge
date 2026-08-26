use std::net::AddrParseError;
use thiserror::Error;

/// Lab Workbench error enumeration.
#[derive(Debug, Error)]
pub enum LabError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Socket error: {0}")]
    Socket(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Timeout waiting for response from {0}")]
    Timeout(String),

    #[error("Netns management error: {0}")]
    Netns(String),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] AddrParseError),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Assertion failed: {0}")]
    Assertion(String),

    #[error("Root privileges required: {0}")]
    RootRequired(String),

    #[error("Operation cancelled")]
    Cancelled,
}
