use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported response encodings.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// JSON line-based (standard).
    Json,
    /// Postcard binary (length-prefixed).
    Postcard,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Postcard => write!(f, "postcard"),
        }
    }
}

/// Supported compression algorithms.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// No compression.
    None,
    /// Zstd compression.
    Zstd,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Zstd => write!(f, "zstd"),
        }
    }
}

/// Daemon capabilities payload.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Capabilities {
    /// List of supported response encodings.
    pub encodings: Vec<Encoding>,
    /// List of supported compression algorithms.
    pub compression: Vec<Compression>,
}

/// A simple success result containing a message.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SimpleSuccess {
    /// Informational message about the operation.
    pub message: String,
}
