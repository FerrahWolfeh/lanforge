use serde::{Deserialize, Serialize};

/// Configuration for the Unix Domain Socket (UDS) control service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    /// Whether the control API is enabled.
    pub enabled: bool,
    /// Filesystem path to the Unix socket (e.g., "/run/lanforge/control.sock").
    pub socket_path: String,
    /// Optional TCP port for the control API (debug).
    pub tcp_port: Option<u16>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: "/run/lanforge/control.sock".to_string(),
            tcp_port: None,
        }
    }
}

#[cfg(test)]
impl ApiConfig {
    /// Creates a dummy configuration for testing purposes.
    pub fn test_default() -> Self {
        Self {
            enabled: true,
            socket_path: "/tmp/lanforge_test.sock".to_string(),
            tcp_port: None,
        }
    }
}
