use std::net::SocketAddr;

use lanforge_macros::ServiceConfig;
use serde::{Deserialize, Serialize};

/// Configuration for the REST API and Metrics HTTP service.
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "http")]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct HttpConfig {
    /// Whether the HTTP service is enabled.
    pub enabled: bool,
    /// Listen address (e.g., "0.0.0.0:9090").
    pub listen: SocketAddr,
    /// Whether HTTPS is explicitly enabled.
    pub https_enabled: bool,
    /// Whether plaintext HTTP is explicitly allowed (for local development only).
    pub allow_plaintext_http: bool,
    /// Whether `DoH` (DNS-over-HTTPS) is explicitly enabled.
    pub doh_enabled: bool,
    /// TLS certificate path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    /// TLS private key path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,

    /// Secure hash of the API password.
    pub auth_password_hash: Option<String>,
    /// Directory for serving PXE/boot files.
    pub boot_dir: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:9090".parse().unwrap(),
            https_enabled: false,
            allow_plaintext_http: false,
            doh_enabled: false,
            tls_cert: None,
            tls_key: None,
            auth_password_hash: None,
            boot_dir: None,
        }
    }
}
