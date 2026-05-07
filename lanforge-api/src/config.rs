use std::net::SocketAddr;

use lanforge_db::config::DatabaseConfig;
use lanforge_macros::ServiceConfig;
use serde::{Deserialize, Serialize};

/// Configuration for the Unix Domain Socket (UDS) control service.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "api")]
#[serde(default)]
pub struct ApiConfig {
    /// Whether the control API is enabled.
    pub enabled: bool,
    /// Whether the HTTP API is enabled.
    pub http_enabled: bool,
    /// Filesystem path to the Unix socket (e.g., "/run/lanforge/control.sock").
    pub socket_path: String,
    /// Optional TCP port for the control API (debug).
    pub tcp_port: Option<u16>,
    /// Optional listen address for the HTTP API (reporting only).
    pub http_listen: Option<SocketAddr>,

    /// Secure hash of the API password (shared with HTTP).
    pub auth_password_hash: Option<String>,

    /// Database configuration for status reporting.
    #[serde(skip)]
    pub database: DatabaseConfig,

    // --- Reporting / Status fields ---
    #[serde(skip)]
    pub db_path: String,
    #[serde(skip)]
    pub db_url: String,
    #[serde(skip)]
    pub log_db_url: String,
    #[serde(skip)]
    pub lan_iface: String,
    #[serde(skip)]
    pub ula_prefix: Option<String>,
    #[serde(skip)]
    pub ra_enabled: bool,
    #[serde(skip)]
    pub dhcp_v4_enabled: bool,
    #[serde(skip)]
    pub dhcp_v4_range_size: u32,
    #[serde(skip)]
    pub dhcp_v6_enabled: bool,
    #[serde(skip)]
    pub dhcp_v6_pool_size: Option<u64>,
    #[serde(skip)]
    pub dns_enabled: bool,
    #[serde(skip)]
    pub dns_upstream: Option<String>,
    #[serde(skip)]
    pub boot_dir: Option<String>,
    #[serde(skip)]
    pub tls_cert: Option<String>,
    #[serde(skip)]
    pub tls_key: Option<String>,
    #[serde(skip)]
    pub log_db_path: String,
    #[serde(skip)]
    pub dot_listen: Option<SocketAddr>,
    #[serde(skip)]
    pub dot_enabled: bool,
    #[serde(skip)]
    pub doh_enabled: bool,
    #[serde(skip)]
    pub https_enabled: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            http_enabled: false,
            socket_path: "/run/lanforge/control.sock".to_string(),
            tcp_port: None,
            http_listen: None,
            auth_password_hash: None,
            database: DatabaseConfig::default(),
            db_path: String::new(),
            db_url: String::new(),
            log_db_url: String::new(),
            lan_iface: "eth0".to_string(),
            ula_prefix: None,
            ra_enabled: false,
            dhcp_v4_enabled: false,
            dhcp_v4_range_size: 0,
            dhcp_v6_enabled: false,
            dhcp_v6_pool_size: None,
            dns_enabled: false,
            dns_upstream: None,
            boot_dir: None,
            tls_cert: None,
            tls_key: None,
            log_db_path: String::new(),
            dot_listen: None,
            dot_enabled: false,
            doh_enabled: false,
            https_enabled: false,
        }
    }
}

/// Configuration for the REST API and Metrics HTTP service.
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "http")]
#[serde(default)]
pub struct HttpConfig {
    /// Whether the HTTP service is enabled.
    pub enabled: bool,
    /// Listen address (e.g., "0.0.0.0:8080").
    pub listen: SocketAddr,
    /// Whether HTTPS is explicitly enabled.
    pub https_enabled: bool,
    /// Whether `DoH` (DNS-over-HTTPS) is explicitly enabled.
    pub doh_enabled: bool,
    /// TLS certificate path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    /// TLS private key path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:8080".parse().unwrap(),
            https_enabled: false,
            doh_enabled: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

#[cfg(test)]
impl ApiConfig {
    /// Creates a dummy configuration for testing purposes.
    #[must_use]
    pub fn dummy() -> Self {
        Self::default()
    }
}
