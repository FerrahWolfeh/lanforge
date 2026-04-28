/// Configuration for the Unix Domain Socket (UDS) control service.
///
/// This struct is defined within the API crate to allow isolated use,
/// independent of the main daemon's internal configuration structures.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Filesystem path to the Unix socket (e.g., "/run/lanforge/control.sock").
    pub socket_path: String,

    /// Name of the LAN interface reported in status (e.g., "eth0").
    pub lan_iface: String,

    /// Whether Router Advertisements (RA) are enabled.
    pub ra_enabled: bool,

    /// The announced ULA prefix (e.g., "fd00::/64"), if any.
    pub ula_prefix: Option<String>,

    /// Whether the DHCPv4 service is enabled.
    pub dhcp_v4_enabled: bool,

    /// Whether the DHCPv6 service is enabled.
    pub dhcp_v6_enabled: bool,

    /// Whether the DNS service is enabled.
    pub dns_enabled: bool,

    /// The configured upstream DNS resolver.
    pub dns_upstream: Option<String>,

    /// Path to the SQLite database (used for calculating file size stats).
    pub db_path: String,
    /// Database connection URL.
    pub db_url: String,
    /// Path to the SQLite database for logs (history).
    pub log_db_path: String,
    /// Log database connection URL.
    pub log_db_url: String,

    /// Optional TCP port for the control API (debug).
    pub tcp_port: Option<u16>,

    /// Optional address to listen for the HTTP REST API (e.g., "0.0.0.0:8080").
    #[cfg(feature = "http")]
    pub http_listen: Option<String>,

    /// Total number of addresses in the DHCPv4 dynamic pool.
    pub dhcp_v4_range_size: u32,
    /// Total number of addresses in the DHCPv6 dynamic pool (if finite).
    pub dhcp_v6_pool_size: Option<u64>,

    /// Secure hash of the API password.
    #[cfg(feature = "http")]
    pub auth_password_hash: Option<String>,

    /// Native TLS certificate (Path or raw PEM).
    #[cfg(feature = "http")]
    pub tls_cert: Option<String>,

    /// Native TLS private key (Path or raw PEM).
    #[cfg(feature = "http")]
    pub tls_key: Option<String>,
}

#[cfg(test)]
impl ApiConfig {
    /// Creates a dummy configuration for testing purposes.
    pub fn dummy() -> Self {
        Self {
            socket_path: "/tmp/lanforge.sock".to_string(),
            lan_iface: "eth0".to_string(),
            ra_enabled: true,
            ula_prefix: None,
            dhcp_v4_enabled: true,
            dhcp_v6_enabled: true,
            dns_enabled: true,
            dns_upstream: None,
            db_path: "/tmp/leases.db".to_string(),
            db_url: "sqlite:///tmp/leases.db".to_string(),
            log_db_path: "/tmp/lanforge_logs.db".to_string(),
            log_db_url: "sqlite:///tmp/lanforge_logs.db".to_string(),
            tcp_port: None,
            #[cfg(feature = "http")]
            http_listen: None,
            dhcp_v4_range_size: 100,
            dhcp_v6_pool_size: Some(100),
            #[cfg(feature = "http")]
            auth_password_hash: None,
            #[cfg(feature = "http")]
            tls_cert: None,
            #[cfg(feature = "http")]
            tls_key: None,
        }
    }
}
