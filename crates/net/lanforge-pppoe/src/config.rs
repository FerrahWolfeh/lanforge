use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AuthMethod {
    None,
    Pap,
    #[default]
    ChapMd5,
}

/// Configuration structure for `PPPoE` service.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct PppoeConfig {
    pub enabled: bool,
    pub wan_iface: String,
    pub username: String,
    pub password: String,
    pub auth: AuthMethod,
    pub mru: u16,
    pub lcp_echo_interval_secs: u64,
    pub lcp_echo_max_failures: u32,
    pub reconnect_delay_secs: u64,
}

impl Default for PppoeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            wan_iface: "eth1".into(),
            username: String::new(),
            password: String::new(),
            auth: AuthMethod::ChapMd5,
            mru: 1492,
            lcp_echo_interval_secs: 10,
            lcp_echo_max_failures: 3,
            reconnect_delay_secs: 10,
        }
    }
}

/// Decoupled credentials handle, ready for future DB integration.
#[derive(Debug, Clone)]
pub struct PppoeCredentials {
    pub username: String,
    pub password: String,
    pub auth: AuthMethod,
}
