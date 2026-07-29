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

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Pap => write!(f, "pap"),
            Self::ChapMd5 => write!(f, "chap_md5"),
        }
    }
}

impl std::str::FromStr for AuthMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "pap" => Ok(Self::Pap),
            "chap_md5" | "chap" | "chapmd5" => Ok(Self::ChapMd5),
            other => Err(format!("Unknown auth method: {other}")),
        }
    }
}

/// Configuration for `nftables` performance tuning on the gateway interface.
#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct PppoeNftablesConfig {
    pub enabled: bool,
    pub table_name: String,
    pub flow_offload: bool,
    pub mss_clamping: bool,
    pub bypass_dns: bool,
    pub bypass_vowifi: bool,
    pub custom_rules_file: Option<String>,
}

impl Default for PppoeNftablesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            table_name: "lanforge".into(),
            flow_offload: true,
            mss_clamping: true,
            bypass_dns: true,
            bypass_vowifi: true,
            custom_rules_file: None,
        }
    }
}

/// Configuration structure for `PPPoE` service.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
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
    pub nftables: PppoeNftablesConfig,
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
            nftables: PppoeNftablesConfig::default(),
        }
    }
}

