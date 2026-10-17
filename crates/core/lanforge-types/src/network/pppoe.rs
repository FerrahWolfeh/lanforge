use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    None,
    Pap,
    #[default]
    #[serde(alias = "chapmd5", alias = "chap")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PppoeDataplane {
    /// Traditional Linux kernel data plane using /dev/ppp and `ppp_generic` module.
    #[default]
    Kernel,
    /// High-performance eBPF data plane using Generic XDP (SKB mode) and TC BPF.
    Ebpf,
}

impl std::fmt::Display for PppoeDataplane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kernel => write!(f, "kernel"),
            Self::Ebpf => write!(f, "ebpf"),
        }
    }
}

impl std::str::FromStr for PppoeDataplane {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "kernel" | "linux" | "k" => Ok(Self::Kernel),
            "ebpf" | "xdp" | "bpf" => Ok(Self::Ebpf),
            other => Err(format!("Unknown dataplane: {other}")),
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
    pub masquerade: bool,
    pub custom_rules_file: Option<String>,
    pub lan_ifaces: Vec<String>,
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
            masquerade: true,
            custom_rules_file: None,
            lan_ifaces: Vec::new(),
        }
    }
}

/// Configuration for the optional GPON ONT / modem underlay probe (Layer 2 ARP).
///
/// Opt-in. The probe is a *soft gate*: if the terminal does not answer within
/// `max_wait_secs`, `PPPoE` dials anyway. It must never block the WAN indefinitely.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct TerminalProbeConfig {
    pub enabled: bool,
    /// Management IP of the ONT / modem (e.g. `192.168.1.1`).
    pub target_ip: Ipv4Addr,
    /// Optional sender IP inside the ARP payload. `None` = `0.0.0.0` (RFC 5227 probe).
    pub sender_ip: Option<Ipv4Addr>,
    /// Interface used for probing. `None` = parent of `wan_iface`
    /// (e.g. `wan0` when `PPPoE` runs on `wan0.10`), since ONT management is usually untagged.
    pub iface: Option<String>,
    /// Per-probe ARP reply timeout.
    pub timeout_ms: u64,
    /// Interval between probes while waiting for the terminal.
    pub poll_interval_secs: u64,
    /// Soft-gate deadline: after this, dial `PPPoE` regardless of probe result.
    pub max_wait_secs: u64,
}

impl Default for TerminalProbeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            sender_ip: None,
            iface: None,
            timeout_ms: 1000,
            poll_interval_secs: 2,
            max_wait_secs: 10,
        }
    }
}

/// Configuration structure for `PPPoE` service.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct PppoeConfig {
    pub enabled: bool,
    pub dataplane: PppoeDataplane,
    pub wan_iface: String,
    pub username: String,
    pub password: String,
    pub service_name: Option<String>,
    pub ac_name: Option<String>,
    pub auth: AuthMethod,
    pub mru: u16,
    pub lcp_echo_interval_secs: u64,
    pub lcp_echo_max_failures: u32,
    pub reconnect_delay_secs: u64,
    pub send_padt_on_shutdown: bool,
    pub discovery_padi_retries: u32,
    pub discovery_padi_timeout_secs: u64,
    pub terminal_probe: TerminalProbeConfig,
    pub nftables: PppoeNftablesConfig,
}

impl Default for PppoeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dataplane: PppoeDataplane::Kernel,
            wan_iface: "eth1".into(),
            username: String::new(),
            password: String::new(),
            service_name: None,
            ac_name: None,
            auth: AuthMethod::ChapMd5,
            mru: 1492,
            lcp_echo_interval_secs: 20,
            lcp_echo_max_failures: 5,
            reconnect_delay_secs: 10,
            send_padt_on_shutdown: true,
            discovery_padi_retries: 5,
            discovery_padi_timeout_secs: 3,
            terminal_probe: TerminalProbeConfig::default(),
            nftables: PppoeNftablesConfig::default(),
        }
    }
}

