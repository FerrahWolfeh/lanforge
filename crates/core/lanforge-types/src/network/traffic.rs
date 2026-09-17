use serde::{Deserialize, Serialize};

/// Global traffic and NIC management configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrafficConfig {
    #[serde(default)]
    pub tuning: NicTuningConfig,
    #[serde(default)]
    pub sqm: SqmConfig,
}

/// NIC-level hardware, interrupt, and queuing optimization settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicTuningConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default = "default_auto")]
    pub cpu_mask: String,
    #[serde(default = "default_rps_flow_entries")]
    pub rps_flow_entries: u32,
    #[serde(default = "default_rps_flow_cnt")]
    pub rps_flow_cnt: u32,
    #[serde(default = "default_auto")]
    pub rx_ring: String,
    #[serde(default = "default_auto")]
    pub tx_ring: String,
    #[serde(default = "default_true")]
    pub disable_eee: bool,
    #[serde(default = "default_true")]
    pub udp_gro_forwarding: bool,
}

impl Default for NicTuningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interfaces: Vec::new(),
            cpu_mask: "auto".to_string(),
            rps_flow_entries: 32768,
            rps_flow_cnt: 4096,
            rx_ring: "auto".to_string(),
            tx_ring: "auto".to_string(),
            disable_eee: true,
            udp_gro_forwarding: true,
        }
    }
}

/// Smart Queue Management (SQM) / Bufferbloat shaper configuration (CAKE / `FQ_CoDel`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqmConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_auto")]
    pub interface: String,
    #[serde(default = "default_zero")]
    pub download_mbps: u32,
    #[serde(default = "default_zero")]
    pub upload_mbps: u32,
    #[serde(default)]
    pub overhead: SqmOverhead,
    #[serde(default)]
    pub diffserv: SqmDiffserv,
    #[serde(default = "default_true")]
    pub per_host_isolation: bool,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default = "default_auto")]
    pub ingress_device: String,
    #[serde(default)]
    pub raw_cake_args: Option<String>,
}

impl Default for SqmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "auto".to_string(),
            download_mbps: 0,
            upload_mbps: 0,
            overhead: SqmOverhead::Auto,
            diffserv: SqmDiffserv::Diffserv4,
            per_host_isolation: true,
            rtt_ms: None,
            ingress_device: "auto".to_string(),
            raw_cake_args: None,
        }
    }
}

/// Framing overhead compensation profiles for CAKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SqmOverhead {
    #[default]
    Auto,
    Pppoe,
    Ethernet,
    Docsis,
    None,
}

/// Diffserv classification profiles for CAKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SqmDiffserv {
    #[default]
    Diffserv4,
    Diffserv3,
    Besteffort,
}

const fn default_true() -> bool {
    true
}

const fn default_zero() -> u32 {
    0
}

fn default_auto() -> String {
    "auto".to_string()
}

const fn default_rps_flow_entries() -> u32 {
    32768
}

const fn default_rps_flow_cnt() -> u32 {
    4096
}
