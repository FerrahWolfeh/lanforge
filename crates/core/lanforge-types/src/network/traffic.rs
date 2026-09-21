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

/// Detailed throughput and packet counters for a single network interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InterfaceTrafficStats {
    pub interface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_rate_bps: u64,
    pub tx_rate_bps: u64,
}

/// Statistics for a single `DiffServ` priority queue / tin in CAKE.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CakeTinStats {
    pub tin_index: u8,
    pub name: String,
    pub threshold_rate: u64,
    pub sent_bytes: u64,
    pub sent_packets: u64,
    pub backlog_bytes: u64,
    pub peak_delay_us: u32,
    pub avg_delay_us: u32,
    pub base_delay_us: u32,
    pub drops: u64,
    pub ecn_mark: u64,
    pub ack_drops: u64,
    pub sparse_flows: u32,
    pub bulk_flows: u32,
    pub unresponsive_flows: u32,
}

/// Real-time statistics of a CAKE queuing discipline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CakeQdiscStats {
    pub dev: String,
    pub kind: String,
    pub bandwidth: u64,
    pub bytes: u64,
    pub packets: u64,
    pub drops: u64,
    pub overlimits: u64,
    pub backlog: u64,
    pub qlen: u32,
    pub memory_used: u64,
    pub memory_limit: u64,
    pub capacity_estimate: u64,
    pub tins: Vec<CakeTinStats>,
}

/// Aggregated SQM telemetry (egress on WAN + ingress on IFB).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SqmTelemetryStats {
    pub active: bool,
    pub egress: Option<CakeQdiscStats>,
    pub ingress: Option<CakeQdiscStats>,
}

/// Kernel Netfilter conntrack table statistics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ConntrackStats {
    pub active_connections: u32,
    pub max_connections: u32,
    pub utilization_percent: f32,
    #[serde(default)]
    pub search: u64,
    #[serde(default)]
    pub new: u64,
    #[serde(default)]
    pub drop: u64,
    #[serde(default)]
    pub invalid: u64,
}

/// Per-interface instantaneous throughput rate within a historical snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InterfaceThroughputPoint {
    pub interface: String,
    pub rx_rate_bps: u64,
    pub tx_rate_bps: u64,
}

/// Historical network telemetry sample representing a single timestamp slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrafficHistorySample {
    pub timestamp: u64,
    pub interfaces: Vec<InterfaceThroughputPoint>,
}

/// Complete real-time traffic, SQM, and conntrack telemetry payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TrafficTelemetryResponse {
    pub timestamp: u64,
    pub interfaces: Vec<InterfaceTrafficStats>,
    pub sqm: Option<SqmTelemetryStats>,
    pub conntrack: Option<ConntrackStats>,
    #[serde(default)]
    pub history: Vec<TrafficHistorySample>,
}

