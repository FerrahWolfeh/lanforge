use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lanforge_types::network::traffic::{
    CakeQdiscStats, CakeTinStats, ConntrackStats, InterfaceThroughputPoint, InterfaceTrafficStats,
    SqmTelemetryStats, TrafficHistorySample, TrafficTelemetryResponse,
};
use serde::Deserialize;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::debug;

static COLLECTOR: OnceLock<Mutex<TrafficCollector>> = OnceLock::new();

/// Cached period for `tc` execution (2.5 seconds to avoid high fork rate on SBCs).
const SQM_CACHE_TTL: Duration = Duration::from_millis(2500);

/// Maximum number of historical samples preserved in memory (240 samples @ 2.5s = 10 minutes).
const MAX_HISTORY_SAMPLES: usize = 240;

/// Raw JSON structures for deserializing `tc -j -s qdisc show`.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RawTcQdisc {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    dev: String,
    #[serde(default)]
    bytes: u64,
    #[serde(default)]
    packets: u64,
    #[serde(default)]
    drops: u64,
    #[serde(default)]
    overlimits: u64,
    #[serde(default)]
    backlog: u64,
    #[serde(default)]
    qlen: u32,
    #[serde(default)]
    memory_used: u64,
    #[serde(default)]
    memory_limit: u64,
    #[serde(default)]
    capacity_estimate: u64,
    #[serde(default)]
    min_network_size: u32,
    #[serde(default)]
    max_network_size: u32,
    #[serde(default)]
    min_adj_size: u32,
    #[serde(default)]
    max_adj_size: u32,
    #[serde(default)]
    avg_hdr_offset: u32,
    #[serde(default)]
    options: Option<RawTcOptions>,
    #[serde(default)]
    tins: Vec<RawTcTin>,
}

#[derive(Debug, Deserialize)]
struct RawTcOptions {
    #[serde(default)]
    bandwidth: Option<serde_json::Value>,
    #[serde(default)]
    diffserv: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RawTcTin {
    #[serde(default)]
    threshold_rate: u64,
    #[serde(default)]
    sent_bytes: u64,
    #[serde(default)]
    sent_packets: u64,
    #[serde(default)]
    backlog_bytes: u64,
    #[serde(default)]
    target_us: u32,
    #[serde(default)]
    interval_us: u32,
    #[serde(default)]
    peak_delay_us: u32,
    #[serde(default)]
    avg_delay_us: u32,
    #[serde(default)]
    base_delay_us: u32,
    #[serde(default)]
    way_indirect_hits: u64,
    #[serde(default)]
    way_misses: u64,
    #[serde(default)]
    way_collisions: u64,
    #[serde(default)]
    drops: u64,
    #[serde(default)]
    ecn_mark: u64,
    #[serde(default)]
    ack_drops: u64,
    #[serde(default)]
    sparse_flows: u32,
    #[serde(default)]
    bulk_flows: u32,
    #[serde(default)]
    unresponsive_flows: u32,
}

pub struct TrafficCollector {
    prev_iface_snapshots: HashMap<String, (Instant, u64, u64)>,
    cached_sqm: Option<(Instant, Option<SqmTelemetryStats>)>,
    history: VecDeque<TrafficHistorySample>,
    proc_net_dev_buf: String,
}

impl TrafficCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            prev_iface_snapshots: HashMap::new(),
            cached_sqm: None,
            history: VecDeque::with_capacity(MAX_HISTORY_SAMPLES),
            proc_net_dev_buf: String::with_capacity(1024),
        }
    }

    /// Periodic telemetry tick: samples interface counters into the ring buffer
    /// without building the entire response or cloning history.
    pub async fn record_tick(&mut self, wan_iface: Option<&str>, ifb_iface: Option<&str>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let interfaces = self.collect_interfaces();

        if wan_iface.is_some() || ifb_iface.is_some() {
            let _ = self.collect_sqm(wan_iface, ifb_iface).await;
        }

        if !interfaces.is_empty() {
            let point = TrafficHistorySample {
                timestamp: now,
                interfaces: interfaces
                    .into_iter()
                    .map(|i| InterfaceThroughputPoint {
                        interface: i.interface,
                        rx_rate_bps: i.rx_rate_bps,
                        tx_rate_bps: i.tx_rate_bps,
                    })
                    .collect(),
            };

            if self.history.len() >= MAX_HISTORY_SAMPLES {
                self.history.pop_front();
            }
            self.history.push_back(point);
        }
    }

    /// Collects complete network telemetry payload (interfaces, conntrack, and SQM).
    pub async fn collect(
        &mut self,
        wan_iface: Option<&str>,
        ifb_iface: Option<&str>,
    ) -> TrafficTelemetryResponse {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let interfaces = self.collect_interfaces();
        let conntrack = read_conntrack_stats();
        let sqm = self.collect_sqm(wan_iface, ifb_iface).await;

        // Record historical slice if interfaces are populated
        if !interfaces.is_empty() {
            let point = TrafficHistorySample {
                timestamp: now,
                interfaces: interfaces
                    .iter()
                    .map(|i| InterfaceThroughputPoint {
                        interface: i.interface.clone(),
                        rx_rate_bps: i.rx_rate_bps,
                        tx_rate_bps: i.tx_rate_bps,
                    })
                    .collect(),
            };

            if self.history.len() >= MAX_HISTORY_SAMPLES {
                self.history.pop_front();
            }
            self.history.push_back(point);
        }

        let resolved_wan = wan_iface.map(String::from).or_else(|| {
            interfaces.iter().find_map(|i| {
                if i.interface == "ppp0" || i.interface == "wan0" || i.interface == "wan" {
                    Some(i.interface.clone())
                } else {
                    None
                }
            })
        });

        let resolved_ifb = ifb_iface.map(String::from).or_else(|| {
            sqm.as_ref()
                .and_then(|s| s.ingress.as_ref().map(|i| i.dev.clone()))
                .or_else(|| {
                    interfaces.iter().find_map(|i| {
                        if i.interface.starts_with("ifb") {
                            Some(i.interface.clone())
                        } else {
                            None
                        }
                    })
                })
        });

        TrafficTelemetryResponse {
            timestamp: now,
            interfaces,
            sqm,
            conntrack,
            history: self.history.iter().cloned().collect(),
            wan_interface: resolved_wan,
            ingress_device: resolved_ifb,
        }
    }

    /// Reads `/proc/net/dev` and calculates throughput rates based on elapsed time.
    fn collect_interfaces(&mut self) -> Vec<InterfaceTrafficStats> {
        self.proc_net_dev_buf.clear();
        if let Ok(mut file) = std::fs::File::open("/proc/net/dev") {
            use std::io::Read;
            if file.read_to_string(&mut self.proc_net_dev_buf).is_ok() {
                return parse_proc_net_dev(&self.proc_net_dev_buf, &mut self.prev_iface_snapshots);
            }
        }
        Vec::new()
    }

    /// Reads SQM CAKE statistics with caching to prevent excessive process forks.
    async fn collect_sqm(
        &mut self,
        wan_iface: Option<&str>,
        ifb_iface: Option<&str>,
    ) -> Option<SqmTelemetryStats> {
        if wan_iface.is_none() && ifb_iface.is_none() {
            return None;
        }

        let now = Instant::now();

        if let Some((cached_at, ref cached_res)) = self.cached_sqm
            && now.duration_since(cached_at) < SQM_CACHE_TTL
        {
            return cached_res.clone();
        }

        let qdiscs = fetch_tc_qdiscs().await;
        if qdiscs.is_empty() {
            self.cached_sqm = Some((now, None));
            return None;
        }

        let mut egress = None;
        let mut ingress = None;

        for q in qdiscs {
            if wan_iface.is_some_and(|wan| q.dev == wan) {
                egress = Some(q.clone());
            }
            if ifb_iface.is_some_and(|ifb| q.dev == ifb) {
                ingress = Some(q.clone());
            }
            // Heuristic fallbacks if exact wan/ifb wasn't configured:
            if egress.is_none() && (q.dev == "ppp0" || q.dev == "wan0") {
                egress = Some(q.clone());
            }
            if ingress.is_none() && q.dev.starts_with("ifb") {
                ingress = Some(q.clone());
            }
        }

        let active = egress.is_some() || ingress.is_some();
        let stats = SqmTelemetryStats {
            active,
            egress,
            ingress,
        };

        self.cached_sqm = Some((now, Some(stats.clone())));
        Some(stats)
    }
}

impl Default for TrafficCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Global entry point to record a background telemetry tick.
pub async fn record_traffic_telemetry_tick(wan_iface: Option<&str>, ifb_iface: Option<&str>) {
    let collector = COLLECTOR.get_or_init(|| Mutex::new(TrafficCollector::new()));
    collector
        .lock()
        .await
        .record_tick(wan_iface, ifb_iface)
        .await;
}

/// Global entry point to query telemetry.
pub async fn collect_traffic_telemetry(
    wan_iface: Option<&str>,
    ifb_iface: Option<&str>,
) -> TrafficTelemetryResponse {
    let collector = COLLECTOR.get_or_init(|| Mutex::new(TrafficCollector::new()));
    let mut guard = collector.lock().await;
    guard.collect(wan_iface, ifb_iface).await
}

/// Parses raw `/proc/net/dev` content and computes instantaneous rate.
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
pub fn parse_proc_net_dev<S: ::std::hash::BuildHasher>(
    content: &str,
    prev_snapshots: &mut HashMap<String, (Instant, u64, u64), S>,
) -> Vec<InterfaceTrafficStats> {
    let now = Instant::now();
    let mut results = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains(':') {
            continue;
        }

        let mut parts = trimmed.splitn(2, ':');
        let Some(iface_raw) = parts.next() else {
            continue;
        };
        let iface = iface_raw.trim();

        // Skip loopback interface from telemetry
        if iface == "lo" {
            continue;
        }

        let Some(data) = parts.next() else {
            continue;
        };

        let mut fields = data.split_whitespace();
        let Some(rx_bytes_str) = fields.next() else {
            continue;
        };
        let Some(rx_packets_str) = fields.next() else {
            continue;
        };
        let Some(rx_errors_str) = fields.next() else {
            continue;
        };
        let Some(rx_dropped_str) = fields.next() else {
            continue;
        };
        // Skip 4 fields (fifo, frame, compressed, multicast)
        if fields.nth(3).is_none() {
            continue;
        }
        let Some(tx_bytes_str) = fields.next() else {
            continue;
        };
        let Some(tx_packets_str) = fields.next() else {
            continue;
        };
        let Some(tx_errors_str) = fields.next() else {
            continue;
        };
        let Some(tx_dropped_str) = fields.next() else {
            continue;
        };

        let rx_bytes = rx_bytes_str.parse::<u64>().unwrap_or(0);
        let rx_packets = rx_packets_str.parse::<u64>().unwrap_or(0);
        let rx_errors = rx_errors_str.parse::<u64>().unwrap_or(0);
        let rx_dropped = rx_dropped_str.parse::<u64>().unwrap_or(0);

        let tx_bytes = tx_bytes_str.parse::<u64>().unwrap_or(0);
        let tx_packets = tx_packets_str.parse::<u64>().unwrap_or(0);
        let tx_errors = tx_errors_str.parse::<u64>().unwrap_or(0);
        let tx_dropped = tx_dropped_str.parse::<u64>().unwrap_or(0);

        let mut rx_rate_bps = 0;
        let mut tx_rate_bps = 0;

        if let Some((prev_time, prev_rx, prev_tx)) = prev_snapshots.get(iface) {
            let elapsed_secs = now.duration_since(*prev_time).as_secs_f64();
            if elapsed_secs > 0.05 {
                let delta_rx = rx_bytes.saturating_sub(*prev_rx);
                let delta_tx = tx_bytes.saturating_sub(*prev_tx);

                rx_rate_bps = ((delta_rx as f64 * 8.0) / elapsed_secs) as u64;
                tx_rate_bps = ((delta_tx as f64 * 8.0) / elapsed_secs) as u64;
            }
        }

        if let Some(entry) = prev_snapshots.get_mut(iface) {
            *entry = (now, rx_bytes, tx_bytes);
        } else {
            prev_snapshots.insert(iface.to_string(), (now, rx_bytes, tx_bytes));
        }

        results.push(InterfaceTrafficStats {
            interface: iface.to_string(),
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors,
            tx_errors,
            rx_dropped,
            tx_dropped,
            rx_rate_bps,
            tx_rate_bps,
        });
    }

    results.sort_by(|a, b| a.interface.cmp(&b.interface));
    results
}

fn read_sysctl_u32(path: &str) -> Option<u32> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 32];
    let n = file.read(&mut buf).ok()?;
    let s = std::str::from_utf8(&buf[..n]).ok()?.trim();
    s.parse::<u32>().ok()
}

/// Reads conntrack statistics from procfs.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
pub fn read_conntrack_stats() -> Option<ConntrackStats> {
    let active_connections = read_sysctl_u32("/proc/sys/net/netfilter/nf_conntrack_count")?;
    let max_connections =
        read_sysctl_u32("/proc/sys/net/netfilter/nf_conntrack_max").unwrap_or(65536);

    let utilization_percent = if max_connections > 0 {
        ((f64::from(active_connections) / f64::from(max_connections)) * 100.0) as f32
    } else {
        0.0
    };

    let mut stats = ConntrackStats {
        active_connections,
        max_connections,
        utilization_percent,
        search: 0,
        new: 0,
        drop: 0,
        invalid: 0,
    };

    // Optionally parse /proc/net/stat/nf_conntrack if readable
    if let Ok(stat_content) = std::fs::read_to_string("/proc/net/stat/nf_conntrack") {
        for line in stat_content.lines().skip(1) {
            let mut parts = [""; 12];
            let mut count = 0;
            for (slot, part) in parts.iter_mut().zip(line.split_whitespace()) {
                *slot = part;
                count += 1;
            }
            // entries: cpu, found, invalid, ignore, insert, insert_failed, drop, early_drop, error, search, new...
            if count >= 10 {
                let parse_hex = |s: &str| u64::from_str_radix(s, 16).unwrap_or(0);
                stats.invalid = stats.invalid.saturating_add(parse_hex(parts[1]));
                stats.drop = stats.drop.saturating_add(parse_hex(parts[5]));
                stats.search = stats.search.saturating_add(parse_hex(parts[8]));
                if count >= 11 {
                    stats.new = stats.new.saturating_add(parse_hex(parts[9]));
                }
            }
        }
    }

    Some(stats)
}

/// Runs `tc -j -s qdisc show` and parses all CAKE qdiscs.
async fn fetch_tc_qdiscs() -> Vec<CakeQdiscStats> {
    let tc_path = crate::sqm::tc::resolve_tc_binary();
    let output = match Command::new(tc_path)
        .args(["-j", "-s", "qdisc", "show"])
        .output()
        .await
    {
        Ok(out) => {
            if !out.status.success() {
                debug!("tc -j -s qdisc show exited with non-zero status");
                return Vec::new();
            }
            out.stdout
        }
        Err(e) => {
            debug!("Failed to run tc binary for telemetry: {e}");
            return Vec::new();
        }
    };

    let Ok(json_str) = std::str::from_utf8(&output) else {
        return Vec::new();
    };

    parse_tc_qdisc_json(json_str)
}

/// Parses the JSON output of `tc -j -s qdisc show`.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn parse_tc_qdisc_json(json_str: &str) -> Vec<CakeQdiscStats> {
    let raw_list: Vec<RawTcQdisc> = match serde_json::from_str(json_str) {
        Ok(l) => l,
        Err(e) => {
            debug!("Failed to deserialize tc qdisc json: {e}");
            return Vec::new();
        }
    };

    let mut results = Vec::new();

    for raw in raw_list {
        if raw.kind != "cake" {
            continue;
        }

        let bandwidth = match raw.options.as_ref().and_then(|o| o.bandwidth.as_ref()) {
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
            _ => 0,
        };

        let diffserv_mode = raw
            .options
            .as_ref()
            .and_then(|o| o.diffserv.as_deref())
            .unwrap_or("diffserv4");

        let tins = raw
            .tins
            .into_iter()
            .enumerate()
            .map(|(idx, tin)| {
                let name = match (diffserv_mode, idx) {
                    ("diffserv4" | "diffserv3", 0) => "Bulk",
                    ("diffserv4" | "diffserv3", 1) | ("besteffort", 0) => "Best Effort",
                    ("diffserv4", 2) => "Video",
                    ("diffserv4" | "diffserv3", 3) | ("diffserv3", 2) => "Voice",
                    _ => "",
                };
                let name_str = if name.is_empty() {
                    format!("Tin {idx}")
                } else {
                    name.to_string()
                };

                CakeTinStats {
                    tin_index: u8::try_from(idx).unwrap_or(255),
                    name: name_str,
                    threshold_rate: tin.threshold_rate,
                    sent_bytes: tin.sent_bytes,
                    sent_packets: tin.sent_packets,
                    backlog_bytes: tin.backlog_bytes,
                    peak_delay_us: tin.peak_delay_us,
                    avg_delay_us: tin.avg_delay_us,
                    base_delay_us: tin.base_delay_us,
                    drops: tin.drops,
                    ecn_mark: tin.ecn_mark,
                    ack_drops: tin.ack_drops,
                    sparse_flows: tin.sparse_flows,
                    bulk_flows: tin.bulk_flows,
                    unresponsive_flows: tin.unresponsive_flows,
                }
            })
            .collect();

        results.push(CakeQdiscStats {
            dev: raw.dev,
            kind: raw.kind,
            bandwidth,
            bytes: raw.bytes,
            packets: raw.packets,
            drops: raw.drops,
            overlimits: raw.overlimits,
            backlog: raw.backlog,
            qlen: raw.qlen,
            memory_used: raw.memory_used,
            memory_limit: raw.memory_limit,
            capacity_estimate: raw.capacity_estimate,
            tins,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tc_qdisc_json_live_payload() {
        let json = r#"[
            {"kind":"noqueue","handle":"0:","dev":"lo","root":true,"bytes":0,"packets":0,"drops":0},
            {"kind":"cake","handle":"8001:","dev":"ppp0","root":true,"options":{"bandwidth":50000000,"diffserv":"diffserv4"},"bytes":1537931590,"packets":1730112,"drops":56,"overlimits":829022,"memory_used":711110,"memory_limit":4194304,"tins":[
                {"threshold_rate":3125000,"sent_bytes":0,"sent_packets":0,"drops":0,"ecn_mark":0,"sparse_flows":0,"bulk_flows":0},
                {"threshold_rate":50000000,"sent_bytes":1537690545,"sent_packets":1728127,"drops":56,"ecn_mark":0,"peak_delay_us":7,"avg_delay_us":1,"sparse_flows":1,"bulk_flows":1}
            ]},
            {"kind":"cake","handle":"8002:","dev":"ifb4ppp0","root":true,"options":{"bandwidth":106250000,"diffserv":"diffserv4"},"bytes":6214061205,"packets":5237653,"drops":1110,"overlimits":1027059,"memory_used":1423292,"memory_limit":8500000,"tins":[
                {"threshold_rate":6640625,"sent_bytes":50732519,"sent_packets":211751,"drops":0,"ecn_mark":0,"peak_delay_us":437,"avg_delay_us":233,"sparse_flows":0,"bulk_flows":0},
                {"threshold_rate":106250000,"sent_bytes":6072902829,"sent_packets":4667290,"drops":1109,"ecn_mark":14,"peak_delay_us":494,"avg_delay_us":198,"sparse_flows":1,"bulk_flows":1}
            ]}
        ]"#;

        let parsed = parse_tc_qdisc_json(json);
        assert_eq!(parsed.len(), 2);

        let ppp0 = &parsed[0];
        assert_eq!(ppp0.dev, "ppp0");
        assert_eq!(ppp0.bandwidth, 50_000_000);
        assert_eq!(ppp0.drops, 56);
        assert_eq!(ppp0.tins.len(), 2);
        assert_eq!(ppp0.tins[0].name, "Bulk");
        assert_eq!(ppp0.tins[1].name, "Best Effort");
        assert_eq!(ppp0.tins[1].sent_packets, 1_728_127);

        let ifb = &parsed[1];
        assert_eq!(ifb.dev, "ifb4ppp0");
        assert_eq!(ifb.bandwidth, 106_250_000);
        assert_eq!(ifb.drops, 1110);
        assert_eq!(ifb.tins[1].ecn_mark, 14);
        assert_eq!(ifb.tins[1].avg_delay_us, 198);
        assert_eq!(ifb.tins[1].peak_delay_us, 494);
    }

    #[test]
    fn test_parse_proc_net_dev() {
        let content = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  lan0: 1000000   10000    0    0    0     0          0         0  2000000    15000    0    0    0     0       0          0\n  ppp0: 5000000   40000    0    0    0     0          0         0  1000000    20000    0    0    0     0       0          0\n    lo: 1234567   12345    0    0    0     0          0         0  1234567    12345    0    0    0     0       0          0\n";

        let mut prev = HashMap::new();
        let ifaces = parse_proc_net_dev(content, &mut prev);

        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].interface, "lan0");
        assert_eq!(ifaces[0].rx_bytes, 1_000_000);
        assert_eq!(ifaces[0].tx_bytes, 2_000_000);

        assert_eq!(ifaces[1].interface, "ppp0");
        assert_eq!(ifaces[1].rx_bytes, 5_000_000);
        assert_eq!(ifaces[1].tx_bytes, 1_000_000);
    }

    #[tokio::test]
    async fn test_collector_record_tick_and_history() {
        let mut collector = TrafficCollector::new();
        assert!(collector.history.is_empty());
        collector.record_tick(None, None).await;
        let resp = collector.collect(None, None).await;
        assert!(resp.wan_interface.is_none());
        assert!(resp.ingress_device.is_none());
    }
}
