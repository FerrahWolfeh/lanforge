use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use rand::RngExt;

use crate::harness::LabHarness;

/// Visual action item in the TUI menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabAction {
    DhcpDora,
    Ipv6Ra,
    DnsQuery,
    DiscoveryPing,
    DhcpStorm,
    DnsFlood,
    RunSuite,
}

impl LabAction {
    pub const ALL: [Self; 7] = [
        Self::DhcpDora,
        Self::Ipv6Ra,
        Self::DnsQuery,
        Self::DiscoveryPing,
        Self::DhcpStorm,
        Self::DnsFlood,
        Self::RunSuite,
    ];

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::DhcpDora => "1. DHCP DORA Client Flow",
            Self::Ipv6Ra => "2. IPv6 Router Advertisement (RA)",
            Self::DnsQuery => "3. DNS & Adblock Query",
            Self::DiscoveryPing => "4. Discovery / RTT Probe",
            Self::DhcpStorm => "5. ⚡ DHCP Storm Benchmark",
            Self::DnsFlood => "6. ⚡ DNS Flood Benchmark",
            Self::RunSuite => "7. 🧪 Run Regression Suite",
        }
    }

    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::DhcpDora => "Simulate a client joining LAN (Discover -> Offer -> Request -> Ack)",
            Self::Ipv6Ra => "Send Router Solicitation (RS) and decode IPv6 prefixes & RDNSS",
            Self::DnsQuery => "Send DNS query to test local resolution, upstream and adblocking",
            Self::DiscoveryPing => "Probe round-trip time and connectivity to target server",
            Self::DhcpStorm => "Stress test DHCP server with concurrent client DORA cycles",
            Self::DnsFlood => "High-QPS DNS flood benchmark measuring latency percentiles",
            Self::RunSuite => "Execute automated regression test suite across all subsystems",
        }
    }

    #[must_use]
    pub const fn requires_root(self) -> bool {
        matches!(self, Self::Ipv6Ra)
    }
}

/// TUI State Manager.
pub struct App {
    pub selected_index: usize,
    pub logs: Arc<Mutex<VecDeque<String>>>,
    pub running: bool,
    pub is_busy: bool,
    pub is_root: bool,
    pub status_message: String,
    pub dhcp_server: SocketAddr,
    pub dns_server: SocketAddr,
    pub mode_str: String,
}

impl App {
    #[must_use]
    pub fn new(dhcp_server: SocketAddr, dns_server: SocketAddr, mode_str: String) -> Self {
        let is_root = crate::is_root();
        let logs = Arc::new(Mutex::new(VecDeque::with_capacity(200)));
        logs.lock().push_back("● Lanforge Lab Workbench initialized. Press [1..7] or Enter to run an action.".to_string());
        if !is_root {
            logs.lock().push_back("ℹ Running in unprivileged (rootless) mode. Root-only features (IPv6 RA) are disabled.".to_string());
        }

        Self {
            selected_index: 0,
            logs,
            running: true,
            is_busy: false,
            is_root,
            status_message: "Ready".to_string(),
            dhcp_server,
            dns_server,
            mode_str,
        }
    }

    pub fn add_log(&self, msg: impl Into<String>) {
        let mut l = self.logs.lock();
        if l.len() >= 200 {
            l.pop_front();
        }
        l.push_back(msg.into());
    }

    pub fn next_action(&mut self) {
        self.selected_index = (self.selected_index + 1) % LabAction::ALL.len();
    }

    pub fn previous_action(&mut self) {
        if self.selected_index == 0 {
            self.selected_index = LabAction::ALL.len() - 1;
        } else {
            self.selected_index -= 1;
        }
    }

    #[must_use]
    pub fn current_action(&self) -> LabAction {
        LabAction::ALL[self.selected_index]
    }

    /// Triggers the specified action asynchronously.
    pub fn trigger_action(&mut self, action: LabAction, harness: Arc<LabHarness>) {
        if self.is_busy {
            return;
        }

        if action.requires_root() && !self.is_root {
            self.status_message = format!("Blocked: {} requires root (sudo)", action.title());
            self.add_log(format!(
                "✖ [GUARD] '{}' requires root privileges (CAP_NET_RAW). Re-run lanforge-lab with sudo.",
                action.title()
            ));
            return;
        }

        self.is_busy = true;
        self.status_message = format!("Running {}...", action.title());
        let logs = self.logs.clone();

        tokio::spawn(async move {
            match action {
                LabAction::DhcpDora => {
                    let b = rand::rng().random_range(10..=250);
                    let mac = lanforge_types::identifiers::MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, b]);
                    logs.lock().push_back(format!("-> [DHCP] Simulating client {mac} (hostname: 'lab-device-{b}')..."));

                    match harness.dhcp().simulate_dora(mac, Some(&format!("lab-device-{b}"))).await {
                        Ok(res) if res.success => {
                            let ip = res.assigned_ip.map_or_else(|| "none".to_string(), |i| i.to_string());
                            let mask = res.subnet_mask.map_or_else(|| "none".to_string(), |i| i.to_string());
                            let rtr = res.router.map_or_else(|| "none".to_string(), |i| i.to_string());
                            let lease = res.lease_time_secs.unwrap_or(0);
                            logs.lock().push_back(format!("<- [DHCP] ACK Received: IP={ip}, Mask={mask}, Gateway={rtr}, Lease={lease}s in {:.2}ms", res.total_time_ms));
                        }
                        Ok(res) => {
                            logs.lock().push_back(format!("✖ [DHCP] DORA failed: {:?}", res.error));
                        }
                        Err(e) => {
                            logs.lock().push_back(format!("✖ [DHCP] Error: {e}"));
                        }
                    }
                }
                LabAction::Ipv6Ra => {
                    logs.lock().push_back("-> [RA] Sending Router Solicitation (RS) to ff02::2...".to_string());
                    match harness.ra().send_rs_and_await_ra().await {
                        Ok(ra) => {
                            logs.lock().push_back(format!("<- [RA] Received from {}: {} prefix(es), RDNSS: {:?} in {:.2}ms", ra.router_ip, ra.prefixes.len(), ra.rdnss_servers, ra.latency_ms));
                            for p in &ra.prefixes {
                                logs.lock().push_back(format!("   • Prefix: {}/{} (On-Link: {}, Auto: {})", p.prefix, p.prefix_len, p.on_link, p.auto_config));
                            }
                        }
                        Err(e) => {
                            logs.lock().push_back(format!("✖ [RA] Error: {e}"));
                        }
                    }
                }
                LabAction::DnsQuery => {
                    let domains = ["lanforge.lan", "doubleclick.net", "google.com"];
                    for d in domains {
                        logs.lock().push_back(format!("-> [DNS] Querying '{d}' (A record)..."));
                        match harness.dns().query(d, lanforge_types::network::dns::DnsRecordType::A).await {
                            Ok(res) => {
                                let blk = if res.is_blocked { " [ADBLOCK BLOCKED]" } else { "" };
                                logs.lock().push_back(format!("<- [DNS] '{d}' -> RCODE: {}, Answers: {:?}{} in {} µs", res.rcode, res.answers, blk, res.latency_us));
                            }
                            Err(e) => {
                                logs.lock().push_back(format!("✖ [DNS] Error querying '{d}': {e}"));
                            }
                        }
                    }
                }
                LabAction::DiscoveryPing => {
                    logs.lock().push_back("-> [PROBE] Sending connectivity probe...".to_string());
                    match crate::engine::DiscoveryEngine::probe_rtt(harness.dhcp_target).await {
                        Ok(dur) => {
                            logs.lock().push_back(format!("<- [PROBE] RTT against {}: {:.2} ms", harness.dhcp_target, dur.as_secs_f64() * 1000.0));
                        }
                        Err(e) => {
                            logs.lock().push_back(format!("✖ [PROBE] Error: {e}"));
                        }
                    }
                }
                LabAction::DhcpStorm => {
                    logs.lock().push_back("-> [STORM] Running DHCP Storm (30 clients, concurrency 5)...".to_string());
                    match harness.dhcp().storm_benchmark(30, 5).await {
                        Ok(rep) => {
                            logs.lock().push_back(format!("<- [STORM] Complete: {}/{} success, Throughput: {:.1} DORA/s, p50: {:.2}ms, p99: {:.2}ms", rep.successful_leases, rep.total_clients, rep.throughput_dora_per_sec, rep.p50_latency_ms, rep.p99_latency_ms));
                        }
                        Err(e) => {
                            logs.lock().push_back(format!("✖ [STORM] Error: {e}"));
                        }
                    }
                }
                LabAction::DnsFlood => {
                    logs.lock().push_back("-> [FLOOD] Running DNS Flood (1,000 queries)...".to_string());
                    match harness.dns().flood_benchmark(1000, std::time::Duration::from_secs(1), &[]).await {
                        Ok(rep) => {
                            logs.lock().push_back(format!("<- [FLOOD] Complete: {}/{} success, Actual QPS: {:.1}, p50: {} µs, p99: {} µs, Blocked: {}", rep.successful_queries, rep.total_queries, rep.actual_qps, rep.p50_latency_us, rep.p99_latency_us, rep.blocked_count));
                        }
                        Err(e) => {
                            logs.lock().push_back(format!("✖ [FLOOD] Error: {e}"));
                        }
                    }
                }
                LabAction::RunSuite => {
                    logs.lock().push_back("-> [SUITE] Running full regression test suite...".to_string());
                    match harness.run_full_suite().await {
                        Ok(rep) => {
                            let status = if rep.all_passed { "ALL TESTS PASSED ✓" } else { "SOME TESTS FAILED ✖" };
                            logs.lock().push_back(format!("<- [SUITE] {status} (DHCP: {}, DNS Local: {}, DNS Adblock: {}, DNS Upstream: {})", rep.dhcp_dora_passed, rep.dns_local_passed, rep.dns_adblock_passed, rep.dns_upstream_passed));
                        }
                        Err(e) => {
                            logs.lock().push_back(format!("✖ [SUITE] Error: {e}"));
                        }
                    }
                }
            }
        });

        self.is_busy = false;
        self.status_message = "Ready".to_string();
    }
}
