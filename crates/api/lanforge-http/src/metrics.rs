use std::fmt::Write;
use std::fs;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::timeout;

use lanforge_core::context::{EventCounters, LanforgeContext};
use lanforge_types::device::Origin;
use lanforge_types::network::dns::{
    DnsRequest, DnsResponse, DnsStatsResponse, UpstreamHealthSnapshot,
};
use lanforge_types::system::SystemStatus;

/// How long a scrape waits for the DNS service; past it the DNS section is left out.
const DNS_SCRAPE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Default)]
struct DeviceMetricsSummary {
    total: usize,
    online: usize,
    static_count: usize,
    dynamic_count: usize,
    v4_leases: usize,
    v6_leases: usize,
}

/// DNS counters and upstream health, asked through the `DnsHandle` like any other client.
#[derive(Default)]
struct DnsMetrics {
    stats: Option<DnsStatsResponse>,
    upstreams: Vec<UpstreamHealthSnapshot>,
}

async fn fetch_dns_metrics(ctx: &LanforgeContext) -> DnsMetrics {
    let Some(handle) = ctx.dns_handle() else {
        return DnsMetrics::default();
    };
    let ask = |req| {
        let handle = handle.clone();
        async move {
            timeout(DNS_SCRAPE_TIMEOUT, handle.send_request(req))
                .await
                .ok()
                .and_then(Result::ok)
        }
    };
    let (stats, upstreams) = tokio::join!(ask(DnsRequest::Stats), ask(DnsRequest::Upstreams));
    DnsMetrics {
        stats: match stats {
            Some(DnsResponse::Stats(s)) => Some(s),
            _ => None,
        },
        upstreams: match upstreams {
            Some(DnsResponse::Upstreams(u)) => u,
            _ => Vec::new(),
        },
    }
}

/// Generates a Prometheus-formatted metrics string.
pub async fn generate_metrics(ctx: &LanforgeContext, uptime_secs: u64) -> String {
    let dns = fetch_dns_metrics(ctx).await;
    let mut out = String::with_capacity(4096);
    let summary = ctx.with_state(|state| {
        let mut summary = DeviceMetricsSummary::default();
        for dev in state.devices.values() {
            summary.total += 1;
            if dev.is_online() {
                summary.online += 1;
            }
            match dev.origin {
                Origin::Static => summary.static_count += 1,
                Origin::Dynamic => summary.dynamic_count += 1,
                Origin::System => {}
            }
            if dev.v4.is_dynamic() {
                summary.v4_leases += 1;
            }
            summary.v6_leases += dev.v6.iter().filter(|s| s.is_dynamic()).count();
        }
        summary
    });
    let counters = ctx.counters();
    let status = ctx.get_status().unwrap_or_default();

    append_device_metrics(&mut out, &summary);
    append_dhcp_metrics(&mut out, ctx, &status, summary.v4_leases, summary.v6_leases);
    append_dns_metrics(&mut out, &dns);
    append_core_metrics(&mut out, counters);
    append_system_metrics(&mut out, &status, uptime_secs);

    out
}

fn append_device_metrics(out: &mut String, summary: &DeviceMetricsSummary) {
    out.push_str("# HELP lanforge_devices_total Total number of known devices in state table\n");
    out.push_str("# TYPE lanforge_devices_total gauge\n");
    let _ = writeln!(out, "lanforge_devices_total {}", summary.total);

    out.push_str("# HELP lanforge_devices_online Number of devices seen recently (online)\n");
    out.push_str("# TYPE lanforge_devices_online gauge\n");
    let _ = writeln!(out, "lanforge_devices_online {}", summary.online);

    out.push_str("# HELP lanforge_devices_by_origin Number of devices by discovery origin\n");
    out.push_str("# TYPE lanforge_devices_by_origin gauge\n");
    let _ = writeln!(
        out,
        "lanforge_devices_by_origin{{origin=\"static\"}} {}",
        summary.static_count
    );
    let _ = writeln!(
        out,
        "lanforge_devices_by_origin{{origin=\"dynamic\"}} {}",
        summary.dynamic_count
    );
}

fn append_dhcpv4_packet_metrics(out: &mut String, ctx: &LanforgeContext) {
    let v4_stats = ctx.dhcpv4_stats().snapshot();
    out.push_str(
        "# HELP lanforge_dhcp_packets_total Total DHCP packets processed/sent by message type\n",
    );
    out.push_str("# TYPE lanforge_dhcp_packets_total counter\n");
    let _ = writeln!(
        out,
        "lanforge_dhcp_packets_total{{proto=\"v4\",msg_type=\"discover\"}} {}",
        v4_stats.discovers
    );
    let _ = writeln!(
        out,
        "lanforge_dhcp_packets_total{{proto=\"v4\",msg_type=\"offer\"}} {}",
        v4_stats.offers
    );
    let _ = writeln!(
        out,
        "lanforge_dhcp_packets_total{{proto=\"v4\",msg_type=\"request\"}} {}",
        v4_stats.requests
    );
    let _ = writeln!(
        out,
        "lanforge_dhcp_packets_total{{proto=\"v4\",msg_type=\"ack\"}} {}",
        v4_stats.acks
    );
    let _ = writeln!(
        out,
        "lanforge_dhcp_packets_total{{proto=\"v4\",msg_type=\"nak\"}} {}",
        v4_stats.naks
    );
    let _ = writeln!(
        out,
        "lanforge_dhcp_packets_total{{proto=\"v4\",msg_type=\"release\"}} {}",
        v4_stats.releases
    );
    let _ = writeln!(
        out,
        "lanforge_dhcp_packets_total{{proto=\"v4\",msg_type=\"decline\"}} {}",
        v4_stats.declines
    );
    let _ = writeln!(
        out,
        "lanforge_dhcp_packets_total{{proto=\"v4\",msg_type=\"inform\"}} {}",
        v4_stats.informs
    );
}

fn append_dhcpv6_packet_metrics(out: &mut String, ctx: &LanforgeContext) {
    let v6_stats = ctx.dhcpv6_stats().snapshot();
    out.push_str("# HELP lanforge_dhcpv6_packets_total Total DHCPv6 packets processed/sent by message type\n");
    out.push_str("# TYPE lanforge_dhcpv6_packets_total counter\n");
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"solicit\"}} {}",
        v6_stats.solicits
    );
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"advertise\"}} {}",
        v6_stats.advertises
    );
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"request\"}} {}",
        v6_stats.requests
    );
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"reply\"}} {}",
        v6_stats.replies
    );
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"renew\"}} {}",
        v6_stats.renews
    );
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"rebind\"}} {}",
        v6_stats.rebinds
    );
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"release\"}} {}",
        v6_stats.releases
    );
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"decline\"}} {}",
        v6_stats.declines
    );
    let _ = writeln!(
        out,
        "lanforge_dhcpv6_packets_total{{proto=\"v6\",msg_type=\"info_request\"}} {}",
        v6_stats.info_requests
    );
}

#[allow(clippy::cast_precision_loss)]
fn append_dhcp_metrics(
    out: &mut String,
    ctx: &LanforgeContext,
    status: &SystemStatus,
    v4_leases: usize,
    v6_leases: usize,
) {
    append_dhcpv4_packet_metrics(out, ctx);
    append_dhcpv6_packet_metrics(out, ctx);

    out.push_str("# HELP lanforge_dhcp_leases_active Total active dynamic leases\n");
    out.push_str("# TYPE lanforge_dhcp_leases_active gauge\n");
    let _ = writeln!(
        out,
        "lanforge_dhcp_leases_active{{proto=\"v4\"}} {v4_leases}"
    );
    let _ = writeln!(
        out,
        "lanforge_dhcp_leases_active{{proto=\"v6\"}} {v6_leases}"
    );

    if status.dhcp_v4_range_size > 0 {
        let ratio = (v4_leases as f64) / (f64::from(status.dhcp_v4_range_size));
        out.push_str(
            "# HELP lanforge_dhcp_pool_usage_ratio Ratio of IP pool currently allocated\n",
        );
        out.push_str("# TYPE lanforge_dhcp_pool_usage_ratio gauge\n");
        let _ = writeln!(
            out,
            "lanforge_dhcp_pool_usage_ratio{{proto=\"v4\"}} {ratio:.4}"
        );
    }

    if let Some(pool_size) = status.dhcp_v6_pool_size
        && pool_size > 0
    {
        let ratio = (v6_leases as f64) / (pool_size as f64);
        let _ = writeln!(
            out,
            "lanforge_dhcp_pool_usage_ratio{{proto=\"v6\"}} {ratio:.4}"
        );
    }
}

fn append_dns_metrics(out: &mut String, dns: &DnsMetrics) {
    if let Some(snap) = &dns.stats {
        out.push_str("# HELP lanforge_dns_queries_total Total DNS queries received\n");
        out.push_str("# TYPE lanforge_dns_queries_total counter\n");
        let _ = writeln!(out, "lanforge_dns_queries_total {}", snap.total_requests);

        out.push_str("# HELP lanforge_dns_cache_hits_total DNS queries answered from cache\n");
        out.push_str("# TYPE lanforge_dns_cache_hits_total counter\n");
        let _ = writeln!(out, "lanforge_dns_cache_hits_total {}", snap.cache_hits);

        out.push_str("# HELP lanforge_dns_auth_answers_total DNS queries answered authoritatively (local hostnames)\n");
        out.push_str("# TYPE lanforge_dns_auth_answers_total counter\n");
        let _ = writeln!(out, "lanforge_dns_auth_answers_total {}", snap.auth_queries);

        out.push_str(
            "# HELP lanforge_dns_upstream_errors_total DNS queries that failed at upstream\n",
        );
        out.push_str("# TYPE lanforge_dns_upstream_errors_total counter\n");
        let _ = writeln!(
            out,
            "lanforge_dns_upstream_errors_total {}",
            snap.upstream_errors
        );
    }

    if dns.stats.is_some() {
        out.push_str("# HELP lanforge_dns_upstream_rtt_us Round-trip time to upstream resolver in microseconds\n");
        out.push_str("# TYPE lanforge_dns_upstream_rtt_us gauge\n");
        out.push_str(
            "# HELP lanforge_dns_upstream_queries_total Client queries sent to the upstream\n",
        );
        out.push_str("# TYPE lanforge_dns_upstream_queries_total counter\n");
        out.push_str(
            "# HELP lanforge_dns_upstream_wins_total Answers from the upstream that resolved the query\n",
        );
        out.push_str("# TYPE lanforge_dns_upstream_wins_total counter\n");
        out.push_str(
            "# HELP lanforge_dns_upstream_failures_total Total failed queries to upstream\n",
        );
        out.push_str("# TYPE lanforge_dns_upstream_failures_total counter\n");

        for up in &dns.upstreams {
            let target = up.target;
            let proto = format!("{:?}", up.protocol).to_lowercase();
            let _ = writeln!(
                out,
                "lanforge_dns_upstream_rtt_us{{target=\"{target}\",proto=\"{proto}\"}} {}",
                up.rtt_ewma_us
            );
            let _ = writeln!(
                out,
                "lanforge_dns_upstream_queries_total{{target=\"{target}\",proto=\"{proto}\"}} {}",
                up.total_queries
            );
            let _ = writeln!(
                out,
                "lanforge_dns_upstream_wins_total{{target=\"{target}\",proto=\"{proto}\"}} {}",
                up.total_wins
            );
            let _ = writeln!(
                out,
                "lanforge_dns_upstream_failures_total{{target=\"{target}\",proto=\"{proto}\"}} {}",
                up.total_failures
            );
        }
    }
}

fn append_core_metrics(out: &mut String, counters: &EventCounters) {
    out.push_str("# HELP lanforge_events_total Total internal events processed by core\n");
    out.push_str("# TYPE lanforge_events_total counter\n");
    let _ = writeln!(
        out,
        "lanforge_events_total{{type=\"arp\"}} {}",
        counters.arp_seen.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "lanforge_events_total{{type=\"ndp\"}} {}",
        counters.ndp_seen.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "lanforge_events_total{{type=\"slaac\"}} {}",
        counters.slaac_observed.load(Ordering::Relaxed)
    );
}

fn append_system_metrics(out: &mut String, status: &SystemStatus, uptime_secs: u64) {
    out.push_str("# HELP lanforge_uptime_seconds Daemon uptime in seconds\n");
    out.push_str("# TYPE lanforge_uptime_seconds counter\n");
    let _ = writeln!(out, "lanforge_uptime_seconds {uptime_secs}");

    if !status.db_path.is_empty()
        && let Ok(metadata) = fs::metadata(&status.db_path)
    {
        out.push_str("# HELP lanforge_db_size_bytes Size of the persistence database\n");
        out.push_str("# TYPE lanforge_db_size_bytes gauge\n");
        let _ = writeln!(
            out,
            "lanforge_db_size_bytes{{file=\"leases\"}} {}",
            metadata.len()
        );
    }
    if !status.log_db_path.is_empty()
        && let Ok(metadata) = fs::metadata(&status.log_db_path)
    {
        let _ = writeln!(
            out,
            "lanforge_db_size_bytes{{file=\"logs\"}} {}",
            metadata.len()
        );
    }

    if let Ok(stat) = fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = stat.split_whitespace().collect();
        if let Some(rss_pages) = parts.get(1).and_then(|s| s.parse::<u64>().ok()) {
            let rss_bytes = rss_pages * 4096;
            out.push_str(
                "# HELP lanforge_memory_rss_bytes Resident set size of the daemon process\n",
            );
            out.push_str("# TYPE lanforge_memory_rss_bytes gauge\n");
            let _ = writeln!(out, "lanforge_memory_rss_bytes {rss_bytes}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lanforge_core::bus::EventBus;
    use lanforge_core::context::state::State;
    use lanforge_types::network::dns::UpstreamStatus;
    use lanforge_types::network::dns::upstream::UpstreamProtocol;

    use super::*;

    /// The DNS section comes from the `DnsHandle` (the DNS service's public interface), not
    /// from its internal context: a fake service answering the handle is all it needs.
    #[tokio::test]
    async fn dns_section_is_served_through_the_handle() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let mut rx = ctx.take_dns_requests();
        tokio::spawn(async move {
            while let Some((req, resp_tx)) = rx.recv().await {
                let resp = match req {
                    DnsRequest::Stats => DnsResponse::Stats(DnsStatsResponse {
                        total_requests: 42,
                        cache_hits: 7,
                        ..DnsStatsResponse::default()
                    }),
                    DnsRequest::Upstreams => DnsResponse::Upstreams(vec![UpstreamHealthSnapshot {
                        target: "9.9.9.9:53".parse().unwrap(),
                        protocol: UpstreamProtocol::Udp,
                        rtt_ewma_us: 1500,
                        last_rtt_us: 1400,
                        total_queries: 10,
                        total_successes: 9,
                        total_failures: 1,
                        total_wins: 8,
                        status: UpstreamStatus::Healthy,
                        last_success_secs_ago: Some(1),
                        domain: None,
                    }]),
                    _ => continue,
                };
                let _ = resp_tx.send(resp);
            }
        });

        let out = generate_metrics(&ctx, 1).await;
        assert!(out.contains("lanforge_dns_queries_total 42"), "{out}");
        assert!(out.contains("lanforge_dns_cache_hits_total 7"));
        assert!(out.contains(
            "lanforge_dns_upstream_failures_total{target=\"9.9.9.9:53\",proto=\"udp\"} 1"
        ));
        assert!(out.contains(
            "lanforge_dns_upstream_queries_total{target=\"9.9.9.9:53\",proto=\"udp\"} 10"
        ));
        assert!(
            out.contains("lanforge_dns_upstream_wins_total{target=\"9.9.9.9:53\",proto=\"udp\"} 8")
        );
    }

    /// A DNS that does not answer leaves its section out instead of stalling the scrape.
    #[tokio::test]
    async fn silent_dns_does_not_stall_the_scrape() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let _rx = ctx.take_dns_requests();
        let out = timeout(Duration::from_secs(3), generate_metrics(&ctx, 1))
            .await
            .expect("scrape returns");
        assert!(!out.contains("lanforge_dns_queries_total"));
        assert!(out.contains("lanforge_uptime_seconds 1"));
    }
}
