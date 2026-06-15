use lanforge_core::context::{EventCounters, LanforgeContext};
use lanforge_dns::server::DnsContext;
use lanforge_dns::telemetry::DnsStats;
use lanforge_types::device::{Device, Origin};
use lanforge_types::system::SystemStatus;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Generates a Prometheus-formatted metrics string.
#[must_use]
pub fn generate_metrics(ctx: &LanforgeContext, uptime_secs: u64) -> String {
    let mut out = String::with_capacity(4096);
    let (devices, v4_leases, v6_leases) = {
        let state = ctx.read();

        let devices: Vec<_> = state.devices().collect();
        let v4_leases = state.devices().filter(|d| d.v4.is_dynamic()).count();
        let v6_leases: usize = state
            .devices()
            .map(|d| d.v6.iter().filter(|s| s.is_dynamic()).count())
            .sum();

        drop(state);
        (devices, v4_leases, v6_leases)
    };
    let counters = ctx.counters();
    let status = ctx.get_status().unwrap_or_default();

    append_device_metrics(&mut out, &devices);
    append_dhcp_metrics(&mut out, ctx, &status, v4_leases, v6_leases);
    append_dns_metrics(&mut out, ctx);
    append_core_metrics(&mut out, counters);
    append_system_metrics(&mut out, &status, uptime_secs);

    out
}

fn append_device_metrics(out: &mut String, devices: &[Arc<Device>]) {
    out.push_str("# HELP lanforge_devices_total Total number of known devices in state table\n");
    out.push_str("# TYPE lanforge_devices_total gauge\n");
    let _ = writeln!(out, "lanforge_devices_total {}", devices.len());

    let online_ct = devices.iter().filter(|d| d.is_online()).count();
    out.push_str("# HELP lanforge_devices_online Number of devices seen recently (online)\n");
    out.push_str("# TYPE lanforge_devices_online gauge\n");
    let _ = writeln!(out, "lanforge_devices_online {online_ct}");

    let static_ct = devices
        .iter()
        .filter(|d| matches!(d.origin, Origin::Static))
        .count();
    let dyn_ct = devices
        .iter()
        .filter(|d| d.origin == Origin::Dynamic)
        .count();

    out.push_str("# HELP lanforge_devices_by_origin Number of devices by discovery origin\n");
    out.push_str("# TYPE lanforge_devices_by_origin gauge\n");
    let _ = writeln!(
        out,
        "lanforge_devices_by_origin{{origin=\"static\"}} {static_ct}"
    );
    let _ = writeln!(
        out,
        "lanforge_devices_by_origin{{origin=\"dynamic\"}} {dyn_ct}"
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

fn append_dns_metrics(out: &mut String, ctx: &LanforgeContext) {
    if let Some(stats) = ctx.get_service_state_ref::<DnsStats>("dns::stats") {
        let snap = stats.snapshot();
        out.push_str("# HELP lanforge_dns_queries_total Total DNS queries received\n");
        out.push_str("# TYPE lanforge_dns_queries_total counter\n");
        let _ = writeln!(out, "lanforge_dns_queries_total {}", snap.requests_total);

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

    if let Some(dns_ctx) = ctx.get_service_state_ref::<DnsContext>("dns::context") {
        out.push_str("# HELP lanforge_dns_upstream_rtt_us Round-trip time to upstream resolver in microseconds\n");
        out.push_str("# TYPE lanforge_dns_upstream_rtt_us gauge\n");
        out.push_str(
            "# HELP lanforge_dns_upstream_queries_total Total successful queries to upstream\n",
        );
        out.push_str("# TYPE lanforge_dns_upstream_queries_total counter\n");
        out.push_str(
            "# HELP lanforge_dns_upstream_failures_total Total failed queries to upstream\n",
        );
        out.push_str("# TYPE lanforge_dns_upstream_failures_total counter\n");

        for mgr in dns_ctx.recursive.all_upstreams() {
            let target = &mgr.target.addr.to_string();
            let proto = format!("{:?}", mgr.target.protocol).to_lowercase();
            let rtt = mgr.health.rtt_ewma_us.load(Ordering::Relaxed);
            let queries = mgr.health.total_successes.load(Ordering::Relaxed);
            let failures = mgr.health.total_failures.load(Ordering::Relaxed);

            let _ = writeln!(
                out,
                "lanforge_dns_upstream_rtt_us{{target=\"{target}\",proto=\"{proto}\"}} {rtt}"
            );
            let _ = writeln!(
                out,
                "lanforge_dns_upstream_queries_total{{target=\"{target}\",proto=\"{proto}\"}} {queries}"
            );
            let _ = writeln!(
                out,
                "lanforge_dns_upstream_failures_total{{target=\"{target}\",proto=\"{proto}\"}} {failures}"
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
        && let Ok(metadata) = std::fs::metadata(&status.db_path)
    {
        out.push_str("# HELP lanforge_db_size_bytes Size of the SQLite persistence database\n");
        out.push_str("# TYPE lanforge_db_size_bytes gauge\n");
        let _ = writeln!(
            out,
            "lanforge_db_size_bytes{{file=\"leases\"}} {}",
            metadata.len()
        );
    }
    if !status.log_db_path.is_empty()
        && let Ok(metadata) = std::fs::metadata(&status.log_db_path)
    {
        let _ = writeln!(
            out,
            "lanforge_db_size_bytes{{file=\"logs\"}} {}",
            metadata.len()
        );
    }

    if let Ok(stat) = std::fs::read_to_string("/proc/self/statm") {
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
