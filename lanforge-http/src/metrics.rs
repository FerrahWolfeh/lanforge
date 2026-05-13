use lanforge_api::config::ApiConfig;
use lanforge_core::context::{EventCounters, LanforgeContext};
use lanforge_core::types::device::{Device, Origin};
use lanforge_dns::server::DnsContext;
use lanforge_dns::telemetry::DnsStats;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Generates a Prometheus-formatted metrics string.
#[must_use]
pub fn generate_metrics(ctx: &LanforgeContext, cfg: &ApiConfig, uptime_secs: u64) -> String {
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

    append_device_metrics(&mut out, &devices);
    append_dhcp_metrics(&mut out, cfg, v4_leases, v6_leases);
    append_dns_metrics(&mut out, ctx);
    append_core_metrics(&mut out, counters);
    append_system_metrics(&mut out, cfg, uptime_secs);

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
    let cli_ct = devices.iter().filter(|d| d.origin == Origin::Cli).count();
    let sys_ct = devices
        .iter()
        .filter(|d| d.origin == Origin::System)
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
    let _ = writeln!(out, "lanforge_devices_by_origin{{origin=\"cli\"}} {cli_ct}");
    let _ = writeln!(
        out,
        "lanforge_devices_by_origin{{origin=\"system\"}} {sys_ct}"
    );
    let _ = writeln!(
        out,
        "lanforge_devices_by_origin{{origin=\"dynamic\"}} {dyn_ct}"
    );
}

#[allow(clippy::cast_precision_loss)]
fn append_dhcp_metrics(out: &mut String, cfg: &ApiConfig, v4_leases: usize, v6_leases: usize) {
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

    if cfg.dhcp_v4_range_size > 0 {
        let ratio = (v4_leases as f64) / (f64::from(cfg.dhcp_v4_range_size));
        out.push_str(
            "# HELP lanforge_dhcp_pool_usage_ratio Ratio of IP pool currently allocated\n",
        );
        out.push_str("# TYPE lanforge_dhcp_pool_usage_ratio gauge\n");
        let _ = writeln!(
            out,
            "lanforge_dhcp_pool_usage_ratio{{proto=\"v4\"}} {ratio:.4}"
        );
    }

    if let Some(pool_size) = cfg.dhcp_v6_pool_size
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
    if let Some(stats_any) = ctx.get_dns_stats()
        && let Some(stats) = stats_any.downcast_ref::<DnsStats>()
    {
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

    if let Some(dns_ctx_any) = ctx.get_dns_context()
        && let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>()
    {
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

fn append_system_metrics(out: &mut String, cfg: &ApiConfig, uptime_secs: u64) {
    out.push_str("# HELP lanforge_uptime_seconds Daemon uptime in seconds\n");
    out.push_str("# TYPE lanforge_uptime_seconds counter\n");
    let _ = writeln!(out, "lanforge_uptime_seconds {uptime_secs}");

    if let Ok(metadata) = std::fs::metadata(&cfg.db_path) {
        out.push_str("# HELP lanforge_db_size_bytes Size of the SQLite persistence database\n");
        out.push_str("# TYPE lanforge_db_size_bytes gauge\n");
        let _ = writeln!(
            out,
            "lanforge_db_size_bytes{{file=\"leases\"}} {}",
            metadata.len()
        );
    }
    if let Ok(metadata) = std::fs::metadata(&cfg.log_db_path) {
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
