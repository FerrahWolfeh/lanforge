use crate::config::ApiConfig;
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::Origin;
use lanforge_dns::stats::DnsStats;

/// Generates a Prometheus-formatted metrics string.
pub fn generate_metrics(ctx: &LanforgeContext, cfg: &ApiConfig, uptime_secs: u64) -> String {
    let mut out = String::with_capacity(4096);
    let state = ctx.read();
    let devices: Vec<_> = state.devices().collect();
    let counters = ctx.counters();

    // 1. Device Discovery Metrics
    out.push_str("# HELP lanforge_devices_total Total number of known devices in state table\n");
    out.push_str("# TYPE lanforge_devices_total gauge\n");
    out.push_str(&format!("lanforge_devices_total {}\n", devices.len()));

    let online_ct = devices.iter().filter(|d| d.is_online()).count();
    out.push_str("# HELP lanforge_devices_online Number of devices seen recently (online)\n");
    out.push_str("# TYPE lanforge_devices_online gauge\n");
    out.push_str(&format!("lanforge_devices_online {}\n", online_ct));

    let toml_ct = devices.iter().filter(|d| d.origin == Origin::Toml).count();
    let cli_ct = devices.iter().filter(|d| d.origin == Origin::Cli).count();
    let dyn_ct = devices
        .iter()
        .filter(|d| d.origin == Origin::Dynamic)
        .count();

    out.push_str("# HELP lanforge_devices_by_origin Number of devices by discovery origin\n");
    out.push_str("# TYPE lanforge_devices_by_origin gauge\n");
    out.push_str(&format!(
        "lanforge_devices_by_origin{{origin=\"toml\"}} {}\n",
        toml_ct
    ));
    out.push_str(&format!(
        "lanforge_devices_by_origin{{origin=\"cli\"}} {}\n",
        cli_ct
    ));
    out.push_str(&format!(
        "lanforge_devices_by_origin{{origin=\"dynamic\"}} {}\n",
        dyn_ct
    ));

    // 2. DHCP Metrics
    let v4_leases = state.devices().filter(|d| d.v4.is_dynamic()).count();
    out.push_str("# HELP lanforge_dhcp_leases_active Total active dynamic leases\n");
    out.push_str("# TYPE lanforge_dhcp_leases_active gauge\n");
    out.push_str(&format!(
        "lanforge_dhcp_leases_active{{proto=\"v4\"}} {}\n",
        v4_leases
    ));

    let v6_leases: usize = state
        .devices()
        .map(|d| d.v6.iter().filter(|s| s.is_dynamic()).count())
        .sum();
    out.push_str(&format!(
        "lanforge_dhcp_leases_active{{proto=\"v6\"}} {}\n",
        v6_leases
    ));

    if cfg.dhcp_v4_range_size > 0 {
        let ratio = (v4_leases as f64) / (f64::from(cfg.dhcp_v4_range_size));
        out.push_str(
            "# HELP lanforge_dhcp_pool_usage_ratio Ratio of IP pool currently allocated\n",
        );
        out.push_str("# TYPE lanforge_dhcp_pool_usage_ratio gauge\n");
        out.push_str(&format!(
            "lanforge_dhcp_pool_usage_ratio{{proto=\"v4\"}} {:.4}\n",
            ratio
        ));
    }

    if let Some(pool_size) = cfg.dhcp_v6_pool_size
        && pool_size > 0
    {
        let ratio = (v6_leases as f64) / (pool_size as f64);
        out.push_str(&format!(
            "lanforge_dhcp_pool_usage_ratio{{proto=\"v6\"}} {:.4}\n",
            ratio
        ));
    }

    // 3. DNS Metrics (if available)
    if let Some(stats_any) = ctx.get_dns_stats()
        && let Some(stats) = stats_any.downcast_ref::<DnsStats>()
    {
        let snap = stats.snapshot();
        out.push_str("# HELP lanforge_dns_queries_total Total DNS queries received\n");
        out.push_str("# TYPE lanforge_dns_queries_total counter\n");
        out.push_str(&format!(
            "lanforge_dns_queries_total {}\n",
            snap.requests_total
        ));

        out.push_str("# HELP lanforge_dns_cache_hits_total DNS queries answered from cache\n");
        out.push_str("# TYPE lanforge_dns_cache_hits_total counter\n");
        out.push_str(&format!(
            "lanforge_dns_cache_hits_total {}\n",
            snap.cache_hits
        ));

        out.push_str("# HELP lanforge_dns_auth_answers_total DNS queries answered authoritatively (local hostnames)\n");
        out.push_str("# TYPE lanforge_dns_auth_answers_total counter\n");
        out.push_str(&format!(
            "lanforge_dns_auth_answers_total {}\n",
            snap.auth_queries
        ));

        out.push_str(
            "# HELP lanforge_dns_upstream_errors_total DNS queries that failed at upstream\n",
        );
        out.push_str("# TYPE lanforge_dns_upstream_errors_total counter\n");
        out.push_str(&format!(
            "lanforge_dns_upstream_errors_total {}\n",
            snap.upstream_errors
        ));
    }

    // 4. Core Event Counters
    out.push_str("# HELP lanforge_events_total Total internal events processed by core\n");
    out.push_str("# TYPE lanforge_events_total counter\n");
    out.push_str(&format!(
        "lanforge_events_total{{type=\"arp\"}} {}\n",
        counters.arp_seen.load(std::sync::atomic::Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "lanforge_events_total{{type=\"ndp\"}} {}\n",
        counters.ndp_seen.load(std::sync::atomic::Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "lanforge_events_total{{type=\"slaac\"}} {}\n",
        counters
            .slaac_observed
            .load(std::sync::atomic::Ordering::Relaxed)
    ));

    // 5. System Metrics
    out.push_str("# HELP lanforge_uptime_seconds Daemon uptime in seconds\n");
    out.push_str("# TYPE lanforge_uptime_seconds counter\n");
    out.push_str(&format!("lanforge_uptime_seconds {}\n", uptime_secs));

    // DB Size
    if let Ok(metadata) = std::fs::metadata(&cfg.db_path) {
        out.push_str("# HELP lanforge_db_size_bytes Size of the SQLite persistence database\n");
        out.push_str("# TYPE lanforge_db_size_bytes gauge\n");
        out.push_str(&format!(
            "lanforge_db_size_bytes{{file=\"leases\"}} {}\n",
            metadata.len()
        ));
    }
    if let Ok(metadata) = std::fs::metadata(&cfg.log_db_path) {
        out.push_str(&format!(
            "lanforge_db_size_bytes{{file=\"logs\"}} {}\n",
            metadata.len()
        ));
    }

    // Memory RSS (Linux only, best effort)
    if let Ok(stat) = std::fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = stat.split_whitespace().collect();
        if let Some(rss_pages) = parts.get(1).and_then(|s| s.parse::<u64>().ok()) {
            let rss_bytes = rss_pages * 4096; // Assumes 4KB pages
            out.push_str(
                "# HELP lanforge_memory_rss_bytes Resident set size of the daemon process\n",
            );
            out.push_str("# TYPE lanforge_memory_rss_bytes gauge\n");
            out.push_str(&format!("lanforge_memory_rss_bytes {}\n", rss_bytes));
        }
    }

    out
}
