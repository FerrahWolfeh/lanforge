#[path = "common/mod.rs"]
mod common;

use std::sync::atomic::Ordering;

use common::{init_test_context, mock_config};
use lanforge_core::service::AsyncService;
use lanforge_dns::server::service::DnsService;
use lanforge_dns::telemetry::DnsStats;

/// `lanforge status` asks the instance registered at start-up for its banner, while the
/// runner serves a second instance: the banner must show the serving instance's counters.
#[test]
fn banner_counts_come_from_the_serving_instance() {
    let ctx = init_test_context();
    let registered = DnsService::new(mock_config(), ctx.clone());
    let _serving = DnsService::new(mock_config(), ctx.clone());

    let live = ctx.get_shared::<DnsStats>().expect("serving stats are shared");
    live.cache_entries.store(42, Ordering::Relaxed);
    live.requests_total.store(10, Ordering::Relaxed);
    live.cache_hits.store(5, Ordering::Relaxed);

    let banner = registered.banner(&ctx);
    let stat = |key: &str| {
        banner
            .stats
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(stat("cache_entries").as_deref(), Some("42"));
    assert_eq!(stat("cache_hit_rate").as_deref(), Some("50.0%"));
}
