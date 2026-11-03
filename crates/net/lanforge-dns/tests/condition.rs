#[path = "common/mod.rs"]
mod common;

use common::{init_test_context, mock_config};
use lanforge_core::service::{Activation, LanforgeService};
use lanforge_dns::server::service::DnsService;
use lanforge_types::config::DnsListenConfig;

/// `[dns] enabled` is live: a reload that turns it off puts DNS to sleep, turning it back on
/// starts it, with no daemon restart.
#[test]
fn dns_runs_while_enabled_and_listening() {
    let ctx = init_test_context();
    let condition = DnsService::new(mock_config(), ctx.clone()).spec().condition;
    let active = || matches!(condition.evaluate(&ctx), Activation::Active);

    assert!(active(), "default listener, enabled");
    ctx.update_dns_listen(DnsListenConfig {
        enabled: false,
        ..DnsListenConfig::default()
    });
    assert!(!active(), "disabled");
    ctx.update_dns_listen(DnsListenConfig::default());
    assert!(active(), "enabled again");
}
