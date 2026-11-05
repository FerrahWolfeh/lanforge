mod common;

use common::*;
use lanforge_core::context::ConfigPatch;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_types::network::dns::upstream::UpstreamMode;

/// The live config is the only source of the upstream mode. `Sequential` is both the default
/// and a valid admin choice: the service used to read it as "unset" and fall back to the
/// static `[dns] upstream_mode`, so a `WebUI` choice of Sequential flipped back on a DNS restart.
#[tokio::test]
async fn upstream_mode_comes_from_the_live_config() {
    let ctx = init_test_context();
    let _ = ctx.apply_config(ConfigPatch::new().with_dns_upstream_mode(UpstreamMode::Sequential));
    let cfg = DnsConfig {
        upstream_mode: UpstreamMode::Parallel,
        ..mock_config()
    };
    let service = DnsService::new(cfg, ctx.clone());

    let dns_ctx = service.init_dns_context().await.expect("dns context");
    assert_eq!(dns_ctx.recursive.mode(), UpstreamMode::Sequential);
}
