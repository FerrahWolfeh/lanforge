mod common;

use common::*;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::resolver::filter::manifest::AdblockManifest;
use lanforge_dns::server::worker::spawn_adblock_manager;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockSourceFormat, AdblockUrlKind};
use lanforge_types::network::dns::AdblockUrlEntry;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOSTS_BODY: &str = "# StevenBlack-style hosts\n127.0.0.1 localhost\n0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net # inline comment\n0.0.0.0 telemetry.example.org\n";

/// Mock upstream: 200 + ETag on first fetch, 304 when the client sends `If-None-Match`.
async fn spawn_conditional_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let resp = if req.contains("if-none-match") {
                    "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nETag: \"v1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        HOSTS_BODY.len(),
                        HOSTS_BODY
                    )
                };
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

/// Boots a DNS context + adblock manager on `cache_dir` and waits up to `timeout`
/// for `domain` to become blocked. Returns whether it was blocked.
async fn boot_and_check(cache_dir: &Path, port: u16, domain: &str, timeout: Duration) -> bool {
    let ctx_instance = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx_instance.set_pppoe_ready(true);
    ctx_instance.update_dns_adblock_urls(vec![AdblockUrlEntry {
        id: Some(1),
        url: format!("http://127.0.0.1:{port}/hosts"),
        kind: AdblockUrlKind::Blocklist,
        format: AdblockSourceFormat::Auto,
    }]);
    ctx_instance.update_dns_adblock(AdblockDbConfig {
        enabled: true,
        refresh_hours: 12,
        ..Default::default()
    });

    let cfg = DnsConfig {
        enabled: true,
        adblock_enabled: true,
        adblock_cache_dir: Some(cache_dir.to_str().unwrap().to_string()),
        ..mock_config()
    };
    let dns_ctx = Arc::new(mock_dns_context(ctx_instance, cfg).await);
    let handle = spawn_adblock_manager(dns_ctx.clone());

    let filter = dns_ctx.filter.as_ref().unwrap();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut blocked = false;
    while tokio::time::Instant::now() < deadline {
        if filter.should_block(domain) {
            blocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    handle.abort();
    blocked
}

/// Reproduces the "adblock blocks nothing after restart" bug:
/// the compiled cache on disk is older than `refresh_hours`, so the manager skips the
/// disk load, upstream answers 304, the source fingerprint is unchanged and the merge
/// (the only place that loads the FST into memory) is skipped, leaving the blocklist empty.
#[cfg(feature = "adblock")]
#[tokio::test(flavor = "multi_thread")]
async fn test_restart_with_stale_cache_and_304_still_blocks() {
    let port = spawn_conditional_server().await;
    let temp_dir = tempfile::tempdir().unwrap();

    // Run 1: cold start. Download, compile, merge, load.
    assert!(
        boot_and_check(temp_dir.path(), port, "ads.example.com", Duration::from_secs(10)).await,
        "cold start should block ads.example.com"
    );
    assert!(temp_dir.path().join("adblock/block.fst").exists());

    // Age the merged cache beyond refresh_hours (simulates a daemon restarted >12h later).
    let manifest_path = temp_dir.path().join("adblock/manifest.json");
    let mut manifest = AdblockManifest::load_or_default(&manifest_path);
    assert!(manifest.merged_blocks >= 3, "manifest should record merged blocks");
    manifest.last_merge = 1;
    manifest.save_atomic(&manifest_path).unwrap();

    // Run 2: restart. Upstream returns 304, fingerprint unchanged.
    assert!(
        boot_and_check(temp_dir.path(), port, "ads.example.com", Duration::from_secs(5)).await,
        "restart with stale cache + 304 must still load the compiled blocklist into memory"
    );
    // Subdomains of hosts entries are exact-only, unrelated domains must stay clean.
    assert!(
        !boot_and_check(temp_dir.path(), port, "example.com", Duration::from_millis(500)).await,
        "unlisted domain must not be blocked"
    );
}

