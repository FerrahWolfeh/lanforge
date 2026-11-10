#![cfg(feature = "adblock")]

use crate::common::*;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::resolver::recursive::UpstreamManager;
use lanforge_dns::server::worker::spawn_adblock_manager;
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockSourceFormat, AdblockUrlKind};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Instant, sleep};

const RULES: &str = "||ads.example.com^\n";

/// Answers 503 until `online` is set: stands in for a list host that cannot be resolved yet.
async fn spawn_list_server(online: Arc<AtomicBool>) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            let counter = Arc::clone(&counter);
            let online = Arc::clone(&online);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                counter.fetch_add(1, Ordering::SeqCst);
                let resp = if online.load(Ordering::SeqCst) {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RULES}",
                        RULES.len()
                    )
                } else {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });
    (port, hits)
}

/// Owner's boot log: the stale-list refresh ran before `PPPoE` was up, failed to resolve the list
/// host and slept a 5 min backoff although upstreams appeared seconds later. A failed pass must
/// retry as soon as the DNS server gets upstreams.
#[tokio::test(flavor = "multi_thread")]
async fn adblock_failed_refresh_retries_when_upstreams_appear() {
    let online = Arc::new(AtomicBool::new(false));
    let (port, hits) = spawn_list_server(Arc::clone(&online)).await;
    let temp_dir = tempfile::tempdir().unwrap();

    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus, State::new(), None);
    ctx.update_dns_adblock_urls(vec![AdblockUrlEntry {
        id: Some(1),
        name: Some("list".to_string()),
        url: format!("http://127.0.0.1:{port}/list.txt"),
        kind: AdblockUrlKind::Blocklist,
        format: AdblockSourceFormat::Adblock,
    }]);
    ctx.update_dns_adblock(AdblockDbConfig {
        enabled: true,
        ..Default::default()
    });
    let cfg = DnsConfig {
        enabled: true,
        adblock_enabled: true,
        adblock_cache_dir: Some(temp_dir.path().to_str().unwrap().to_string()),
        ..mock_config()
    };
    let dns_ctx = Arc::new(mock_dns_context(ctx, cfg).await);
    assert!(dns_ctx.recursive.is_empty(), "boot: no upstreams yet");
    let filter = dns_ctx.filter.clone().expect("adblock filter");
    let manager = spawn_adblock_manager(Arc::clone(&dns_ctx));

    let deadline = Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        sleep(Duration::from_millis(50)).await;
    }
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "first pass tried once and failed"
    );
    assert_eq!(filter.blocklist_size(), 0);

    // PPPoE comes up: the list host resolves now, and the DNS service installs upstreams.
    online.store(true, Ordering::SeqCst);
    let upstream = MockUpstreamServer::spawn(HashMap::new()).await;
    let mgr = UpstreamManager::new(&upstream.target(), Arc::clone(&dns_ctx.cache))
        .await
        .expect("upstream manager");
    dns_ctx.recursive.replace_upstreams(vec![mgr]);

    let deadline = Instant::now() + Duration::from_secs(5);
    while filter.blocklist_size() == 0 && Instant::now() < deadline {
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        filter.blocklist_size() > 0,
        "retry must follow the upstreams, not the 5 min backoff (hits: {})",
        hits.load(Ordering::SeqCst)
    );

    manager.abort();
}
