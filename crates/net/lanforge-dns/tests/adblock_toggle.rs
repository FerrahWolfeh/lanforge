#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
#![cfg(feature = "adblock")]

mod common;

use common::*;
use lanforge_core::bus::{DnsEvent, EventBus, LanforgeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::worker::spawn_adblock_manager;
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockSourceFormat, AdblockUrlKind, TimeOfDay,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RULES: &str = "||ads.example.com^\n||tracker.example.net^\n";

/// Serves `RULES` and counts every request: one request = one download pass for one source.
async fn spawn_counting_server() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                counter.fetch_add(1, Ordering::SeqCst);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RULES}",
                    RULES.len()
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });
    (port, hits)
}

fn source(id: i64, port: u16, path: &str) -> AdblockUrlEntry {
    AdblockUrlEntry {
        id: Some(id),
        name: Some(path.to_string()),
        url: format!("http://127.0.0.1:{port}/{path}"),
        kind: AdblockUrlKind::Blocklist,
        format: AdblockSourceFormat::Adblock,
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// A toggle, a pause or a schedule change only flips state: none of them may re-download the
/// source lists (each pass is one HTTP request per source plus a full cache flush). Only a
/// change of the source list needs a pass.
#[tokio::test(flavor = "multi_thread")]
async fn adblock_toggle_and_pause_do_not_refetch_lists() {
    let (port, hits) = spawn_counting_server().await;
    let temp_dir = tempfile::tempdir().unwrap();

    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(Arc::clone(&bus), State::new(), None);
    ctx.update_dns_adblock_urls(vec![source(1, port, "a.txt")]);
    let enabled_cfg = AdblockDbConfig {
        enabled: true,
        ..Default::default()
    };
    ctx.update_dns_adblock(enabled_cfg.clone());

    let cfg = DnsConfig {
        enabled: true,
        adblock_enabled: true,
        adblock_cache_dir: Some(temp_dir.path().to_str().unwrap().to_string()),
        ..mock_config()
    };
    let dns_ctx = Arc::new(mock_dns_context(ctx.clone(), cfg).await);
    let filter = dns_ctx.filter.clone().expect("adblock filter");
    let manager = spawn_adblock_manager(Arc::clone(&dns_ctx));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while filter.blocklist_size() == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(filter.blocklist_size() > 0, "initial list loaded");
    settle().await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "initial pass fetched the source once"
    );

    let toggle = |enabled: bool, duration_secs: Option<u64>| {
        let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::AdblockToggle {
            enabled,
            duration_secs,
        }));
    };

    // WebUI 30 s pause, then resume (as the DNS service applies it, the filter flips too).
    filter.set_enabled(false);
    toggle(false, Some(30));
    settle().await;
    filter.set_enabled(true);
    toggle(true, None);
    settle().await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "pause/resume must not re-download"
    );

    // Permanent off/on: the API writes the config *and* publishes the toggle.
    ctx.update_dns_adblock(AdblockDbConfig {
        enabled: false,
        ..enabled_cfg.clone()
    });
    filter.set_enabled(false);
    toggle(false, None);
    settle().await;
    ctx.update_dns_adblock(enabled_cfg.clone());
    filter.set_enabled(true);
    toggle(true, None);
    settle().await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "off/on must not re-download"
    );

    // A new daily refresh time only reschedules.
    ctx.update_dns_adblock(AdblockDbConfig {
        refresh_time: TimeOfDay {
            hour: 4,
            minute: 30,
        },
        ..enabled_cfg.clone()
    });
    settle().await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a schedule change must not re-download"
    );
    assert!(filter.blocklist_size() > 0 && filter.is_enabled());

    // A new source list is the one change that needs a download pass.
    ctx.update_dns_adblock_urls(vec![source(1, port, "a.txt"), source(2, port, "b.txt")]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) < 3 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    settle().await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "one fetch per configured source"
    );

    manager.abort();
}

/// A temporary pause is not a disable: the filter re-enables itself lazily when the pause ends,
/// with no event. A worker that reached its schedule (or started) during a pause parked in the
/// "disabled" wait, which only a toggle or config change ends: lists stopped refreshing.
#[tokio::test(flavor = "multi_thread")]
async fn adblock_lists_refresh_during_a_pause() {
    let (port, hits) = spawn_counting_server().await;
    let temp_dir = tempfile::tempdir().unwrap();

    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus, State::new(), None);
    ctx.update_dns_adblock_urls(vec![source(1, port, "a.txt")]);
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
    let filter = dns_ctx.filter.clone().expect("adblock filter");

    // Paused for 30 s (as the DNS service applies a WebUI pause).
    let until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 30;
    filter.timer.disabled_until.store(until, Ordering::SeqCst);
    filter.set_enabled(false);

    let manager = spawn_adblock_manager(Arc::clone(&dns_ctx));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while hits.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "lists refresh while paused");
    assert!(!filter.is_enabled(), "the pause itself is untouched");

    manager.abort();
}
