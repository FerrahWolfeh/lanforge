mod common;

use common::*;
use lanforge_core::bus::{DnsEvent, EventBus, LanforgeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::worker::spawn_adblock_manager;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockRuleAction, AdblockRuleEntry, AdblockSourceFormat, AdblockUrlKind,
    BlockingMode,
};
use lanforge_types::network::dns::{
    AdblockUrlEntry, DnsClass, DnsMessage, DnsQuestion, DnsRecordType, DnsResponseCode,
    FilterAction, FilterOrigin,
};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LOCAL_ADBLOCK_RULES: &str = r#"[Adblock Plus 2.0]
! Test adblock list
||doubleclick.net^
||analytics-engine.io^
@@||good.adservice.google.com^
@@||whitelisted-sub.doubleclick.net^
||important.tracker.com^$important
||canceled.badtracker.com^
"#;

const LOCAL_BADFILTER_RULES: &str = r#"[Adblock Plus 2.0]
! Badfilter test list
||canceled.badtracker.com^$badfilter
"#;

/// Spawns a local mock HTTP server that serves local adblock & badfilter lists.
async fn spawn_local_rule_server() -> u16 {
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
                let req = String::from_utf8_lossy(&buf[..n]);

                let body = if req.contains("/badfilter.txt") {
                    LOCAL_BADFILTER_RULES
                } else {
                    LOCAL_ADBLOCK_RULES
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    port
}

fn make_query(name: &str, qtype: DnsRecordType) -> Vec<u8> {
    let mut query = DnsMessage::new();
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from(name),
        qtype,
        qclass: DnsClass::IN,
    });
    WireEncoder::new().encode_message(&query)
}

/// Comprehensive battery of adblock test cases executed against live StevenBlack hosts
/// combined with Adblock-syntax wildcards, exception rules, badfilters, user allowlist overrides,
/// and dynamic runtime toggles in a single execution.
///
/// Run explicitly with:
/// `cargo test -p lanforge-dns --test adblock_live -- --ignored --nocapture`
#[cfg(feature = "adblock")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires public internet access to raw.githubusercontent.com"]
async fn test_adblock_live_comprehensive_battery() {
    let port = spawn_local_rule_server().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let cache_dir_path = temp_dir.path().to_str().unwrap().to_string();

    let bus = Arc::new(EventBus::new());
    let ctx_instance = LanforgeContext::new(bus, State::new(), None);
    ctx_instance.set_pppoe_ready(true);

    // 1. Configure 3 sources:
    // Source 1: Live StevenBlack hosts from GitHub
    // Source 2: Local mock Adblock Plus list (wildcards + exceptions + important)
    // Source 3: Local mock Badfilter list
    ctx_instance.update_dns_adblock_urls(vec![
        AdblockUrlEntry {
            id: Some(1),
            name: Some("stevenblack".to_string()),
            url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
            kind: AdblockUrlKind::Blocklist,
            format: AdblockSourceFormat::Auto, // Detected as Hosts
        },
        AdblockUrlEntry {
            id: Some(2),
            name: Some("adblock-txt".to_string()),
            url: format!("http://127.0.0.1:{port}/adblock.txt"),
            kind: AdblockUrlKind::Blocklist,
            format: AdblockSourceFormat::Adblock,
        },
        AdblockUrlEntry {
            id: Some(3),
            name: Some("badfilter".to_string()),
            url: format!("http://127.0.0.1:{port}/badfilter.txt"),
            kind: AdblockUrlKind::Blocklist,
            format: AdblockSourceFormat::Adblock,
        },
    ]);

    ctx_instance.update_dns_adblock(AdblockDbConfig {
        enabled: true,
        blocking_mode: BlockingMode::NullIp,
        ..Default::default()
    });

    let cfg = DnsConfig {
        enabled: true,
        adblock_enabled: true,
        adblock_cache_dir: Some(cache_dir_path.clone()),
        blocking_mode: BlockingMode::NullIp,
        blocking_ip_v4: Some(Ipv4Addr::UNSPECIFIED),
        ..mock_config()
    };

    let dns_ctx = Arc::new(mock_dns_context(ctx_instance.clone(), cfg).await);
    let manager_handle = spawn_adblock_manager(dns_ctx.clone());

    let filter = dns_ctx
        .filter
        .as_ref()
        .expect("AdBlocker should be initialized");

    // Wait for the manager to download, compile, merge, and arm the in-memory blocker
    println!("Waiting for adblock lists to download, compile, and merge...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        if filter.blocklist_size() > 50_000 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        filter.blocklist_size() > 50_000,
        "Blocklist size should be > 50k, got {}",
        filter.blocklist_size()
    );
    println!(
        "Blocklist loaded successfully with {} rules!",
        filter.blocklist_size()
    );

    let client_ip = "192.168.1.100".parse().unwrap();

    // =========================================================================
    // Case 1: Exact matches from StevenBlack hosts (Source ID 1)
    // =========================================================================
    let m = filter
        .check_domain("adservice.google.com")
        .expect("adservice.google.com should match");
    assert_eq!(m.action, FilterAction::Block);
    assert_eq!(m.origin, FilterOrigin::List { source_id: 1 });

    let query_data = make_query("adservice.google.com", DnsRecordType::A);
    let mut resp_buf = Vec::new();
    let handled = process_query_test(&query_data, &dns_ctx, client_ip, &mut resp_buf)
        .await
        .unwrap();
    assert!(handled);
    let resp = WireDecoder::new(&resp_buf).decode_message().unwrap();
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    assert!(
        !resp.answers.is_empty(),
        "NullIp mode should answer with 0.0.0.0"
    );

    // =========================================================================
    // Case 2: Exact-only restriction for hosts syntax
    // =========================================================================
    // Hosts format rules (0.0.0.0 domain) MUST NOT wildcard subdomains.
    assert!(
        filter
            .check_domain("unlisted-sub.adservice.google.com")
            .is_none(),
        "Hosts syntax should not wildcard unlisted subdomains"
    );

    // =========================================================================
    // Case 3: Adblock-format wildcard blocking (Source ID 2)
    // =========================================================================
    // ||analytics-engine.io^ is unique to Source 2: apex and subdomains attribute to Source 2
    let m_apex = filter
        .check_domain("analytics-engine.io")
        .expect("analytics-engine.io should match");
    assert_eq!(m_apex.action, FilterAction::Block);
    assert_eq!(m_apex.origin, FilterOrigin::List { source_id: 2 });

    let m_sub = filter
        .check_domain("tracker.analytics-engine.io")
        .expect("tracker.analytics-engine.io should match");
    assert_eq!(m_sub.action, FilterAction::Block);
    assert_eq!(m_sub.origin, FilterOrigin::List { source_id: 2 });

    let m_deep = filter
        .check_domain("deep.sub.ad.analytics-engine.io")
        .expect("deep subdomain should match");
    assert_eq!(m_deep.action, FilterAction::Block);
    assert_eq!(m_deep.origin, FilterOrigin::List { source_id: 2 });

    // doubleclick.net is in both StevenBlack (exact) and Source 2 (wildcard)
    assert!(filter.check_domain("doubleclick.net").is_some());
    assert!(filter.check_domain("ad.doubleclick.net").is_some());

    // =========================================================================
    // Case 4: Exception rules (@@||...) unblocking domains
    // =========================================================================
    // @@||good.adservice.google.com^ unblocks a subdomain of StevenBlack
    let m_exc1 = filter
        .check_domain("good.adservice.google.com")
        .expect("should match exception");
    assert_eq!(m_exc1.action, FilterAction::Allow);
    assert_eq!(m_exc1.origin, FilterOrigin::List { source_id: 2 });

    // @@||whitelisted-sub.doubleclick.net^ unblocks a subdomain of Source 2
    let m_exc2 = filter
        .check_domain("whitelisted-sub.doubleclick.net")
        .expect("should match exception");
    assert_eq!(m_exc2.action, FilterAction::Allow);

    // =========================================================================
    // Case 5: Badfilter cancellation (Source ID 3)
    // =========================================================================
    // ||canceled.badtracker.com^ was canceled by Source 3's $badfilter rule
    assert!(
        filter.check_domain("canceled.badtracker.com").is_none(),
        "Domain matched by $badfilter rule must not be blocked"
    );

    // =========================================================================
    // Case 6: Priority $important modifier
    // =========================================================================
    let m_imp = filter
        .check_domain("important.tracker.com")
        .expect("important.tracker.com should match");
    assert_eq!(m_imp.action, FilterAction::Block);
    assert!(m_imp.important, "Match must preserve important flag");

    // =========================================================================
    // Case 7: Clean legitimate domains must never be blocked
    // =========================================================================
    assert!(filter.check_domain("google.com").is_none());
    assert!(filter.check_domain("github.com").is_none());
    assert!(filter.check_domain("wikipedia.org").is_none());
    assert!(filter.check_domain("rust-lang.org").is_none());
    assert!(filter.check_domain("cloudflare.com").is_none());

    // =========================================================================
    // Case 8: User dynamic custom block rules
    // =========================================================================
    ctx_instance.update_dns_adblock_rules(vec![AdblockRuleEntry {
        id: Some(101),
        name: Some("custom-ad".to_string()),
        domain: "my-custom-ad.internal".to_string(),
        action: AdblockRuleAction::Block,
        enabled: true,
    }]);
    let _ = dns_ctx
        .bus
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockRulesChanged));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let m_custom = filter
        .check_domain("my-custom-ad.internal")
        .expect("custom rule must block");
    assert_eq!(m_custom.action, FilterAction::Block);
    assert_eq!(m_custom.origin, FilterOrigin::UserRule);

    // =========================================================================
    // Case 9: User dynamic allowlist override
    // =========================================================================
    // Add doubleclick.net to user allowlist -> should override FST block
    ctx_instance.update_dns_allowlist(vec!["doubleclick.net".to_string()]);
    let _ = dns_ctx
        .bus
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigAllowlistChanged));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let m_allowed = filter
        .check_domain("doubleclick.net")
        .expect("should match allowlist");
    assert_eq!(m_allowed.action, FilterAction::Allow);
    assert_eq!(m_allowed.origin, FilterOrigin::UserAllowlist);

    // Remove from allowlist -> should block again
    ctx_instance.update_dns_allowlist(vec![]);
    let _ = dns_ctx
        .bus
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigAllowlistChanged));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let m_reblocked = filter
        .check_domain("doubleclick.net")
        .expect("should block again");
    assert_eq!(m_reblocked.action, FilterAction::Block);

    // =========================================================================
    // Case 10: Blocking mode switching (Refused, NXDomain, NullIp)
    // =========================================================================
    // Refused
    filter.replace_config(
        BlockingMode::Refused,
        Some(Ipv4Addr::UNSPECIFIED),
        Some(std::net::Ipv6Addr::UNSPECIFIED),
    );
    resp_buf.clear();
    process_query_test(&query_data, &dns_ctx, client_ip, &mut resp_buf)
        .await
        .unwrap();
    let resp_refused = WireDecoder::new(&resp_buf).decode_message().unwrap();
    assert_eq!(resp_refused.header.rcode, DnsResponseCode::Refused);

    // NXDomain
    filter.replace_config(
        BlockingMode::NxDomain,
        Some(Ipv4Addr::UNSPECIFIED),
        Some(std::net::Ipv6Addr::UNSPECIFIED),
    );
    resp_buf.clear();
    process_query_test(&query_data, &dns_ctx, client_ip, &mut resp_buf)
        .await
        .unwrap();
    let resp_nx = WireDecoder::new(&resp_buf).decode_message().unwrap();
    assert_eq!(resp_nx.header.rcode, DnsResponseCode::NXDomain);

    // =========================================================================
    // Case 11: Dynamic adblock toggle
    // =========================================================================
    // Toggle off
    filter.set_enabled(false);
    assert!(!filter.is_enabled());
    assert!(filter.check_domain("adservice.google.com").is_none());

    // Toggle on
    filter.set_enabled(true);
    assert!(filter.is_enabled());
    assert!(filter.check_domain("adservice.google.com").is_some());

    println!("All 11 adblock live battery cases passed successfully!");
    manager_handle.abort();
}
