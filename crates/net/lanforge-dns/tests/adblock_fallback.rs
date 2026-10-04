mod common;

use common::*;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::resolver::filter::DiskBlocklist;
use lanforge_dns::server::worker::spawn_adblock_manager;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockUrlKind};
use lanforge_types::network::dns::{
    AdblockUrlEntry, DnsClass, DnsMessage, DnsQuestion, DnsRecordType, DnsResponseCode,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "adblock")]
#[tokio::test]
async fn test_dns_adblock_update_failure_and_fallback() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cache_dir_path = temp_dir.path().to_str().unwrap().to_string();
    let cache_path = temp_dir.path().join("blocklist.fst");

    // 1. Create a pre-existing FST cache containing ads.example.com
    let mut initial_domains = HashSet::new();
    initial_domains.insert("ads.example.com".to_string());
    DiskBlocklist::build(initial_domains, &cache_path, 50000).unwrap();

    // 3. Initialize DnsContext
    let bus = Arc::new(EventBus::new());
    let ctx_instance = LanforgeContext::new(bus, State::new(), None);
    ctx_instance.set_pppoe_ready(true);
    ctx_instance.update_dns_adblock_urls(vec![AdblockUrlEntry {
        id: Some(1),
        url: "http://127.0.0.1:1/nonexistent.txt".to_string(),
        kind: AdblockUrlKind::Blocklist,
        format: lanforge_types::network::dns::adblock::AdblockSourceFormat::Auto,
    }]);
    ctx_instance.update_dns_adblock(AdblockDbConfig {
        enabled: true,
        refresh_hours: 12,
        ..Default::default()
    });

    let cfg = DnsConfig {
        enabled: true,
        adblock_enabled: true,
        adblock_cache_dir: Some(cache_dir_path.clone()),
        ..mock_config()
    };

    let dns_ctx = mock_dns_context(ctx_instance, cfg).await;
    let dns_ctx_arc = Arc::new(dns_ctx);

    // Verify initial load from the cache path works
    let filter = dns_ctx_arc.filter.as_ref().unwrap();

    // 4. Start the adblock manager worker in the background
    let manager_handle = spawn_adblock_manager(dns_ctx_arc.clone());

    // Wait a short duration to let it run the first download pass, which will FAIL
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 5. Verify the adblocker still has ads.example.com in memory and is active
    assert!(
        filter.should_block("ads.example.com"),
        "Adblocker cleared blocklist after a download failure!"
    );

    // 6. End-to-end query check on the pipeline
    let mut query = DnsMessage::new();
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("ads.example.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query_data = WireEncoder::new().encode_message(&query);
    let mut resp_buf = Vec::new();

    let has_resp = process_query_test(
        &query_data,
        &dns_ctx_arc,
        "127.0.0.1".parse().unwrap(),
        &mut resp_buf,
    )
    .await
    .unwrap();

    assert!(has_resp);
    let mut decoder = WireDecoder::new(&resp_buf);
    let resp = decoder.decode_message().unwrap();

    // Verify it is blocked and returns NXDomain
    assert_eq!(resp.header.rcode, DnsResponseCode::NXDomain);
    assert_eq!(resp.answers.len(), 0);

    // Clean up
    manager_handle.abort();
}
