mod common;
use lanforge_core::bus::{DnsEvent, EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_dns_wire::WireEncoder;
use lanforge_types::network::dns::DnsRequest;
use lanforge_types::network::dns::DnsResponse;
use lanforge_types::network::dns::{DnsClass, DnsMessage, DnsQuestion, DnsRecordType};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;

#[cfg(any(feature = "dot", feature = "doq", feature = "doh-upstream"))]
fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    });
}

#[tokio::test]
async fn dns_reload_causes_full_cache_refresh_if_enabled() {
    #[cfg(any(feature = "dot", feature = "doq", feature = "doh-upstream"))]
    init_crypto();

    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let db = Arc::new(
        lanforge_db::engine::LanforgeDb::open(&lanforge_db::config::DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let ctx = LanforgeContext::new(bus, table, None);

    // 1. Setup Config with an upstream
    let cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1063".parse().unwrap(),
        ..Default::default()
    };

    // Seed an upstream in the database
    let _ = db.add_dns_upstream("1.1.1.1:53", "Udp", None).await;

    // 2. Start DNS Service
    let mut service = DnsService::new(cfg, ctx.clone(), db.clone());
    let ctrl = ServiceControl::new("dns-reload-test", ctx.clone());

    ctx.set_db_ready(true);
    let mut rx = ctx.bus().subscribe();

    tokio::spawn(async move {
        service.run(ctrl).await.expect("Service failed");
    });

    // Wait for ServiceReady
    loop {
        let event = rx.recv().await.expect("Bus closed");
        if let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = event.event
            && name == "dns-reload-test"
        {
            break;
        }
    }

    // 3. Query once to populate the cache
    let client_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect("127.0.0.1:1063").await.unwrap();

    let mut query = DnsMessage::new();
    query.header.id = 1234;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("google.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let query_bytes = WireEncoder::new().encode_message(&query);
    client_sock.send(&query_bytes).await.unwrap();

    let mut buf = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(5), client_sock.recv(&mut buf))
        .await
        .expect("Timeout waiting for DNS response")
        .unwrap();

    // Verify cache has entries
    let dns_handle = ctx.dns_handle().expect("DNS handle not found");

    let cache_dump_res = dns_handle
        .send_request(DnsRequest::CacheDump {
            limit: None,
            offset: None,
        })
        .await
        .unwrap();
    if let DnsResponse::CacheDump(res) = cache_dump_res {
        assert!(
            !res.entries.is_empty(),
            "Cache should be populated after query"
        );
    } else {
        panic!("Expected CacheDump response");
    }

    // 4. Trigger reload event by publishing ConfigUpstreamsChanged to the bus
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigUpstreamsChanged));

    // Wait a brief moment for the event to be processed by the service loop
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Verify the cache is empty (refreshed)
    let cache_dump_res2 = dns_handle
        .send_request(DnsRequest::CacheDump {
            limit: None,
            offset: None,
        })
        .await
        .unwrap();
    if let DnsResponse::CacheDump(res) = cache_dump_res2 {
        assert_eq!(
            res.entries.len(),
            0,
            "Cache should be empty after upstream reload"
        );
    } else {
        panic!("Expected CacheDump response");
    }

    // 6. Test CacheFlush directly too
    // Populate cache again by querying
    client_sock.send(&query_bytes).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), client_sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let cache_dump_res3 = dns_handle
        .send_request(DnsRequest::CacheDump {
            limit: None,
            offset: None,
        })
        .await
        .unwrap();
    if let DnsResponse::CacheDump(res) = cache_dump_res3 {
        assert!(!res.entries.is_empty());
    }

    // Publish CacheFlush
    let _ = ctx.bus().publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let cache_dump_res4 = dns_handle
        .send_request(DnsRequest::CacheDump {
            limit: None,
            offset: None,
        })
        .await
        .unwrap();
    if let DnsResponse::CacheDump(res) = cache_dump_res4 {
        assert_eq!(
            res.entries.len(),
            0,
            "Cache should be empty after CacheFlush"
        );
    }

    ctx.terminate();
}
