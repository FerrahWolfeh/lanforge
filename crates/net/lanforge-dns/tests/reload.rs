mod common;
use lanforge_core::bus::{DnsEvent, EventBus, LanforgeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::DnsRequest;
use lanforge_types::network::dns::DnsResponse;
use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, DnsResponseCode,
};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;

#[cfg(any(feature = "dot", feature = "doq", feature = "doh-upstream"))]
fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        #[cfg(feature = "ring")]
        let _ = rustls::crypto::ring::default_provider().install_default();
        #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[tokio::test]
async fn dns_reload_causes_full_cache_refresh_if_enabled() {
    #[cfg(any(feature = "dot", feature = "doq", feature = "doh-upstream"))]
    init_crypto();

    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let ctx = LanforgeContext::new(bus, table, None);

    // 1. Setup Config with an upstream
    let cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1063".parse().unwrap(),
        ..Default::default()
    };

    // Seed an upstream in the context
    let target = "udp://1.1.1.1:53".parse::<UpstreamTarget>().unwrap();
    ctx.update_dns_upstreams(vec![target]);

    // 2. Start DNS Service
    let mut service = DnsService::new(cfg, ctx.clone());
    let ctx_service = ctx.clone();

    ctx.set_db_ready(true);

    tokio::spawn(async move {
        service.serve(&ctx_service).await.expect("Service failed");
    });

    // Wait for service to bind socket
    tokio::time::sleep(Duration::from_millis(100)).await;

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
            q: None,
            kind: None,
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
            q: None,
            kind: None,
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
            q: None,
            kind: None,
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
            q: None,
            kind: None,
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

#[tokio::test]
async fn dns_reload_rewrites_on_the_fly() {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let ctx = LanforgeContext::new(bus, table, None);

    // 1. Setup Config
    let cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1064".parse().unwrap(),
        ..Default::default()
    };

    // 2. Start DNS Service
    let mut service = DnsService::new(cfg, ctx.clone());
    let ctx_service = ctx.clone();

    ctx.set_db_ready(true);

    tokio::spawn(async move {
        service.serve(&ctx_service).await.expect("Service failed");
    });

    // Wait for service to bind socket
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Query once for my-site.lan (should return ServFail or NXDOMAIN because no rewrites/upstream exist)
    let client_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect("127.0.0.1:1064").await.unwrap();

    let mut query = DnsMessage::new();
    query.header.id = 4321;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("my-site.lan"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let query_bytes = WireEncoder::new().encode_message(&query);
    client_sock.send(&query_bytes).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client_sock.recv(&mut buf))
        .await
        .expect("Timeout waiting for DNS response")
        .unwrap();

    let response = WireDecoder::new(&buf[..n]).decode_message().unwrap();
    assert_ne!(response.header.rcode, DnsResponseCode::NoError);

    // 4. Update rewrites in the context and trigger reload
    ctx.update_dns_rewrites(vec![RewriteRule {
        id: Some(1),
        domain: "my-site.lan".to_string(),
        rtype: DnsRecordType::A,
        answer: RewriteAnswer::A(Ipv4Addr::new(1, 2, 3, 4)),
    }]);

    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));

    // Wait a brief moment for the event to be processed
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Query again (should now return 1.2.3.4 via rewrite)
    client_sock.send(&query_bytes).await.unwrap();
    let n2 = tokio::time::timeout(Duration::from_secs(5), client_sock.recv(&mut buf))
        .await
        .expect("Timeout waiting for DNS response after reload")
        .unwrap();

    let response2 = WireDecoder::new(&buf[..n2]).decode_message().unwrap();
    assert_eq!(response2.header.rcode, DnsResponseCode::NoError);
    assert_eq!(response2.answers.len(), 1);
    if let DnsRData::A(ip) = response2.answers[0].rdata {
        assert_eq!(ip, Ipv4Addr::new(1, 2, 3, 4));
    } else {
        panic!("Expected A record");
    }

    ctx.terminate();
}
