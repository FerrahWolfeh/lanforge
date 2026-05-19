use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_dns::telemetry::DnsStats;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, DnsResponseCode,
};
use lanforge_types::update::DeviceUpdate;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket as TokioUdpSocket;

#[cfg(any(feature = "dot", feature = "doq", feature = "doh-upstream"))]
fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    });
}

use lanforge_db::engine::LanforgeDb;

async fn init_test_context() -> (LanforgeContext, Arc<LanforgeDb>) {
    #[cfg(any(feature = "dot", feature = "doq", feature = "doh-upstream"))]
    init_crypto();

    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let db = Arc::new(
        LanforgeDb::open(&lanforge_db::config::DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    (LanforgeContext::new(bus, table, None), db)
}

#[tokio::test]
async fn dns_simulation_udp() {
    let (ctx, db) = init_test_context().await;

    // 1. Setup Config
    let cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1053".parse().unwrap(),
        search_domains: vec!["lan".to_string()],
        ..Default::default()
    };

    // 2. Register a device for local resolution
    let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv4Addr::new(192, 168, 1, 50);
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip,
        expires: SystemTime::now() + Duration::from_hours(1),
    });
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "my-device".to_string(),
    });

    // 3. Start DNS Service
    let mut service = DnsService::new(cfg, ctx.clone(), db);
    let ctrl = ServiceControl::new("dns", ctx.clone());

    ctx.set_db_ready(true);
    let mut rx = ctx.bus().subscribe();

    tokio::spawn(async move {
        service.run(ctrl).await.expect("Service failed");
    });

    // Wait for ServiceReady event
    loop {
        let event = rx.recv().await.expect("Bus closed");
        if let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = event.event
            && name == "dns"
        {
            break;
        }
    }

    // 4. Query using raw UDP socket
    let client_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect("127.0.0.1:1053").await.unwrap();

    let mut query = DnsMessage::new();
    query.header.id = 1234;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("my-device.lan"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let query_bytes = encoder.encode_message(&query);

    client_sock.send(&query_bytes).await.unwrap();

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .expect("Timeout waiting for DNS response")
        .expect("Recv failed");

    let mut decoder = WireDecoder::new(&buf[..n]);
    let response = decoder.decode_message().unwrap();

    // 5. Verify Response
    assert_eq!(response.header.id, 1234);
    assert_eq!(response.header.rcode, DnsResponseCode::NoError);

    assert!(!response.answers.is_empty(), "No answers in response");

    let answer = &response.answers[0];
    if let DnsRData::A(rdata_ip) = &answer.rdata {
        assert_eq!(*rdata_ip, ip);
    } else {
        panic!("Wrong RData type: {:?}", answer.rdata);
    }

    // Cleanup: Shutdown context
    ctx.terminate();
}

#[tokio::test]
async fn dns_simulation_upstream() {
    let (ctx, db) = init_test_context().await;

    // 1. Setup Config with multiple upstreams
    #[allow(unused_mut)]
    let mut cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1054".parse().unwrap(),
        ..Default::default()
    };

    let _ = db.add_dns_upstream("1.1.1.1:53", "Udp", None).await;

    #[cfg(feature = "dot")]
    let _ = db.add_dns_upstream("1.1.1.1:853", "Tls", None).await;

    #[cfg(feature = "doq")]
    let _ = db.add_dns_upstream("94.140.14.14:784", "Quic", None).await;

    // 2. Start DNS Service
    let mut service = DnsService::new(cfg, ctx.clone(), db);
    let ctrl = ServiceControl::new("dns-upstream", ctx.clone());

    ctx.set_db_ready(true);
    let mut rx = ctx.bus().subscribe();

    tokio::spawn(async move {
        service.run(ctrl).await.expect("Service failed");
    });

    // Wait for ServiceReady
    loop {
        let event = rx.recv().await.expect("Bus closed");
        if let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = event.event
            && name == "dns-upstream"
        {
            break;
        }
    }

    // 3. Query for google.com
    let client_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect("127.0.0.1:1054").await.unwrap();

    let mut query = DnsMessage::new();
    query.header.id = 5678;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("google.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let query_bytes = encoder.encode_message(&query);

    client_sock.send(&query_bytes).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client_sock.recv(&mut buf))
        .await
        .expect("Timeout waiting for upstream DNS response")
        .expect("Recv failed");

    let mut decoder = WireDecoder::new(&buf[..n]);
    let response = decoder.decode_message().unwrap();

    // 4. Verify Response
    assert_eq!(response.header.id, 5678);
    assert_eq!(response.header.rcode, DnsResponseCode::NoError);
    assert!(!response.answers.is_empty(), "No answers for google.com");

    ctx.terminate();
}

#[tokio::test]
#[ignore]
async fn dns_simulation_cache_case_insensitive() {
    let (ctx, db) = init_test_context().await;

    let cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1056".parse().unwrap(),
        ..Default::default()
    };
    let _ = db.add_dns_upstream("1.1.1.1:53", "Udp", None).await;

    let mut service = DnsService::new(cfg, ctx.clone(), db);
    let ctrl = ServiceControl::new("dns-cache", ctx.clone());
    ctx.set_db_ready(true);
    let mut rx = ctx.bus().subscribe();

    tokio::spawn(async move {
        service.run(ctrl).await.expect("Service failed");
    });

    loop {
        let event = rx.recv().await.expect("Bus closed");
        if let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = event.event
            && name == "dns-cache"
        {
            break;
        }
    }

    let client_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect("127.0.0.1:1056").await.unwrap();

    // 1. First query: google.com (lowercase)
    let mut query1 = DnsMessage::new();
    query1.header.id = 1111;
    query1.header.qdcount = 1;
    query1.questions.push(DnsQuestion {
        name: Arc::from("google.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query1_bytes = WireEncoder::new().encode_message(&query1);
    client_sock.send(&query1_bytes).await.unwrap();
    let mut buf = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(5), client_sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let hits_before = ctx
        .get_dns_stats()
        .and_then(|s| s.downcast::<DnsStats>().ok())
        .map(|s| s.cache_hits.load(Ordering::Relaxed))
        .unwrap_or(0);

    // 2. Second query: GoOgLe.CoM (mixed case)
    let mut query2 = DnsMessage::new();
    query2.header.id = 2222;
    query2.header.qdcount = 1;
    query2.questions.push(DnsQuestion {
        name: Arc::from("GoOgLe.CoM"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query2_bytes = WireEncoder::new().encode_message(&query2);
    client_sock.send(&query2_bytes).await.unwrap();
    let n2 = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let mut decoder = WireDecoder::new(&buf[..n2]);
    let response = decoder.decode_message().unwrap();
    assert_eq!(response.header.id, 2222);
    assert!(!response.answers.is_empty());

    let hits_after = ctx
        .get_dns_stats()
        .and_then(|s| s.downcast::<DnsStats>().ok())
        .map(|s| s.cache_hits.load(Ordering::Relaxed))
        .unwrap_or(0);
    assert!(
        hits_after > hits_before,
        "Cache hit count did not increase for case-insensitive query"
    );

    ctx.terminate();
}
