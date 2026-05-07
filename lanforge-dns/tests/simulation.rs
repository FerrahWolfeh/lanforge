use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_dns::DnsService;
use lanforge_dns::config::{DnsConfig, PrioritizedUpstream};
use lanforge_core::types::{DeviceUpdate, MacAddr};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket as TokioUdpSocket;

fn init_test_context() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    LanforgeContext::new(bus, table, None)
}

#[tokio::test]
async fn test_dns_simulation_udp() {
    let ctx = init_test_context();

    // 1. Setup Config
    let cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1053".parse().unwrap(),
        search_domains: vec!["lan".to_string()],
        ..Default::default()
    };

    // Default multi_search_labels is [[b"lan"]]

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
    let mut service = DnsService::new(cfg, ctx.clone());
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

    let mut query = Message::query();
    query.metadata.id = 1234;
    query.add_query(Query::query(
        Name::from_str("my-device.lan.").unwrap(),
        RecordType::A,
    ));
    let query_bytes = query.to_vec().unwrap();

    client_sock.send(&query_bytes).await.unwrap();

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .expect("Timeout waiting for DNS response")
        .expect("Recv failed");

    let response = Message::from_vec(&buf[..n]).unwrap();

    // 5. Verify Response
    assert_eq!(response.metadata.id, 1234);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);

    assert!(!response.answers.is_empty(), "No answers in response");

    let answer = &response.answers[0];
    if let RData::A(rdata) = &answer.data {
        assert_eq!(u32::from(rdata.0), u32::from(ip));
    } else {
        panic!("Wrong RData type: {:?}", answer.data);
    }

    // Cleanup: Shutdown context
    ctx.terminate();
}

#[tokio::test]
async fn test_dns_simulation_upstream() {
    let ctx = init_test_context();

    // 1. Setup Config with multiple upstreams
    #[allow(unused_mut)]
    let mut cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1054".parse().unwrap(),
        upstreams: vec![PrioritizedUpstream {
            target: "1.1.1.1:53".parse().unwrap(),
            priority: 0,
        }],
        ..Default::default()
    };

    #[cfg(feature = "dot")]
    cfg.upstreams.push(PrioritizedUpstream {
        target: "tls://1.1.1.1:853".parse().unwrap(),
        priority: 1,
    });

    #[cfg(feature = "doq")]
    cfg.upstreams.push(PrioritizedUpstream {
        target: "quic://94.140.14.14:784".parse().unwrap(),
        priority: 2,
    });

    // 2. Start DNS Service
    let mut service = DnsService::new(cfg, ctx.clone());
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

    let mut query = Message::query();
    query.metadata.id = 5678;
    query.add_query(Query::query(
        Name::from_str("google.com.").unwrap(),
        RecordType::A,
    ));
    let query_bytes = query.to_vec().unwrap();

    client_sock.send(&query_bytes).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client_sock.recv(&mut buf))
        .await
        .expect("Timeout waiting for upstream DNS response")
        .expect("Recv failed");

    let response = Message::from_vec(&buf[..n]).unwrap();

    // 4. Verify Response
    assert_eq!(response.metadata.id, 5678);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.answers.is_empty(), "No answers for google.com");

    ctx.terminate();
}
