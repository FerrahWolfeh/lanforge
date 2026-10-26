#[path = "common/mod.rs"]
mod common;

use common::{
    DnsPacketBuilder, MockUpstreamServer, extract_a, extract_ptr, init_test_context,
    mock_config, parse_response, wait_for_service_online,
};
use lanforge_core::service::AsyncService;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_dns::telemetry::DnsStats;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::device::TransientOrigin;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::upstream::{UpstreamProtocol, UpstreamTarget};
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsRData, DnsRecord, DnsRecordType, DnsResponseCode,
};
use lanforge_types::network::{DnsReverseResolver, IpSubnet};
use lanforge_types::update::DeviceUpdate;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket as TokioUdpSocket;

#[tokio::test]
async fn dns_simulation_udp() {
    let ctx = init_test_context();

    // 1. Setup Config
    let cfg = DnsConfig {
        enabled: true,
        search_domains: vec!["lan".to_string()],
        ..mock_config()
    };

    // 2. Register a device for local resolution
    let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv4Addr::new(192, 168, 1, 50);
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip,
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "my-device".to_string(),
    });

    // 3. Start DNS Service in inert mode
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    ctx.set_db_ready(true);

    tokio::spawn(async move {
        let h = lanforge_core::service::ServiceHandle::new(lanforge_types::system::ServiceId::Dns, ctx_service.clone());
        service.serve(&ctx_service, &h).await.expect("Service failed");
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    // 4. Send DNS query for "my-device.lan" via inert transport
    let client_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let query_bytes = DnsPacketBuilder::query("my-device.lan", DnsRecordType::A)
        .with_id(1234)
        .build_bytes();

    handle.inject(query_bytes, client_addr).await;

    let (reply_bytes, dest) = handle.recv_reply().await.expect("Expected DNS reply");
    assert_eq!(dest, client_addr);

    let response = parse_response(&reply_bytes).expect("Valid DNS response");

    // 5. Verify Response
    assert_eq!(response.header.id, 1234);
    assert_eq!(response.header.rcode, DnsResponseCode::NoError);
    assert_eq!(extract_a(&response), vec![ip]);

    // 6. Test Reverse DNS Lookup (PTR)
    let ptr_query_bytes = DnsPacketBuilder::query_ptr(IpAddr::V4(ip))
        .with_id(4321)
        .build_bytes();

    handle.inject(ptr_query_bytes, client_addr).await;

    let (ptr_reply_bytes, _) = handle.recv_reply().await.expect("Expected PTR reply");
    let ptr_response = parse_response(&ptr_reply_bytes).expect("Valid PTR response");

    assert_eq!(ptr_response.header.id, 4321);
    assert_eq!(ptr_response.header.rcode, DnsResponseCode::NoError);
    assert_eq!(extract_ptr(&ptr_response), vec!["my-device.lan".to_string()]);

    ctx.terminate();
}

#[tokio::test]
async fn dns_simulation_forwarding_fallback() {
    let ctx = init_test_context();

    // 1. Spawn local mock upstream server with answer for google.com
    let expected_ip = IpAddr::V4(Ipv4Addr::new(142, 250, 190, 46));
    let mut records = HashMap::new();
    records.insert("google.com".to_string(), vec![expected_ip]);
    let mock_upstream = MockUpstreamServer::spawn(records).await;

    ctx.update_dns_upstreams(vec![mock_upstream.target()]);

    // 2. Setup Config
    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };

    // 3. Start DNS Service in inert mode
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    ctx.set_db_ready(true);

    tokio::spawn(async move {
        let h = lanforge_core::service::ServiceHandle::new(lanforge_types::system::ServiceId::Dns, ctx_service.clone());
        service.serve(&ctx_service, &h).await.expect("Service failed");
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    // 4. Query for google.com via inert transport
    let client_addr: SocketAddr = "192.168.1.100:54322".parse().unwrap();
    let query_bytes = DnsPacketBuilder::query("google.com", DnsRecordType::A)
        .with_id(5678)
        .build_bytes();

    handle.inject(query_bytes, client_addr).await;

    let (reply_bytes, dest) = handle.recv_reply().await.expect("Expected reply from upstream");
    assert_eq!(dest, client_addr);

    let response = parse_response(&reply_bytes).expect("Valid DNS response");

    // 5. Verify Response
    assert_eq!(response.header.id, 5678);
    assert_eq!(response.header.rcode, DnsResponseCode::NoError);
    assert_eq!(extract_a(&response), vec![Ipv4Addr::new(142, 250, 190, 46)]);

    ctx.terminate();
}

#[tokio::test]
async fn dns_simulation_cache_case_insensitive() {
    let ctx = init_test_context();

    let expected_ip = IpAddr::V4(Ipv4Addr::new(142, 250, 190, 46));
    let mut records = HashMap::new();
    records.insert("google.com".to_string(), vec![expected_ip]);
    let mock_upstream = MockUpstreamServer::spawn(records).await;

    ctx.update_dns_upstreams(vec![mock_upstream.target()]);

    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };

    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    ctx.set_db_ready(true);

    tokio::spawn(async move {
        let h = lanforge_core::service::ServiceHandle::new(lanforge_types::system::ServiceId::Dns, ctx_service.clone());
        service.serve(&ctx_service, &h).await.expect("Service failed");
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    let client_addr: SocketAddr = "192.168.1.100:54323".parse().unwrap();

    // 1. First query: google.com (lowercase)
    let query1_bytes = DnsPacketBuilder::query("google.com", DnsRecordType::A)
        .with_id(1111)
        .build_bytes();

    handle.inject(query1_bytes, client_addr).await;

    let (reply1, _) = handle.recv_reply().await.expect("Expected reply for query1");
    let resp1 = parse_response(&reply1).expect("Valid response 1");
    assert_eq!(resp1.header.id, 1111);
    assert_eq!(extract_a(&resp1), vec![Ipv4Addr::new(142, 250, 190, 46)]);

    let hits_before = ctx
        .get_shared::<DnsStats>()
        .map(|s| s.cache_hits.load(Ordering::Relaxed))
        .unwrap_or(0);

    // 2. Second query: GoOgLe.CoM (mixed case)
    let query2_bytes = DnsPacketBuilder::query("GoOgLe.CoM", DnsRecordType::A)
        .with_id(2222)
        .build_bytes();

    handle.inject(query2_bytes, client_addr).await;

    let (reply2, _) = handle.recv_reply().await.expect("Expected reply for query2");
    let resp2 = parse_response(&reply2).expect("Valid response 2");
    assert_eq!(resp2.header.id, 2222);
    assert_eq!(extract_a(&resp2), vec![Ipv4Addr::new(142, 250, 190, 46)]);

    let hits_after = ctx
        .get_shared::<DnsStats>()
        .map(|s| s.cache_hits.load(Ordering::Relaxed))
        .unwrap_or(0);

    assert!(
        hits_after > hits_before,
        "Cache hit count did not increase for case-insensitive query (before: {hits_before}, after: {hits_after})"
    );

    ctx.terminate();
}

#[tokio::test]
async fn dns_simulation_malformed_and_special_prefixes() {
    let ctx = init_test_context();

    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };

    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    ctx.set_db_ready(true);

    tokio::spawn(async move {
        let h = lanforge_core::service::ServiceHandle::new(lanforge_types::system::ServiceId::Dns, ctx_service.clone());
        let _ = service.serve(&ctx_service, &h).await;
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    let client_addr: SocketAddr = "192.168.1.100:54324".parse().unwrap();

    // 1. TEST CASE: Sending complete garbage bytes (Not a valid DNS message)
    let garbage = vec![0u8; 20];
    handle.inject(garbage, client_addr).await;

    // The service returns FormErr with ID 0
    let (garbage_reply, _) = handle.recv_reply().await.expect("Expected reply for garbage");
    let resp = parse_response(&garbage_reply).expect("Valid DNS response");
    assert_eq!(resp.header.id, 0);
    assert_eq!(resp.header.rcode, DnsResponseCode::FormErr);

    // 2. Verify service is still alive and responds to custom queries
    let query_bytes = DnsPacketBuilder::query("invalid-prefix:something.lan", DnsRecordType::A)
        .with_id(9999)
        .build_bytes();

    handle.inject(query_bytes, client_addr).await;

    let (reply_bytes, _) = handle.recv_reply().await.expect("Service must respond after garbage");
    let response = parse_response(&reply_bytes).expect("Valid response");
    assert_eq!(response.header.id, 9999);
    assert_eq!(response.header.rcode, DnsResponseCode::NXDomain);

    ctx.terminate();
}

#[tokio::test]
async fn dns_simulation_transient_ip_reverse_dns() {
    let ctx = init_test_context();

    // 1. Bind mock DNS upstream server to 127.0.0.1:0
    let mock_upstream = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = mock_upstream.local_addr().unwrap();

    // 2. Setup Config
    let cfg = DnsConfig {
        enabled: true,
        search_domains: vec!["lan".to_string()],
        ..mock_config()
    };

    // Configure reverse resolver rule pointing to our mock upstream server
    let resolver_target = UpstreamTarget {
        addr: upstream_addr,
        protocol: UpstreamProtocol::Udp,
        hostname: None,
        domain: None,
    };
    let subnet = IpSubnet::from_str("127.0.0.1/32").unwrap();
    let resolver_rule = DnsReverseResolver {
        subnet,
        resolver: resolver_target,
    };
    ctx.add_reverse_resolver(resolver_rule);

    // 3. Start DNS Service in inert mode
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    ctx.set_db_ready(true);

    tokio::spawn(async move {
        let h = lanforge_core::service::ServiceHandle::new(lanforge_types::system::ServiceId::Dns, ctx_service.clone());
        service.serve(&ctx_service, &h).await.expect("Service failed");
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    // 4. Mock upstream behavior to answer PTR queries
    let (tx_shutdown, mut rx_shutdown) = tokio::sync::oneshot::channel::<()>();
    let mock_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        tokio::select! {
            res = mock_upstream.recv_from(&mut buf) => {
                if let Ok((len, src)) = res {
                    let mut decoder = WireDecoder::new(&buf[..len]);
                    let msg = decoder.decode_message().unwrap();
                    assert_eq!(msg.questions.len(), 1);
                    assert_eq!(msg.questions[0].qtype, DnsRecordType::PTR);

                    let mut resp_msg = DnsMessage::new();
                    resp_msg.header.id = msg.header.id;
                    resp_msg.header.qr = true;
                    resp_msg.header.qdcount = 1;
                    resp_msg.header.ancount = 1;
                    resp_msg.questions.push(msg.questions[0].clone());
                    resp_msg.answers.push(DnsRecord {
                        name: msg.questions[0].name.clone(),
                        rtype: DnsRecordType::PTR,
                        rclass: DnsClass::IN,
                        ttl: 30,
                        rdata: DnsRData::PTR(Arc::from("socket-transient.local.")),
                    });

                    let mut encoder = WireEncoder::new();
                    let resp_bytes = encoder.encode_message(&resp_msg);
                    let _ = mock_upstream.send_to(&resp_bytes, src).await;
                }
            }
            _ = &mut rx_shutdown => {}
        }
    });

    // 5. Send DNS query from 127.0.0.1 via inert client to trigger the background lookup
    let client_addr: SocketAddr = "127.0.0.1:54325".parse().unwrap();
    let query_bytes = DnsPacketBuilder::query("nonexistent-host.lan", DnsRecordType::A)
        .with_id(7777)
        .build_bytes();

    handle.inject(query_bytes, client_addr).await;

    let (_reply_bytes, _) = handle.recv_reply().await.expect("Expected reply");

    // 6. Poll until the background task resolves the transient IP
    let client_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut resolved = false;
    for _ in 0..50 {
        if let Some(host) = ctx.get_transient_host(&client_ip) {
            assert_eq!(host.hostname.name, "socket-transient.local");
            assert_eq!(host.origin, TransientOrigin::LocalPtr);
            resolved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        resolved,
        "Transient host resolution in background via sockets failed"
    );

    // Cleanup
    let _ = tx_shutdown.send(());
    let _ = mock_task.await;
    ctx.terminate();
}
