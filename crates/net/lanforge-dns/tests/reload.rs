#[path = "common/mod.rs"]
mod common;

use common::{
    DnsPacketBuilder, MockUpstreamServer, extract_a, init_test_context, mock_config,
    parse_response, wait_for_service_online,
};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_core::service::AsyncService;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsRData, DnsRecordType, DnsResponseCode,
};
use lanforge_types::network::dns::{DnsRequest, DnsResponse};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;

#[tokio::test]
async fn dns_reload_causes_full_cache_refresh_if_enabled() {
    let ctx = init_test_context();

    // 1. Setup mock upstream server
    let mut records = HashMap::new();
    records.insert(
        "example.com".to_string(),
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    );
    let mock_upstream1 = MockUpstreamServer::spawn(records).await;

    // Seed initial upstream in context
    ctx.update_dns_upstreams(vec![mock_upstream1.target()]);

    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };

    // 2. Start DNS Service in inert mode
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    ctx.set_db_ready(true);

    tokio::spawn(async move {
        let h = lanforge_core::service::ServiceHandle::new(lanforge_types::system::ServiceId::Dns, ctx_service.clone());
        service.serve(&ctx_service, &h).await.expect("Service failed");
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    // 3. Query once to populate the cache
    let client_addr: SocketAddr = "192.168.1.100:54327".parse().unwrap();
    let query_bytes = DnsPacketBuilder::query("example.com", DnsRecordType::A)
        .with_id(1234)
        .build_bytes();

    handle.inject(query_bytes, client_addr).await;

    let (reply, _) = handle.recv_reply().await.expect("Expected DNS reply");
    let resp = parse_response(&reply).expect("Valid DNS message");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    assert_eq!(extract_a(&resp), vec![Ipv4Addr::new(93, 184, 216, 34)]);

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
            res.total > 0,
            "Cache should have entries before upstream change"
        );
    } else {
        panic!("Expected CacheDump response");
    }

    // 4. Update upstreams with new mock upstream and broadcast event
    let mut new_records = HashMap::new();
    new_records.insert(
        "example.com".to_string(),
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))],
    );
    let mock_upstream2 = MockUpstreamServer::spawn(new_records).await;
    let new_target = mock_upstream2.target();

    ctx.update_dns_upstreams(vec![new_target.clone()]);
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigUpstreamsChanged));

    // Wait a brief moment for cache invalidation to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 5. Verify cache has been completely invalidated/flushed
    let cache_dump_after = dns_handle
        .send_request(DnsRequest::CacheDump {
            limit: None,
            offset: None,
            q: None,
            kind: None,
        })
        .await
        .unwrap();

    if let DnsResponse::CacheDump(res) = cache_dump_after {
        assert_eq!(
            res.total, 0,
            "Cache should be completely cleared after upstream reload"
        );
    } else {
        panic!("Expected CacheDump response");
    }

    ctx.terminate();
}

#[tokio::test]
async fn dns_reload_rewrites_on_the_fly() {
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
        service.serve(&ctx_service, &h).await.expect("Service failed");
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    let client_addr: SocketAddr = "192.168.1.100:54328".parse().unwrap();
    let query_bytes = DnsPacketBuilder::query("my-site.lan", DnsRecordType::A)
        .with_id(4321)
        .build_bytes();

    // 1. Query once for my-site.lan (should return ServFail or NXDOMAIN because no rewrites exist)
    handle.inject(query_bytes.clone(), client_addr).await;

    let (reply, _) = handle.recv_reply().await.expect("Expected DNS reply");
    let resp = parse_response(&reply).expect("Valid DNS message");
    assert_ne!(resp.header.rcode, DnsResponseCode::NoError);

    // 2. Update rewrites in the context and trigger reload
    ctx.update_dns_rewrites(vec![RewriteRule {
        id: Some(1),
        domain: "my-site.lan".to_string(),
        rtype: DnsRecordType::A,
        answer: RewriteAnswer::A(Ipv4Addr::new(1, 2, 3, 4)),
    }]);

    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Query again (should now return 1.2.3.4 via rewrite)
    handle.inject(query_bytes, client_addr).await;

    let (reply2, _) = handle.recv_reply().await.expect("Expected DNS reply after rewrite reload");
    let resp2 = parse_response(&reply2).expect("Valid DNS message");
    assert_eq!(resp2.header.rcode, DnsResponseCode::NoError);
    assert_eq!(extract_a(&resp2), vec![Ipv4Addr::new(1, 2, 3, 4)]);

    ctx.terminate();
}

#[tokio::test]
async fn dns_conditional_split_upstream_routing() {
    let ctx = init_test_context();

    // 1. Start mock global upstream on ephemeral port
    let global_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let global_addr = global_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((len, src)) = global_sock.recv_from(&mut buf).await {
            if let Some(req) = WireDecoder::new(&buf[..len]).decode_message() {
                let mut resp = DnsMessage::new();
                resp.header.id = req.header.id;
                resp.header.qr = true;
                resp.header.qdcount = req.questions.len() as u16;
                resp.header.ancount = 1;
                resp.header.rcode = DnsResponseCode::NoError;
                resp.questions = req.questions.clone();
                if let Some(q) = req.questions.first() {
                    resp.answers.push(lanforge_types::network::dns::DnsRecord {
                        name: q.name.clone(),
                        rtype: DnsRecordType::A,
                        rclass: DnsClass::IN,
                        ttl: 300,
                        rdata: DnsRData::A(Ipv4Addr::new(8, 8, 8, 8)),
                    });
                }
                let bytes = WireEncoder::new().encode_message(&resp);
                let _ = global_sock.send_to(&bytes, src).await;
            }
        }
    });

    // 2. Start mock conditional upstream for corp.internal on ephemeral port
    let corp_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let corp_addr = corp_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((len, src)) = corp_sock.recv_from(&mut buf).await {
            if let Some(req) = WireDecoder::new(&buf[..len]).decode_message() {
                let mut resp = DnsMessage::new();
                resp.header.id = req.header.id;
                resp.header.qr = true;
                resp.header.qdcount = req.questions.len() as u16;
                resp.header.ancount = 1;
                resp.header.rcode = DnsResponseCode::NoError;
                resp.questions = req.questions.clone();
                if let Some(q) = req.questions.first() {
                    resp.answers.push(lanforge_types::network::dns::DnsRecord {
                        name: q.name.clone(),
                        rtype: DnsRecordType::A,
                        rclass: DnsClass::IN,
                        ttl: 300,
                        rdata: DnsRData::A(Ipv4Addr::new(10, 0, 0, 99)),
                    });
                }
                let bytes = WireEncoder::new().encode_message(&resp);
                let _ = corp_sock.send_to(&bytes, src).await;
            }
        }
    });

    // 3. Configure upstreams: global + conditional for corp.internal
    let global_target: UpstreamTarget = format!("udp://{global_addr}").parse().unwrap();
    let corp_target: UpstreamTarget = format!("udp://{corp_addr}#corp.internal").parse().unwrap();
    assert_eq!(corp_target.domain.as_deref(), Some("corp.internal"));

    ctx.update_dns_upstreams(vec![global_target, corp_target]);

    // 4. Start Lanforge DNS in inert mode
    let cfg = DnsConfig {
        enabled: true,
        search_domains: vec!["lan".to_string()],
        ..mock_config()
    };

    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    ctx.set_db_ready(true);

    tokio::spawn(async move {
        let h = lanforge_core::service::ServiceHandle::new(lanforge_types::system::ServiceId::Dns, ctx_service.clone());
        service.serve(&ctx_service, &h).await.expect("DNS Service failed");
    });

    wait_for_service_online(&ctx, lanforge_types::system::ServiceId::Dns).await;

    let client_addr: SocketAddr = "192.168.1.100:54329".parse().unwrap();

    // Helper to query domain
    let query_a = |qname: &'static str| {
        let handle_ref = handle.clone();
        async move {
            let query_bytes = DnsPacketBuilder::query(qname, DnsRecordType::A)
                .with_id(999)
                .build_bytes();
            handle_ref.inject(query_bytes, client_addr).await;

            let (reply, _) = handle_ref.recv_reply().await.expect("Expected reply for split query");
            let resp = parse_response(&reply).expect("Valid DNS response");
            assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
            extract_a(&resp)[0]
        }
    };

    // A) Global query: google.com -> routes to global -> returns 8.8.8.8
    let ip_global = query_a("google.com").await;
    assert_eq!(ip_global, Ipv4Addr::new(8, 8, 8, 8));

    // B) Split DNS query: api.corp.internal -> routes to corp.internal -> returns 10.0.0.99
    let ip_corp = query_a("api.corp.internal").await;
    assert_eq!(ip_corp, Ipv4Addr::new(10, 0, 0, 99));

    // C) Non-matching subdomain: other.internal -> routes to global -> returns 8.8.8.8
    let ip_other = query_a("other.internal").await;
    assert_eq!(ip_other, Ipv4Addr::new(8, 8, 8, 8));

    ctx.terminate();
}
