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

#[tokio::test]
async fn dns_conditional_split_upstream_routing() {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let ctx = LanforgeContext::new(bus, table, None);

    // 1. Start mock global upstream (127.0.0.1:1071)
    let global_sock = TokioUdpSocket::bind("127.0.0.1:1071").await.unwrap();
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

    // 2. Start mock conditional upstream for corp.internal (127.0.0.1:1072)
    let corp_sock = TokioUdpSocket::bind("127.0.0.1:1072").await.unwrap();
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
    let global_target: UpstreamTarget = "udp://127.0.0.1:1071".parse().unwrap();
    let corp_target: UpstreamTarget = "udp://127.0.0.1:1072#corp.internal".parse().unwrap();
    assert_eq!(corp_target.domain.as_deref(), Some("corp.internal"));

    ctx.update_dns_upstreams(vec![global_target, corp_target]);

    // 4. Start Lanforge DNS on 127.0.0.1:1073
    let cfg = DnsConfig {
        enabled: true,
        listen: "127.0.0.1:1073".parse().unwrap(),
        search_domains: vec!["lan".to_string()],
        ..Default::default()
    };

    let mut service = DnsService::new(cfg, ctx.clone());
    let ctx_service = ctx.clone();
    ctx.set_db_ready(true);

    tokio::spawn(async move {
        service.serve(&ctx_service).await.expect("DNS Service failed");
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 5. Test resolution using a client socket
    let client = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect("127.0.0.1:1073").await.unwrap();

    let query_buf = [0u8; 1024];

    // Helper to send query and receive resolved A IP
    let query_a = |qname: &'static str| {
        let client_ref = &client;
        let mut q_buf = query_buf;
        async move {
            let mut msg = DnsMessage::new();
            msg.header.id = 999;
            msg.header.rd = true;
            msg.header.qdcount = 1;
            msg.questions.push(DnsQuestion {
                name: Arc::from(qname),
                qtype: DnsRecordType::A,
                qclass: DnsClass::IN,
            });
            let bytes = WireEncoder::new().encode_message(&msg);
            client_ref.send(&bytes).await.unwrap();

            let n = tokio::time::timeout(Duration::from_secs(3), client_ref.recv(&mut q_buf))
                .await
                .expect("DNS query timed out")
                .unwrap();

            let decoded = WireDecoder::new(&q_buf[..n]).decode_message().unwrap();
            assert_eq!(decoded.header.rcode, DnsResponseCode::NoError);
            assert!(!decoded.answers.is_empty(), "No answers returned for {qname}");
            match decoded.answers[0].rdata {
                DnsRData::A(ip) => ip,
                _ => panic!("Expected A record"),
            }
        }
    };

    // A) Global query: google.com -> routes to 127.0.0.1:1071 -> returns 8.8.8.8
    let ip_global = query_a("google.com").await;
    assert_eq!(ip_global, Ipv4Addr::new(8, 8, 8, 8));

    // B) Split DNS query: api.corp.internal -> routes to 127.0.0.1:1072 -> returns 10.0.0.99
    let ip_corp = query_a("api.corp.internal").await;
    assert_eq!(ip_corp, Ipv4Addr::new(10, 0, 0, 99));

    // C) Non-matching subdomain: other.internal -> routes to global -> returns 8.8.8.8
    let ip_other = query_a("other.internal").await;
    assert_eq!(ip_other, Ipv4Addr::new(8, 8, 8, 8));

    ctx.terminate();
}
