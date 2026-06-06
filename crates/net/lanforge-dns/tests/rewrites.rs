mod common;

use common::*;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, DnsResponseCode,
};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

#[tokio::test]
async fn test_dns_rewrites_integration() {
    let ctx = init_test_context();
    let mut cfg = mock_config();

    // Setup test rewrite rules
    cfg.rewrites = vec![
        // 1. dev: target with hostname lookup
        RewriteRule {
            id: None,
            domain: "nas.home".to_string(),
            rtype: DnsRecordType::A,
            answer: RewriteAnswer::from_str("dev:nas-box").unwrap(),
        },
        // 2. dev: target with MAC address lookup
        RewriteRule {
            id: None,
            domain: "printer.home".to_string(),
            rtype: DnsRecordType::A,
            answer: RewriteAnswer::from_str("dev:00:11:22:33:44:55").unwrap(),
        },
        // 3. dev: target offline with fallback IP
        RewriteRule {
            id: None,
            domain: "nas-fallback.home".to_string(),
            rtype: DnsRecordType::A,
            answer: RewriteAnswer::from_str("dev:offline-nas|192.168.1.99").unwrap(),
        },
        // 4. dev: target offline without fallback (returns NXDOMAIN)
        RewriteRule {
            id: None,
            domain: "nas-offline.home".to_string(),
            rtype: DnsRecordType::A,
            answer: RewriteAnswer::from_str("dev:offline-nas").unwrap(),
        },
        // 5. srv: service discovery rule
        RewriteRule {
            id: None,
            domain: "_http._tcp.nas.home".to_string(),
            rtype: DnsRecordType::SRV,
            answer: RewriteAnswer::from_str("srv:http:tcp:nas-box:8096").unwrap(),
        },
    ];

    // Register active devices in the state
    let nas_mac = MacAddr([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let printer_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    register_test_device(&ctx, "nas-box", nas_mac, Ipv4Addr::new(192, 168, 1, 10));
    register_test_device(
        &ctx,
        "printer-box",
        printer_mac,
        Ipv4Addr::new(192, 168, 1, 20),
    );

    let dns_ctx = mock_dns_context(ctx, cfg).await;

    // --- Query 1: dev:nas-box (hostname, online) ---
    {
        let mut query = DnsMessage::new();
        query.header.id = 1;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from("nas.home"),
            qtype: DnsRecordType::A,
            qclass: DnsClass::IN,
        });

        let mut encoder = WireEncoder::new();
        let query_bytes = encoder.encode_message(&query);
        let mut resp_bytes = Vec::new();

        let resolved = process_query_test(
            &query_bytes,
            &dns_ctx,
            "127.0.0.1".parse().unwrap(),
            &mut resp_bytes,
        )
        .await
        .unwrap();
        assert!(resolved);

        let mut decoder = WireDecoder::new(&resp_bytes);
        let response = decoder.decode_message().unwrap();
        assert_eq!(response.header.rcode, DnsResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, 5); // Short TTL for dev: resolve
        if let DnsRData::A(ip) = response.answers[0].rdata {
            assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 10));
        } else {
            panic!("Expected A record");
        }
    }

    // --- Query 2: dev:00:11:22:33:44:55 (MAC, online) ---
    {
        let mut query = DnsMessage::new();
        query.header.id = 2;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from("printer.home"),
            qtype: DnsRecordType::A,
            qclass: DnsClass::IN,
        });

        let mut encoder = WireEncoder::new();
        let query_bytes = encoder.encode_message(&query);
        let mut resp_bytes = Vec::new();

        let resolved = process_query_test(
            &query_bytes,
            &dns_ctx,
            "127.0.0.1".parse().unwrap(),
            &mut resp_bytes,
        )
        .await
        .unwrap();
        assert!(resolved);

        let mut decoder = WireDecoder::new(&resp_bytes);
        let response = decoder.decode_message().unwrap();
        assert_eq!(response.header.rcode, DnsResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, 5); // Short TTL
        if let DnsRData::A(ip) = response.answers[0].rdata {
            assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 20));
        } else {
            panic!("Expected A record");
        }
    }

    // --- Query 3: dev:offline-nas|192.168.1.99 (offline, fallback IP) ---
    {
        let mut query = DnsMessage::new();
        query.header.id = 3;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from("nas-fallback.home"),
            qtype: DnsRecordType::A,
            qclass: DnsClass::IN,
        });

        let mut encoder = WireEncoder::new();
        let query_bytes = encoder.encode_message(&query);
        let mut resp_bytes = Vec::new();

        let resolved = process_query_test(
            &query_bytes,
            &dns_ctx,
            "127.0.0.1".parse().unwrap(),
            &mut resp_bytes,
        )
        .await
        .unwrap();
        assert!(resolved);

        let mut decoder = WireDecoder::new(&resp_bytes);
        let response = decoder.decode_message().unwrap();
        assert_eq!(response.header.rcode, DnsResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        if let DnsRData::A(ip) = response.answers[0].rdata {
            assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 99));
        } else {
            panic!("Expected fallback A record");
        }
    }

    // --- Query 4: dev:offline-nas (offline, no fallback -> NXDOMAIN) ---
    {
        let mut query = DnsMessage::new();
        query.header.id = 4;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from("nas-offline.home"),
            qtype: DnsRecordType::A,
            qclass: DnsClass::IN,
        });

        let mut encoder = WireEncoder::new();
        let query_bytes = encoder.encode_message(&query);
        let mut resp_bytes = Vec::new();

        let resolved = process_query_test(
            &query_bytes,
            &dns_ctx,
            "127.0.0.1".parse().unwrap(),
            &mut resp_bytes,
        )
        .await
        .unwrap();
        assert!(resolved);

        let mut decoder = WireDecoder::new(&resp_bytes);
        let response = decoder.decode_message().unwrap();
        assert_eq!(response.header.rcode, DnsResponseCode::NXDomain);
    }

    // --- Query 5: srv:http:tcp:nas-box:8096 (SRV Record) ---
    {
        let mut query = DnsMessage::new();
        query.header.id = 5;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from("_http._tcp.nas.home"),
            qtype: DnsRecordType::SRV,
            qclass: DnsClass::IN,
        });

        let mut encoder = WireEncoder::new();
        let query_bytes = encoder.encode_message(&query);
        let mut resp_bytes = Vec::new();

        let resolved = process_query_test(
            &query_bytes,
            &dns_ctx,
            "127.0.0.1".parse().unwrap(),
            &mut resp_bytes,
        )
        .await
        .unwrap();
        assert!(resolved);

        let mut decoder = WireDecoder::new(&resp_bytes);
        let response = decoder.decode_message().unwrap();
        assert_eq!(response.header.rcode, DnsResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, 5); // Short TTL
        if let DnsRData::SRV {
            priority,
            weight,
            port,
            target,
        } = &response.answers[0].rdata
        {
            assert_eq!(*priority, 0);
            assert_eq!(*weight, 0);
            assert_eq!(*port, 8096);
            assert_eq!(target.as_ref(), "nas-box.lan");
        } else {
            panic!("Expected SRV record");
        }
    }
}
