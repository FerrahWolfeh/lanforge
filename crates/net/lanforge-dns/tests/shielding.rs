mod common;

use common::*;
use lanforge_dns::resolver::recursive::{UpstreamManager, UpstreamMode, UpstreamStrategy};
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::upstream::{UpstreamProtocol, UpstreamTarget};
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecord, DnsRecordType, DnsResponseCode,
};
use std::sync::Arc;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_dns_local_shielding_anti_poisoning() {
    // 1. Setup mock upstream DNS server on localhost UDP
    let mock_upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = mock_upstream_socket.local_addr().unwrap();

    // Start mock upstream in the background
    // If it receives any query, it will reply with a spoofed A record for nonexistent.lan
    let (tx_queries, mut rx_queries) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
    let mock_upstream_task = tokio::spawn({
        let socket = mock_upstream_socket;
        async move {
            let mut buf = [0u8; 1024];
            loop {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        let (n, client_addr) = res.unwrap();
                        let query_data = buf[..n].to_vec();

                        // Report that we received a query
                        let _ = tx_queries.send(query_data.clone()).await;

                        // Decode query
                        let query_msg = WireDecoder::new(&query_data).decode_message().unwrap();
                        let qname = query_msg.questions[0].name.clone();

                        // Construct spoofed response
                        let mut resp = DnsMessage::new();
                        resp.header.id = query_msg.header.id;
                        resp.header.qr = true;
                        resp.header.qdcount = 1;
                        resp.header.ancount = 1;
                        resp.questions.push(query_msg.questions[0].clone());
                        resp.answers.push(DnsRecord {
                            name: qname,
                            rtype: DnsRecordType::A,
                            rclass: DnsClass::IN,
                            ttl: 60,
                            rdata: DnsRData::A("1.2.3.4".parse().unwrap()),
                        });

                        let resp_bytes = WireEncoder::new().encode_message(&resp);
                        socket.send_to(&resp_bytes, client_addr).await.unwrap();
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        // safety break
                        break;
                    }
                }
            }
        }
    });

    // 2. Setup DnsContext with search domain "lan" and the mock upstream
    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.search_domains = vec!["lan".to_string()];
    cfg.multi_search_labels = vec![vec![b"lan".to_vec()]];

    let mut dns_ctx = mock_dns_context(ctx_instance, cfg).await;

    // Replace DnsContext's upstream strategy with our configured mock upstream
    let target = UpstreamTarget {
        addr: upstream_addr,
        protocol: UpstreamProtocol::Udp,
        hostname: None,
        domain: None,
    };
    let mgr = UpstreamManager::new(&target, dns_ctx.cache.clone())
        .await
        .unwrap();
    let recursive_strategy = UpstreamStrategy::new(UpstreamMode::Sequential, vec![mgr]);
    dns_ctx.recursive = Arc::new(recursive_strategy);

    // 3. Query nonexistent.lan (matching search domain)
    let mut query = DnsMessage::new();
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("nonexistent.lan"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query_data = WireEncoder::new().encode_message(&query);
    let mut resp_buf = Vec::new();

    let has_resp = process_query_test(
        &query_data,
        &dns_ctx,
        "127.0.0.1".parse().unwrap(),
        &mut resp_buf,
    )
    .await
    .unwrap();

    assert!(has_resp);
    let mut decoder = WireDecoder::new(&resp_buf);
    let resp = decoder.decode_message().unwrap();

    // Verify response is NXDomain and NOT the spoofed 1.2.3.4
    assert_eq!(resp.header.rcode, DnsResponseCode::NXDomain);
    assert_eq!(resp.answers.len(), 0);

    // Check if the mock upstream received any query for nonexistent.lan
    // Since it's local search domain, shielding should prevent forwarding!
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let query_received = rx_queries.try_recv().is_ok();
    assert!(
        !query_received,
        "Anti-poisoning/local shielding failed! Upstream was queried for a local search domain."
    );

    // 4. Query a non-local domain (e.g. google.com) to verify upstream forwarding still works normally
    let mut query_ext = DnsMessage::new();
    query_ext.header.qdcount = 1;
    query_ext.questions.push(DnsQuestion {
        name: Arc::from("google.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query_ext_data = WireEncoder::new().encode_message(&query_ext);
    let mut resp_ext_buf = Vec::new();

    let has_resp_ext = process_query_test(
        &query_ext_data,
        &dns_ctx,
        "127.0.0.1".parse().unwrap(),
        &mut resp_ext_buf,
    )
    .await
    .unwrap();

    assert!(has_resp_ext);
    let mut decoder_ext = WireDecoder::new(&resp_ext_buf);
    let resp_ext = decoder_ext.decode_message().unwrap();

    // Verify we got the spoofed reply from our mock upstream
    assert_eq!(resp_ext.header.rcode, DnsResponseCode::NoError);
    assert_eq!(resp_ext.answers.len(), 1);
    if let DnsRData::A(ip) = &resp_ext.answers[0].rdata {
        assert_eq!(ip.to_string(), "1.2.3.4");
    } else {
        panic!("Wrong RData type: {:?}", resp_ext.answers[0].rdata);
    }

    // Verify mock upstream received the query this time
    let ext_query_received = rx_queries.try_recv().is_ok();
    assert!(
        ext_query_received,
        "Upstream forwarding failed for non-local domain."
    );

    // Clean up task
    mock_upstream_task.abort();
}
