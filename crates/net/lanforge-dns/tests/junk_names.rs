//! Names a client loops on (an IP camera asking for `:0` forever) and the root name.
//!
//! The root `.` is a real query (`dig` with no name asks `. NS`) and goes to the upstreams; a
//! dotless name the LAN does not serve is answered NXDOMAIN by the router whatever its type,
//! and the query log folds the repeats into one line with their count, none lost on a stop.

#[path = "common/mod.rs"]
mod common;

use common::{
    DnsPacketBuilder, MockUpstreamServer, init_test_context, mock_config, parse_response,
    wait_for_service_online,
};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_types::network::dns::{DnsRecordType, DnsResponseCode, QueryLogEntry, QueryResult};
use lanforge_types::system::ServiceId;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn root_goes_upstream_and_a_junk_loop_is_one_counted_log_line() {
    let ctx = init_test_context();
    // The mock upstream answers NOERROR for the root ("" once the dot is trimmed) and NXDOMAIN
    // for anything else, with RA set: a reply that is not from the router.
    let mut records = HashMap::new();
    records.insert(String::new(), vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
    let upstream = MockUpstreamServer::spawn(records).await;
    ctx.update_dns_upstreams(vec![upstream.target()]);

    let mut dns_rx = ctx.bus().subscribe_dns();
    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
    let ctx_serve = ctx.clone();
    let serve = tokio::spawn(async move { service.serve(&ctx_serve, &h).await });
    wait_for_service_online(&ctx, ServiceId::Dns).await;

    let camera: SocketAddr = "192.168.1.60:40000".parse().unwrap();

    // 1. `. NS` is a valid query: forwarded, answered by the upstream (it used to be FORMERR).
    handle
        .inject(
            DnsPacketBuilder::query(".", DnsRecordType::NS)
                .with_id(1)
                .build_bytes(),
            camera,
        )
        .await;
    let (reply, _) = handle.recv_reply().await.expect("reply to . NS");
    let resp = parse_response(&reply).expect("valid reply");
    assert_eq!(
        resp.header.rcode,
        DnsResponseCode::NoError,
        "root forwarded"
    );
    assert!(resp.header.ra, "recursion available");
    assert!(
        !resp.header.aa,
        "the router is not authoritative for the root"
    );

    // 2. The camera loop: `:0` for A and for a non-address type, five times each. Every one is
    //    NXDOMAIN from the router itself (aa), never the upstream.
    for (i, qtype) in [DnsRecordType::A, DnsRecordType::TXT]
        .into_iter()
        .cycle()
        .take(10)
        .enumerate()
    {
        let id = 100 + u16::try_from(i).unwrap();
        handle
            .inject(
                DnsPacketBuilder::query(":0", qtype)
                    .with_id(id)
                    .build_bytes(),
                camera,
            )
            .await;
        let (reply, _) = handle.recv_reply().await.expect("reply to :0");
        let resp = parse_response(&reply).expect("valid reply");
        assert_eq!(resp.header.id, id);
        assert_eq!(resp.header.rcode, DnsResponseCode::NXDomain, "{qtype:?}");
        assert!(resp.header.aa, "{qtype:?} answered by the router");
        assert!(resp.header.ra, "{qtype:?}: the router does recurse");
    }

    // 2b. Any dotless name, not just `:0`: a browser's HTTPS lookup for `printer` (no such
    //     device) is NXDOMAIN from the router, not forwarded.
    handle
        .inject(
            DnsPacketBuilder::query("printer", DnsRecordType::HTTPS)
                .with_id(200)
                .build_bytes(),
            camera,
        )
        .await;
    let (reply, _) = handle.recv_reply().await.expect("reply to printer HTTPS");
    let resp = parse_response(&reply).expect("valid reply");
    assert_eq!(resp.header.rcode, DnsResponseCode::NXDomain);
    assert!(resp.header.aa, "answered by the router, not the upstream");

    // 3. Stop: the folded counts are written before serve returns.
    cmd_tx.send(ServiceCommand::Stop).await.expect("alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop")
        .expect("join")
        .expect("serve ok");

    let mut lines: Vec<Arc<QueryLogEntry>> = Vec::new();
    while let Ok(event) = dns_rx.try_recv() {
        if let LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)) = event.event {
            lines.push(entry);
        }
    }
    let junk: Vec<_> = lines.iter().filter(|e| e.domain.as_ref() == ":0").collect();
    for qtype in [DnsRecordType::A, DnsRecordType::TXT] {
        let mut counts: Vec<u32> = junk
            .iter()
            .filter(|e| e.qtype == qtype)
            .map(|e| {
                assert_eq!(e.result, QueryResult::Local, "never forwarded");
                e.repeats
            })
            .collect();
        counts.sort_unstable();
        assert_eq!(
            counts,
            vec![1, 4],
            "{qtype:?}: first line, then one line for 4 repeats"
        );
    }
    assert!(
        lines
            .iter()
            .any(|e| e.qtype == DnsRecordType::NS && e.domain.as_ref() == "." && e.repeats == 1),
        "the root query is logged: {lines:?}"
    );
}

/// Malformed input answered by the header alone: a message with no question gets FORMERR (it
/// used to reach the pipeline as a root query and come back SERVFAIL), and a response sent to
/// the server is ignored, never answered (two servers would bounce it forever).
#[tokio::test]
async fn no_question_is_formerr_and_a_response_is_ignored() {
    let ctx = init_test_context();
    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let h = ServiceHandle::new(ServiceId::Dns, ctx.clone());
    let ctx_serve = ctx.clone();
    tokio::spawn(async move { service.serve(&ctx_serve, &h).await });
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    let client: SocketAddr = "192.168.1.61:40001".parse().unwrap();

    // Header only: id 0x4242, RD, QDCOUNT 0.
    let mut no_question = vec![0u8; 12];
    no_question[..2].copy_from_slice(&0x4242u16.to_be_bytes());
    no_question[2] = 0x01;
    handle.inject(no_question, client).await;
    let (reply, _) = timeout(Duration::from_secs(2), handle.recv_reply())
        .await
        .expect("a reply to a no-question message")
        .expect("reply");
    assert_eq!(reply.len(), 12, "header only");
    let resp = parse_response(&reply).expect("valid reply");
    assert_eq!(resp.header.id, 0x4242);
    assert!(resp.header.qr);
    assert_eq!(resp.header.rcode, DnsResponseCode::FormErr);
    assert_eq!(resp.header.qdcount, 0);

    // A response (QR=1) gets nothing, even for a name the router answers itself; the query
    // after it is the next thing answered.
    let mut response = DnsPacketBuilder::query("printer", DnsRecordType::A)
        .with_id(1)
        .build_bytes();
    response[2] |= 0x80;
    handle.inject(response, client).await;
    handle
        .inject(
            DnsPacketBuilder::query(":0", DnsRecordType::A)
                .with_id(2)
                .build_bytes(),
            client,
        )
        .await;
    let (reply, _) = timeout(Duration::from_secs(2), handle.recv_reply())
        .await
        .expect("an answer")
        .expect("reply");
    assert_eq!(parse_response(&reply).expect("valid").header.id, 2);
    ctx.terminate();
}
