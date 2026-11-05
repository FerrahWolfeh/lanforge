#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions and setup"
)]
#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
//! Names under the site's domains (`.lan`) are the router's, whatever the query type.
//!
//! Owner box, 2026-11-03: `archie` answered every type locally, but `archie.lan` HTTPS/TXT/MX
//! (and anything under `.lan` the LAN does not know) went to the internet and came back as a
//! public NXDOMAIN — a leak of LAN names, and a "no such name" for a host that exists, which a
//! stub may cache against its A/AAAA too (RFC 8020). `lan` itself answered NXDOMAIN to A, which
//! denies every name under it. Local replies also echoed the query's AD bit.

#[path = "common/mod.rs"]
mod common;

use common::{
    DnsPacketBuilder, MockUpstreamServer, init_test_context, mock_config, parse_response,
    register_test_device, wait_for_service_online,
};
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::{DnsRecordType, DnsResponseCode};
use lanforge_types::system::ServiceId;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn site_names_never_leave_the_router() {
    use DnsRecordType::{A, AAAA, HTTPS, MX, NS, SOA, TXT};
    use DnsResponseCode::{NXDomain, NoError};

    let ctx = init_test_context();
    register_test_device(
        &ctx,
        "archie",
        MacAddr([0x02, 0, 0, 0, 0, 0x57]),
        Ipv4Addr::new(192, 168, 1, 2),
    );
    // The mock upstream answers NXDOMAIN to every name, without AA: a reply that is not the
    // router's own.
    let upstream = MockUpstreamServer::spawn(HashMap::new()).await;
    ctx.update_dns_upstreams(vec![upstream.target()]);

    let cfg = DnsConfig {
        enabled: true,
        ..mock_config() // search domain `lan`
    };
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
    let ctx_serve = ctx.clone();
    let serve = tokio::spawn(async move { service.serve(&ctx_serve, &h).await });
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    let client: SocketAddr = "192.168.1.50:40000".parse().unwrap();

    // (name, type, rcode, answers, answered by the router)
    let cases = [
        ("archie.lan", A, NoError, 1, true),
        ("archie.lan", HTTPS, NoError, 0, true),
        ("archie.lan", TXT, NoError, 0, true),
        ("archie.lan", MX, NoError, 0, true),
        ("archie.lan", NS, NoError, 0, true),
        ("ARCHIE.Lan", HTTPS, NoError, 0, true),
        ("naoexiste.lan", A, NXDomain, 0, true),
        ("naoexiste.lan", HTTPS, NXDomain, 0, true),
        ("x.archie.lan", A, NXDomain, 0, true),
        ("x.archie.lan", TXT, NXDomain, 0, true),
        ("lan", A, NoError, 0, true),
        ("lan", SOA, NoError, 0, true),
        ("archie", AAAA, NoError, 0, true),
        ("archie", NS, NoError, 0, true),
        ("printer", HTTPS, NXDomain, 0, true),
        // Not the router's: the root and TLD delegation lookups, and public names.
        ("com", NS, NXDomain, 0, false),
        ("example.com", A, NXDomain, 0, false),
        ("example.com", HTTPS, NXDomain, 0, false),
    ];
    let mut report = String::new();
    for (i, (name, qtype, rcode, answers, local)) in cases.into_iter().enumerate() {
        let id = 10 + u16::try_from(i).unwrap();
        handle
            .inject(
                DnsPacketBuilder::query(name, qtype)
                    .with_id(id)
                    .build_bytes(),
                client,
            )
            .await;
        let (reply, _) = handle.recv_reply().await.expect("reply");
        let resp = parse_response(&reply).expect("valid reply");
        let got = (resp.header.rcode, resp.answers.len(), resp.header.aa);
        if got != (rcode, answers, local) {
            report.push_str(&format!(
                "{name} {qtype:?}: got {got:?}, want {:?}\n",
                (rcode, answers, local)
            ));
        }
    }
    assert!(report.is_empty(), "\n{report}");

    cmd_tx.send(ServiceCommand::Stop).await.expect("alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop")
        .expect("join")
        .expect("serve ok");
}

/// `dig` sets AD in every query. A reply the router writes itself must not echo it — AD claims
/// DNSSEC-validated data (RFC 4035 §3.2.3) — nor Z; CD is copied back (RFC 6840 §5.9).
#[tokio::test]
async fn local_replies_do_not_claim_validated_data() {
    let ctx = init_test_context();
    register_test_device(
        &ctx,
        "archie",
        MacAddr([0x02, 0, 0, 0, 0, 0x57]),
        Ipv4Addr::new(192, 168, 1, 2),
    );
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
    let client: SocketAddr = "192.168.1.50:40000".parse().unwrap();

    // An address answer, a NODATA and an NXDOMAIN: three writers.
    for (id, name, qtype, cd) in [
        (1, "archie.lan", DnsRecordType::A, false),
        (2, "archie.lan", DnsRecordType::A, true),
        (3, "archie", DnsRecordType::TXT, false),
        (4, "naoexiste.lan", DnsRecordType::AAAA, true),
    ] {
        handle
            .inject(
                DnsPacketBuilder::query(name, qtype)
                    .with_id(id)
                    .with_ad(true)
                    .with_cd(cd)
                    .build_bytes(),
                client,
            )
            .await;
        let (reply, _) = handle.recv_reply().await.expect("reply");
        let resp = parse_response(&reply).expect("valid reply");
        assert!(resp.header.aa, "{name} {qtype:?} is local");
        assert!(!resp.header.ad, "{name} {qtype:?}: AD echoed");
        assert!(!resp.header.z, "{name} {qtype:?}: Z set");
        assert_eq!(resp.header.cd, cd, "{name} {qtype:?}: CD not copied");
    }

    cmd_tx.send(ServiceCommand::Stop).await.expect("alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop")
        .expect("join")
        .expect("serve ok");
}
