//! Names under the site's domains (`.lan`) are the router's, whatever the query type.
//!
//! Owner box, 2026-11-03: `archie` answered every type locally, but `archie.lan` HTTPS/TXT/MX
//! (and anything under `.lan` the LAN does not know) went to the internet and came back as a
//! public NXDOMAIN — a leak of LAN names, and a "no such name" for a host that exists, which a
//! stub may cache against its A/AAAA too (RFC 8020). `lan` itself answered NXDOMAIN to A, which
//! denies every name under it. Local replies also echoed the query's AD bit.

use super::common::{
    DnsPacketBuilder, MockUpstreamServer, init_test_context, mock_config, parse_response,
    register_test_device, wait_for_service_online,
};
use crate::config::DnsConfig;
use crate::server::service::DnsService;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::{DnsRData, DnsRecordType, DnsResponseCode};
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
        ("lan", SOA, NoError, 1, true),
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

/// A local NXDOMAIN/NODATA carries the site domain's SOA in authority, with the record TTL and
/// MINIMUM both the local TTL: without it a resolver may not cache the negative answer
/// (RFC 2308 §3, §5). The apex answers a query for its SOA. A dotless name is in no zone the
/// router owns, so its NXDOMAIN carries none. Holds with EDNS, whose OPT follows authority.
#[tokio::test]
async fn local_negative_answers_carry_the_site_soa() {
    use DnsRecordType::{A, AAAA, SOA, TXT};

    let ctx = init_test_context();
    register_test_device(
        &ctx,
        "archie",
        MacAddr([0x02, 0, 0, 0, 0, 0x57]),
        Ipv4Addr::new(192, 168, 1, 2),
    );
    let cfg = DnsConfig {
        enabled: true,
        ttl: 42,
        ..mock_config() // search domain `lan`
    };
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
    let ctx_serve = ctx.clone();
    let serve = tokio::spawn(async move { service.serve(&ctx_serve, &h).await });
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    let client: SocketAddr = "192.168.1.50:40000".parse().unwrap();

    // (name, type, SOA in answer, SOA in authority)
    let cases = [
        ("naoexiste.lan", A, 0, 1),
        ("x.archie.lan", TXT, 0, 1),
        ("archie.lan", TXT, 0, 1),
        ("ARCHIE.LAN", AAAA, 0, 1),
        ("lan", A, 0, 1),
        ("lan", SOA, 1, 0),
        ("printer", A, 0, 0),
        ("archie", TXT, 0, 0),
    ];
    let mut report = String::new();
    for (i, (name, qtype, answers, authorities)) in cases.into_iter().enumerate() {
        for edns in [false, true] {
            let id = 100 + 2 * u16::try_from(i).unwrap() + u16::from(edns);
            let mut query = DnsPacketBuilder::query(name, qtype)
                .with_id(id)
                .build_bytes();
            if edns {
                query[11] = 1; // ARCOUNT = 1: an OPT with a 4096-byte payload
                query.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
            }
            handle.inject(query, client).await;
            let (reply, _) = handle.recv_reply().await.expect("reply");
            let label = format!("{name} {qtype:?} edns={edns}");
            let Some(resp) = parse_response(&reply) else {
                report.push_str(&format!("{label}: undecodable reply\n"));
                continue;
            };
            if (resp.answers.len(), resp.authorities.len()) != (answers, authorities) {
                report.push_str(&format!(
                    "{label}: {} answers / {} authorities, want {answers} / {authorities}\n",
                    resp.answers.len(),
                    resp.authorities.len()
                ));
                continue;
            }
            if usize::from(edns) != resp.additionals.len() {
                report.push_str(&format!("{label}: OPT lost\n"));
            }
            for soa in resp.answers.iter().chain(&resp.authorities) {
                let DnsRData::SOA(data) = &soa.rdata else {
                    report.push_str(&format!("{label}: not a SOA: {:?}\n", soa.rdata));
                    continue;
                };
                let got = (
                    soa.name.trim_end_matches('.'),
                    soa.ttl,
                    data.mname.trim_end_matches('.'),
                    data.rname.trim_end_matches('.'),
                    data.minimum,
                );
                if got != ("lan", 42, "lan", "hostmaster.lan", 42) {
                    report.push_str(&format!("{label}: SOA {got:?}\n"));
                }
            }
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
