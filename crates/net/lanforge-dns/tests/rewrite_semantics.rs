#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions and setup"
)]
#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
//! A name matched by a rewrite never leaves the router (owner rule, 2026-10-28): a query type the
//! rule does not answer gets NODATA (NOERROR, no answer), never NXDOMAIN and never the upstream —
//! a rewrite of a public domain must not leak its public records. `rtype` A/AAAA delimits what a
//! rule answers; `dev:` answers from the device's current IPs, then its fallback, then NODATA.

mod common;

use common::*;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, DnsResponseCode,
};
use lanforge_types::update::DeviceUpdate;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use lanforge_dns::server::DnsContext;

fn rule(domain: &str, rtype: DnsRecordType, answer: &str) -> RewriteRule {
    RewriteRule {
        id: None,
        domain: domain.to_string(),
        rtype,
        answer: RewriteAnswer::from_str(answer).unwrap(),
    }
}

async fn ask(dns: &DnsContext, name: &str, qtype: DnsRecordType) -> DnsMessage {
    let mut query = DnsMessage::new();
    query.header.id = 7;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from(name),
        qtype,
        qclass: DnsClass::IN,
    });
    let bytes = WireEncoder::new().encode_message(&query);
    let mut resp = Vec::new();
    process_query_test(&bytes, dns, "127.0.0.1".parse().unwrap(), &mut resp)
        .await
        .unwrap();
    WireDecoder::new(&resp).decode_message().unwrap()
}

fn ips(resp: &DnsMessage) -> Vec<IpAddr> {
    resp.answers
        .iter()
        .map(|r| match r.rdata {
            DnsRData::A(ip) => IpAddr::V4(ip),
            DnsRData::AAAA(ip) => IpAddr::V6(ip),
            _ => panic!("not an address record: {r:?}"),
        })
        .collect()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn assert_nodata(resp: &DnsMessage, what: &str) {
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError, "{what}: rcode");
    assert!(
        resp.answers.is_empty(),
        "{what}: answers {:?}",
        resp.answers
    );
}

async fn setup() -> DnsContext {
    let ctx = init_test_context();
    let mut cfg = mock_config();
    cfg.rewrites = vec![
        rule("static4.home", DnsRecordType::A, "192.168.1.50"),
        rule("dual.home", DnsRecordType::A, "192.168.1.60"),
        rule("dual.home", DnsRecordType::AAAA, "fd00::60"),
        rule("*.eonteam.xyz", DnsRecordType::Device, "dev:pixie"),
        rule("pixie-v4.home", DnsRecordType::A, "dev:pixie"),
        rule("v4only.home", DnsRecordType::Device, "dev:nas-box"),
        rule("gone.home", DnsRecordType::Device, "dev:offline-nas"),
        rule(
            "gone-fb.home",
            DnsRecordType::Device,
            "dev:offline-nas|192.168.1.99",
        ),
        // `fallback = [v4, v6]` in the file: one rule per family
        rule(
            "fb2.home",
            DnsRecordType::Device,
            "dev:offline-nas|192.168.1.98",
        ),
        rule(
            "fb2.home",
            DnsRecordType::Device,
            "dev:offline-nas|fd00::98",
        ),
        rule(
            "fb2-v4.home",
            DnsRecordType::Device,
            "dev:nas-box|192.168.1.97",
        ),
        rule("fb2-v4.home", DnsRecordType::Device, "dev:nas-box|fd00::97"),
    ];
    let pixie = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
    register_test_device(&ctx, "pixie", pixie, Ipv4Addr::new(192, 168, 1, 2));
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac: pixie,
        addr: Ipv6Addr::from_str("fd00::2").unwrap(),
        is_active: true,
    });
    let nas = MacAddr([0x02, 0, 0, 0, 0, 0x02]);
    register_test_device(&ctx, "nas-box", nas, Ipv4Addr::new(192, 168, 1, 10));
    mock_dns_context(ctx, cfg).await
}

#[tokio::test]
async fn a_static_rule_answers_nodata_for_the_other_family() {
    let dns = setup().await;
    let a = ask(&dns, "static4.home", DnsRecordType::A).await;
    assert_eq!(a.answers.len(), 1);
    assert_nodata(
        &ask(&dns, "static4.home", DnsRecordType::AAAA).await,
        "AAAA of an A rule",
    );
    assert_nodata(
        &ask(&dns, "static4.home", DnsRecordType::HTTPS).await,
        "HTTPS of an A rule",
    );
}

#[tokio::test]
async fn every_rule_of_a_name_is_tried_before_nodata() {
    let dns = setup().await;
    let aaaa = ask(&dns, "dual.home", DnsRecordType::AAAA).await;
    assert_eq!(aaaa.header.rcode, DnsResponseCode::NoError);
    assert_eq!(ips(&aaaa), [ip("fd00::60")]);
}

#[tokio::test]
async fn a_device_rewrite_follows_both_families_and_never_leaks_other_types() {
    let dns = setup().await;
    let a = ask(&dns, "git.eonteam.xyz", DnsRecordType::A).await;
    assert_eq!(ips(&a), [ip("192.168.1.2")]);
    let aaaa = ask(&dns, "git.eonteam.xyz", DnsRecordType::AAAA).await;
    assert_eq!(ips(&aaaa), [ip("fd00::2")]);
    assert_nodata(
        &ask(&dns, "git.eonteam.xyz", DnsRecordType::HTTPS).await,
        "HTTPS of dev:",
    );
    assert_nodata(
        &ask(&dns, "git.eonteam.xyz", DnsRecordType::TXT).await,
        "TXT of dev:",
    );
}

#[tokio::test]
async fn rtype_delimits_a_device_rewrite() {
    let dns = setup().await;
    let a = ask(&dns, "pixie-v4.home", DnsRecordType::A).await;
    assert_eq!(a.answers.len(), 1);
    assert_nodata(
        &ask(&dns, "pixie-v4.home", DnsRecordType::AAAA).await,
        "AAAA of rtype A",
    );
}

#[tokio::test]
async fn a_device_without_the_family_or_offline_is_nodata_not_nxdomain() {
    let dns = setup().await;
    assert_nodata(
        &ask(&dns, "v4only.home", DnsRecordType::AAAA).await,
        "v4-only device, AAAA",
    );
    assert_nodata(
        &ask(&dns, "gone.home", DnsRecordType::A).await,
        "offline, no fallback",
    );
    let fb = ask(&dns, "gone-fb.home", DnsRecordType::A).await;
    assert_eq!(ips(&fb), [ip("192.168.1.99")]);
    assert_nodata(
        &ask(&dns, "gone-fb.home", DnsRecordType::AAAA).await,
        "v4 fallback, AAAA",
    );
}

#[tokio::test]
async fn a_fallback_per_family_answers_only_the_family_the_device_lacks() {
    let dns = setup().await;
    let a = ask(&dns, "fb2.home", DnsRecordType::A).await;
    assert_eq!(ips(&a), [ip("192.168.1.98")], "offline, A");
    let aaaa = ask(&dns, "fb2.home", DnsRecordType::AAAA).await;
    assert_eq!(ips(&aaaa), [ip("fd00::98")], "offline, AAAA");
    let a = ask(&dns, "fb2-v4.home", DnsRecordType::A).await;
    assert_eq!(ips(&a), [ip("192.168.1.10")], "v4-only device, A");
    let aaaa = ask(&dns, "fb2-v4.home", DnsRecordType::AAAA).await;
    assert_eq!(ips(&aaaa), [ip("fd00::97")], "v4-only device, AAAA");
    assert_nodata(
        &ask(&dns, "fb2.home", DnsRecordType::HTTPS).await,
        "HTTPS with two fallbacks",
    );
}
