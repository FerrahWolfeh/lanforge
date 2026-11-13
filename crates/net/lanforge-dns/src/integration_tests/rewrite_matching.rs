//! Which names a rewrite rule matches. A rule's domain is a name (`nas.home`: that name only) or
//! `*.<name>` (`*.corp.lan`: the name itself and every name below it, at any depth); never a
//! partial label (`*.corp.lan` does not match `evilcorp.lan`). DNS names compare
//! case-insensitively (RFC 4343). When several rules match, the first in file order answers.

use super::common::*;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
use lanforge_types::network::dns::{DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use crate::server::DnsContext;

fn rule(domain: &str, answer: &str) -> RewriteRule {
    RewriteRule {
        id: None,
        domain: domain.to_string(),
        rtype: DnsRecordType::A,
        answer: RewriteAnswer::from_str(answer).unwrap(),
    }
}

async fn dns(rules: Vec<RewriteRule>) -> DnsContext {
    let mut cfg = mock_config();
    cfg.rewrites = rules;
    mock_dns_context(init_test_context(), cfg).await
}

/// The A records answered for `name`.
async fn a(dns: &DnsContext, name: &str) -> Vec<Ipv4Addr> {
    let mut query = DnsMessage::new();
    query.header.id = 9;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from(name),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let bytes = WireEncoder::new().encode_message(&query);
    let mut resp = Vec::new();
    let _ = process_query_test(&bytes, dns, "127.0.0.1".parse().unwrap(), &mut resp).await;
    let Some(msg) = WireDecoder::new(&resp).decode_message() else {
        return Vec::new();
    };
    msg.answers
        .iter()
        .filter_map(|r| match r.rdata {
            DnsRData::A(ip) => Some(ip),
            _ => None,
        })
        .collect()
}

const HIT: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);

#[tokio::test]
async fn an_exact_rule_matches_only_its_name() {
    let dns = dns(vec![rule("nas.home", "10.9.9.9")]).await;
    assert_eq!(a(&dns, "nas.home").await, [HIT]);
    for other in ["x.nas.home", "nas.home2", "mynas.home", "home"] {
        assert!(!a(&dns, other).await.contains(&HIT), "{other}");
    }
}

#[tokio::test]
async fn a_wildcard_matches_its_name_and_every_name_below_it() {
    let dns = dns(vec![rule("*.corp.lan", "10.9.9.9")]).await;
    for name in ["corp.lan", "a.corp.lan", "a.b.corp.lan"] {
        assert_eq!(a(&dns, name).await, [HIT], "{name}");
    }
    for other in ["evilcorp.lan", "lan", "corp.lan.evil"] {
        assert!(!a(&dns, other).await.contains(&HIT), "{other}");
    }
}

#[tokio::test]
async fn rule_domains_match_case_insensitively() {
    let dns = dns(vec![
        rule("API.Home", "10.9.9.9"),
        rule("*.Corp.LAN", "10.9.9.9"),
    ])
    .await;
    for name in ["api.home", "API.HOME", "x.corp.lan", "X.CORP.LAN"] {
        assert_eq!(a(&dns, name).await, [HIT], "{name}");
    }
}

#[tokio::test]
async fn the_first_matching_rule_in_file_order_answers() {
    let dns = dns(vec![
        rule("*.corp.lan", "10.9.9.9"),
        rule("a.corp.lan", "10.1.1.1"),
    ])
    .await;
    assert_eq!(a(&dns, "a.corp.lan").await, [HIT]);
}
