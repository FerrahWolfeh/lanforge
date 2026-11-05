#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
//! UDS speaks postcard, which has no field names: a field skipped on serialization shifts every
//! byte after it and the client fails to decode (`lanforge dns upstreams` over the socket did).
//! Each DTO is encoded with its optional fields empty, in a two-element list so a misalignment
//! cannot hide at the end of the message.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use lanforge_api::api::dns::{DnsQueryLogEntry, DnsUpstreamConfig, QueryRateEntry};
use lanforge_api::api::system::SystemConfigExport;
use lanforge_types::network::dns::adblock::{AdblockSourceFormat, FilterAction};
use lanforge_types::network::dns::{
    AdblockCheckResponse, AdblockSourceMatch, AdblockSourceStatus, DnsRecordType, QueryResult,
    UpstreamHealthSnapshot, UpstreamProtocol, UpstreamStatus,
};
use lanforge_types::system::ServiceBanner;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn assert_postcard_roundtrip<T: Serialize + DeserializeOwned>(name: &str, make: impl Fn() -> T) {
    let sent = vec![make(), make()];
    let bytes = postcard::to_allocvec(&sent).unwrap();
    let received: Vec<T> = postcard::from_bytes(&bytes)
        .unwrap_or_else(|e| panic!("{name}: postcard cannot decode what it encoded: {e}"));
    assert_eq!(received.len(), 2, "{name}");
    assert_eq!(postcard::to_allocvec(&received).unwrap(), bytes, "{name}");
}

#[test]
fn dns_dtos_with_empty_optional_fields_cross_the_socket() {
    assert_postcard_roundtrip("DnsUpstreamConfig", || DnsUpstreamConfig {
        name: None,
        addr: SocketAddr::from(([1, 1, 1, 1], 53)),
        protocol: UpstreamProtocol::Udp,
        domain: None,
    });
    assert_postcard_roundtrip("QueryRateEntry", || QueryRateEntry {
        timestamp: 1,
        count: 2,
        cached: 0,
        forwarded: 0,
        blocked: 0,
        local: 0,
        rewritten: 0,
        record_types: HashMap::new(),
        outcome_types: HashMap::new(),
    });
    assert_postcard_roundtrip("DnsQueryLogEntry", || DnsQueryLogEntry {
        timestamp: 1,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        domain: Arc::from("example.com"),
        src_hostname: None,
        answer: None,
        src_mac: None,
        result: QueryResult::Forwarded,
        cached: false,
        qtype: DnsRecordType::A,
        upstream_us: 0,
        filter: None,
        coalesce_id: None,
        repeats: 3,
    });
    assert_postcard_roundtrip("UpstreamHealthSnapshot", || UpstreamHealthSnapshot {
        target: SocketAddr::from(([1, 1, 1, 1], 53)),
        protocol: UpstreamProtocol::Udp,
        rtt_ewma_us: 0,
        last_rtt_us: 0,
        total_queries: 0,
        total_successes: 0,
        total_failures: 0,
        total_wins: 0,
        status: UpstreamStatus::Healthy,
        last_success_secs_ago: None,
        domain: None,
    });
    assert_postcard_roundtrip("AdblockSourceStatus", || AdblockSourceStatus {
        id: 1,
        name: None,
        url: "https://example.com/hosts".into(),
        format: AdblockSourceFormat::Hosts,
        format_detected: None,
        blocks: 0,
        exceptions: 0,
        unsupported: 0,
        last_attempt: 0,
        last_success: None,
        consecutive_failures: 0,
        last_error: None,
        sample_unsupported: Vec::new(),
    });
    assert_postcard_roundtrip("AdblockCheckResponse", || AdblockCheckResponse {
        domain: "example.com".into(),
        matched: false,
        filter: None,
        source_matches: vec![AdblockSourceMatch {
            source_id: 1,
            url: "https://example.com/hosts".into(),
            action: FilterAction::Block,
            rule: None,
            important: false,
        }],
    });
}

#[test]
fn system_dtos_with_empty_optional_fields_cross_the_socket() {
    assert_postcard_roundtrip("ServiceBanner", ServiceBanner::default);
    assert_postcard_roundtrip("SystemConfigExport", SystemConfigExport::default);
}
