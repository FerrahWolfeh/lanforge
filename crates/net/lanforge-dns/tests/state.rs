mod common;
use common::*;
use lanforge_types::device::{Ipv6AddrOrSuffix, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

#[tokio::test]
async fn dns_reacts_to_lease_grant() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let dns_ctx = mock_dns_context(ctx.clone(), cfg).await;

    let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
    let ip = Ipv4Addr::new(10, 0, 0, 50);

    // Before lease: NXDOMAIN
    assert!(
        dns_ctx
            .local
            .resolve_ip("new-device", DnsRecordType::A)
            .is_none()
    );

    // Grant lease
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip,
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "new-device".to_string(),
    });

    // After lease: Should resolve
    let results = dns_ctx
        .local
        .resolve_ip("new-device", DnsRecordType::A)
        .unwrap();
    assert_eq!(results[0], IpAddr::V4(ip));
}

#[tokio::test]
async fn dns_reacts_to_hostname_change() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let dns_ctx = mock_dns_context(ctx.clone(), cfg).await;

    let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02]);
    let ip = Ipv4Addr::new(10, 0, 0, 60);
    register_test_device(&ctx, "old-name", mac, ip);

    assert!(
        dns_ctx
            .local
            .resolve_ip("old-name", DnsRecordType::A)
            .is_some()
    );

    // Change hostname
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "new-name".to_string(),
    });

    // Check both names (Old should be gone, new should be there)
    assert!(
        dns_ctx
            .local
            .resolve_ip("old-name", DnsRecordType::A)
            .is_none()
    );
    assert!(
        dns_ctx
            .local
            .resolve_ip("new-name", DnsRecordType::A)
            .is_some()
    );
}

#[tokio::test]
async fn complex_ipv6_merging_logic() {
    let ctx = init_test_context();
    let mut cfg = mock_config();
    cfg.ula_prefix = Some(Ipv6Addr::from_str("fd00:1234::").unwrap());
    cfg.gua_prefix = Some(Ipv6Addr::from_str("2001:db8:abcd::").unwrap());

    let dns_ctx = mock_dns_context(ctx.clone(), cfg).await;
    let mac = MacAddr([0, 0, 0, 0, 0, 0xFF]);

    // 1. Add a hostname hint
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "hybrid".to_string(),
    });

    // 2. Add a static IPv6 suffix via CLI
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::NoChange,
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::dead:beef").unwrap()),
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
    });

    // 3. Add an observed SLAAC address
    let observed_addr = Ipv6Addr::from_str("2001:db8:abcd::1111").unwrap();
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: observed_addr,
        is_active: true,
    });

    // 4. Resolve
    let results = dns_ctx
        .local
        .resolve_ip("hybrid", DnsRecordType::AAAA)
        .unwrap();

    let mut found_ula_static = false;
    let mut found_gua_static = false;
    let mut found_observed = false;

    for ip in results {
        if ip == IpAddr::V6(Ipv6Addr::from_str("fd00:1234::dead:beef").unwrap()) {
            found_ula_static = true;
        }
        if ip == IpAddr::V6(Ipv6Addr::from_str("2001:db8:abcd::dead:beef").unwrap()) {
            found_gua_static = true;
        }
        if ip == IpAddr::V6(observed_addr) {
            found_observed = true;
        }
    }

    assert!(found_ula_static, "Missing static ULA");
    assert!(found_gua_static, "Missing static GUA");
    assert!(found_observed, "Missing observed SLAAC");
}

#[tokio::test]
async fn dns_suppresses_logging_for_ignored_client() {
    use lanforge_dns::server::DnsLogEvent;
    use lanforge_types::network::dns::{QueryResult, TransportProtocol};
    use std::sync::Arc;

    let ctx = init_test_context();
    let mut cfg = mock_config();
    cfg.query_log.ignore_clients = vec!["10.0.0.99".to_string(), "ignored-host".to_string()];
    let dns_ctx = mock_dns_context(ctx.clone(), cfg).await;

    let mac1 = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x10]);
    let ip1 = Ipv4Addr::new(10, 0, 0, 10);
    register_test_device(&ctx, "authelia-container", mac1, ip1);

    let mac2 = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x20]);
    let ip2 = Ipv4Addr::new(10, 0, 0, 20);
    register_test_device(&ctx, "normal-pc", mac2, ip2);

    let query_log = dns_ctx.query_log.as_ref().unwrap();

    // 1. Initially, device1 is logged normally
    dns_ctx.record_log(DnsLogEvent {
        src_ip: IpAddr::V4(ip1),
        src_mac: Some(mac1),
        domain: Arc::from("example.com"),
        qtype: DnsRecordType::A,
        result: QueryResult::Forwarded,
        upstream_us: 10,
        cached: false,
        answer: None,
        protocol: TransportProtocol::Udp,
    });
    assert_eq!(query_log.len(), 1);

    // 2. Mark device1 with ignore_dns_log = true
    let _ = ctx.apply(DeviceUpdate::IgnoreDnsLogSet {
        mac: mac1,
        ignore: true,
    });

    // 3. New query from device1 should be suppressed!
    dns_ctx.record_log(DnsLogEvent {
        src_ip: IpAddr::V4(ip1),
        src_mac: Some(mac1),
        domain: Arc::from("example.com"),
        qtype: DnsRecordType::A,
        result: QueryResult::Forwarded,
        upstream_us: 10,
        cached: false,
        answer: None,
        protocol: TransportProtocol::Udp,
    });
    assert_eq!(query_log.len(), 1, "Expected device1 queries to be suppressed");

    // 4. Query from device2 should still be logged
    dns_ctx.record_log(DnsLogEvent {
        src_ip: IpAddr::V4(ip2),
        src_mac: Some(mac2),
        domain: Arc::from("example.com"),
        qtype: DnsRecordType::A,
        result: QueryResult::Forwarded,
        upstream_us: 10,
        cached: false,
        answer: None,
        protocol: TransportProtocol::Udp,
    });
    assert_eq!(query_log.len(), 2, "Expected normal device to be logged");

    // 5. Query from IP in cfg.query_log.ignore_clients should also be suppressed
    dns_ctx.record_log(DnsLogEvent {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
        src_mac: None,
        domain: Arc::from("example.com"),
        qtype: DnsRecordType::A,
        result: QueryResult::Forwarded,
        upstream_us: 10,
        cached: false,
        answer: None,
        protocol: TransportProtocol::Udp,
    });
    assert_eq!(query_log.len(), 2, "Expected ignored IP to be suppressed");

    // 6. Test device-specific domain pattern suppression
    let mac3 = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x30]);
    let ip3 = Ipv4Addr::new(10, 0, 0, 30);
    register_test_device(&ctx, "sonarr-container", mac3, ip3);

    let _ = ctx.apply(DeviceUpdate::IgnoredLogDomainsSet {
        mac: mac3,
        domains: vec!["*.sonarr.tv".to_string(), "api.servarr.com".to_string()],
    });

    // 6a. Sonarr calling skyhook.sonarr.tv -> Suppressed!
    dns_ctx.record_log(DnsLogEvent {
        src_ip: IpAddr::V4(ip3),
        src_mac: Some(mac3),
        domain: Arc::from("skyhook.sonarr.tv"),
        qtype: DnsRecordType::A,
        result: QueryResult::Forwarded,
        upstream_us: 10,
        cached: false,
        answer: None,
        protocol: TransportProtocol::Udp,
    });
    assert_eq!(query_log.len(), 2, "Expected *.sonarr.tv to be suppressed for Sonarr");

    // 6b. Sonarr calling github.com -> Logged!
    dns_ctx.record_log(DnsLogEvent {
        src_ip: IpAddr::V4(ip3),
        src_mac: Some(mac3),
        domain: Arc::from("github.com"),
        qtype: DnsRecordType::A,
        result: QueryResult::Forwarded,
        upstream_us: 10,
        cached: false,
        answer: None,
        protocol: TransportProtocol::Udp,
    });
    assert_eq!(query_log.len(), 3, "Expected github.com to be logged for Sonarr");

    // 6c. Another device (device2) calling skyhook.sonarr.tv -> Logged!
    dns_ctx.record_log(DnsLogEvent {
        src_ip: IpAddr::V4(ip2),
        src_mac: Some(mac2),
        domain: Arc::from("skyhook.sonarr.tv"),
        qtype: DnsRecordType::A,
        result: QueryResult::Forwarded,
        upstream_us: 10,
        cached: false,
        answer: None,
        protocol: TransportProtocol::Udp,
    });
    assert_eq!(query_log.len(), 4, "Expected skyhook.sonarr.tv to be logged for device2");
}
