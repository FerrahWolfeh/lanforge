mod common;
use common::*;
use lanforge_core::types::{
    CliHostUpdate, DeviceUpdate, DnsRecordType, FieldUpdate, Ipv6AddrOrSuffix, MacAddr, Origin,
};
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
        update: CliHostUpdate {
            hostname: FieldUpdate::NoChange,
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::dead:beef").unwrap()),
            origin: Origin::Cli,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        },
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
