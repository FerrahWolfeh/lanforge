mod common;

use common::*;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::update::DeviceUpdate;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[tokio::test]
async fn resolve_local_a_record() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let mac = MacAddr([1, 2, 3, 4, 5, 1]);
    let ip = Ipv4Addr::new(192, 168, 1, 10);
    register_test_device(&ctx, "nas", mac, ip);

    let dns_ctx = mock_dns_context(ctx, cfg).await;

    // resolve_ip expects the bare hostname
    let results = dns_ctx.local.resolve_ip("nas", DnsRecordType::A).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], IpAddr::V4(ip));
}

#[tokio::test]
async fn resolve_local_ptr() {
    let ctx = init_test_context();
    let cfg = mock_config();

    // Register IPv4 device
    let mac_v4 = MacAddr([1, 2, 3, 4, 5, 2]);
    let ip_v4 = Ipv4Addr::new(192, 168, 1, 20);
    register_test_device(&ctx, "printer", mac_v4, ip_v4);

    // Register IPv6 device
    let mac_v6 = MacAddr([1, 2, 3, 4, 5, 3]);
    let ip_v6 = Ipv6Addr::from_str("2001:db8::beef").unwrap();
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac: mac_v6,
        addr: ip_v6,
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac: mac_v6,
        hostname: "ipv6-host".to_string(),
    });

    let dns_ctx = mock_dns_context(ctx, cfg).await;

    struct TestCase {
        qname: &'static str,
        expected_host: &'static str,
    }

    let cases = vec![
        TestCase {
            qname: "20.1.168.192.in-addr.arpa",
            expected_host: "printer",
        },
        TestCase {
            qname: "20.1.168.192.in-addr.arpa.",
            expected_host: "printer",
        },
        TestCase {
            qname: "f.e.e.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            expected_host: "ipv6-host",
        },
        TestCase {
            qname: "f.e.e.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            expected_host: "ipv6-host",
        },
    ];

    for case in cases {
        let (host, domain) = dns_ctx
            .local
            .resolve_ptr(case.qname)
            .unwrap()
            .unwrap_or_else(|| panic!("Failed to resolve: {}", case.qname));
        assert_eq!(host, case.expected_host, "Failed on input: {}", case.qname);
        assert_eq!(domain, "lan");
    }
}

#[tokio::test]
async fn resolve_local_aaaa_with_prefixes() {
    let ctx = init_test_context();
    let mut cfg = mock_config();
    cfg.ula_prefix = Some(Ipv6Addr::from_str("fd00::").unwrap());
    cfg.gua_prefix = Some(Ipv6Addr::from_str("2001:db8::").unwrap());

    let mac = MacAddr([0, 0, 0, 0, 0, 1]);
    register_test_device(&ctx, "server", mac, Ipv4Addr::new(192, 168, 1, 5));

    // Add SLAAC address
    let slaac_addr = Ipv6Addr::from_str("2001:db8::beef").unwrap();
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: slaac_addr,
        is_active: true,
    });

    let dns_ctx = mock_dns_context(ctx, cfg).await;

    let results = dns_ctx
        .local
        .resolve_ip("server", DnsRecordType::AAAA)
        .unwrap();

    let mut found_gua = false;
    for ip in results {
        if ip == IpAddr::V6(slaac_addr) {
            found_gua = true;
        }
    }
    assert!(found_gua, "GUA address not found");
}

#[tokio::test]
async fn multi_search_domain_resolution() {
    let ctx = init_test_context();
    let mut cfg = mock_config();
    cfg.search_domains = vec!["lan".to_string(), "local".to_string()];
    cfg.multi_search_labels = vec![vec![b"lan".to_vec()], vec![b"local".to_vec()]];

    let mac = MacAddr([1, 2, 3, 4, 5, 3]);
    register_test_device(&ctx, "workstation", mac, Ipv4Addr::new(192, 168, 1, 50));

    let dns_ctx = mock_dns_context(ctx, cfg).await;

    // resolve_local handles the FQDN stripping
    assert!(
        dns_ctx
            .local
            .resolve_local("workstation.lan", DnsRecordType::A)
            .is_some()
    );
    assert!(
        dns_ctx
            .local
            .resolve_local("workstation.local", DnsRecordType::A)
            .is_some()
    );
    assert!(
        dns_ctx
            .local
            .resolve_local("workstation", DnsRecordType::A)
            .is_some()
    ); // Bare hostname
}

#[tokio::test]
async fn nxdomain_for_unknown_host() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let dns_ctx = mock_dns_context(ctx, cfg).await;

    let result = dns_ctx.local.resolve_ip("ghost", DnsRecordType::A);
    assert!(result.is_none());
}

#[tokio::test]
async fn resolve_local_aaaa_ignores_link_local_and_loopback() {
    let ctx = init_test_context();
    let mut cfg = mock_config();
    cfg.ula_prefix = Some(Ipv6Addr::from_str("fd00::").unwrap());
    cfg.gua_prefix = Some(Ipv6Addr::from_str("2001:db8::").unwrap());

    let mac = MacAddr([0, 0, 0, 0, 0, 2]);
    register_test_device(&ctx, "pixie", mac, Ipv4Addr::new(192, 168, 3, 1));

    // Add GUA, ULA, and Link-Local addresses
    let gua_addr = Ipv6Addr::from_str("2001:db8::beef").unwrap();
    let ula_addr = Ipv6Addr::from_str("fd00::beef").unwrap();
    let link_local = Ipv6Addr::from_str("fe80::8647:9ff:fe85:d212").unwrap();
    let loopback = Ipv6Addr::from_str("::1").unwrap();

    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: gua_addr,
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: ula_addr,
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: link_local,
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: loopback,
        is_active: true,
    });

    let dns_ctx = mock_dns_context(ctx, cfg).await;

    let results = dns_ctx
        .local
        .resolve_ip("pixie", DnsRecordType::AAAA)
        .expect("should resolve AAAA");

    assert!(results.contains(&IpAddr::V6(gua_addr)), "should contain GUA");
    assert!(results.contains(&IpAddr::V6(ula_addr)), "should contain ULA");
    assert!(
        !results.contains(&IpAddr::V6(link_local)),
        "MUST NOT contain link-local fe80 address in DNS AAAA"
    );
    assert!(
        !results.contains(&IpAddr::V6(loopback)),
        "MUST NOT contain loopback ::1 in DNS AAAA"
    );
}
