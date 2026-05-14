mod common;

use common::*;
use lanforge_types::{DnsRecordType, MacAddr};
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
async fn resolve_local_ptr_ipv4() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let mac = MacAddr([1, 2, 3, 4, 5, 2]);
    let ip = Ipv4Addr::new(192, 168, 1, 20);
    register_test_device(&ctx, "printer", mac, ip);

    let dns_ctx = mock_dns_context(ctx, cfg).await;

    // Reverse DNS for 192.168.1.20
    let ptr_name = "20.1.168.192.in-addr.arpa";
    let (host, domain) = dns_ctx.local.resolve_ptr(ptr_name).unwrap().unwrap();
    assert_eq!(host, "printer");
    assert_eq!(domain, "lan");
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
    let _ = ctx.apply(lanforge_types::DeviceUpdate::SlaacObserved {
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
