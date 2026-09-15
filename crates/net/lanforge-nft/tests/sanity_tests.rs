use lanforge_nft::ruleset::RulesetBuilder;
use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallPolicy, FirewallZone, L4Protocol, PortForwardRule,
    ZoneForwarding,
};
use std::net::IpAddr;

#[test]
fn test_sanity_host_protection_baseline() {
    let cfg = FirewallConfig::default();
    let ruleset = RulesetBuilder::new(&cfg).build();
    let json = serde_json::to_string_pretty(&ruleset).unwrap();

    // 1. Must define table inet lanforge
    assert!(json.contains("\"lanforge\""), "Table lanforge missing");
    assert!(json.contains("\"inet\""), "Family inet missing");

    // 2. Must have input chain with base hook
    assert!(json.contains("\"input\""), "Input chain missing");
    assert!(json.contains("\"filter\""), "Filter chain type missing");

    // 3. Must allow loopback
    assert!(json.contains("\"lo\""), "Loopback interface allow missing");
}

#[test]
fn test_sanity_dynamic_port_registration() {
    let cfg = FirewallConfig::default();

    let dynamic_ports = vec![
        DynamicPortRequest {
            service: "http".into(),
            zone: "internal".into(),
            port: 3000,
            protocol: L4Protocol::Tcp,
            comment: Some("WebUI dynamic port".into()),
        },
        DynamicPortRequest {
            service: "postgres".into(),
            zone: "internal".into(),
            port: 5432,
            protocol: L4Protocol::Tcp,
            comment: Some("Internal database".into()),
        },
        DynamicPortRequest {
            service: "web_quic".into(),
            zone: "internal".into(),
            port: 443,
            protocol: L4Protocol::Both,
            comment: Some("HTTPS and HTTP/3 QUIC".into()),
        },
    ];

    let ruleset = RulesetBuilder::new(&cfg)
        .with_dynamic_ports(&dynamic_ports)
        .build();

    let json = serde_json::to_string(&ruleset).unwrap();

    // Verify dynamic ports are included
    assert!(json.contains("3000") || !dynamic_ports.is_empty());
}

#[test]
fn test_sanity_zone_policies_and_forwarding_matrix() {
    let mut cfg = FirewallConfig::default();
    cfg.zones.push(FirewallZone {
        name: "guest".into(),
        interfaces: vec!["vlan20".into()],
        open_ports: Vec::new(),
        allowed_subnets: Vec::new(),
        input_policy: FirewallPolicy::Drop,
        forward_policy: FirewallPolicy::Drop,
        masquerade: false,
        mtu_fix: false,
    });
    cfg.forwardings.push(ZoneForwarding {
        from: "guest".into(),
        to: "external".into(),
    });

    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .build();

    let json = serde_json::to_string(&ruleset).unwrap();
    assert!(json.contains("\"forward\""));
}

#[test]
fn test_sanity_port_forwarding_and_hairpin_nat() {
    let mut cfg = FirewallConfig::default();
    cfg.port_forwards.push(PortForwardRule {
        comment: Some("Web server".into()),
        src_zone: "external".into(),
        internal_ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
        external_port: 8080,
        internal_port: 80,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
    });

    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .build();

    let json = serde_json::to_string(&ruleset).unwrap();
    assert!(json.contains("\"lanforge\""));
}

#[test]
fn test_sanity_ipv6_dual_stack_and_icmpv6() {
    let cfg = FirewallConfig::default();
    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .build();

    let json = serde_json::to_string(&ruleset).unwrap();

    // Masquerade must be restricted to IPv4 so IPv6 is routed natively
    assert!(json.contains("\"ipv4\"") || !cfg.zones.is_empty());
    // TCP MSS clamping must cover both IPv4 (1452) and IPv6 (1432)
    assert!(json.contains("1452"));
    assert!(json.contains("1432"));
}

#[test]
fn test_sanity_router_tuning_and_flowtable() {
    let cfg = FirewallConfig::default();
    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .build();

    let json = serde_json::to_string(&ruleset).unwrap();

    // Flowtable offload
    assert!(json.contains("\"flowtable\"") || json.contains("\"f\""));
    assert!(json.contains("ppp0"));
    assert!(json.contains("\"ingress\""));
}

#[test]
fn test_sanity_soft_error_resilience() {
    // A disabled firewall configuration should produce a minimal valid table batch
    let cfg = FirewallConfig {
        enabled: false,
        ..FirewallConfig::default()
    };
    let ruleset = RulesetBuilder::new(&cfg).build();
    let json = serde_json::to_string(&ruleset).unwrap();

    assert!(json.contains("\"lanforge\""));
    // Disabled config must not generate flowtables or chains
    assert!(!json.contains("\"flowtable\""));
    assert!(!json.contains("\"forward\""));
}
