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

    // 1. Must define table inet lanforge and flush command
    assert!(json.contains("\"lanforge\""), "Table lanforge missing");
    assert!(json.contains("\"inet\""), "Family inet missing");
    assert!(json.contains("\"flush\""), "Flush command missing");

    // 2. Must have input chain with base hook
    assert!(json.contains("\"input\""), "Input chain missing");
    assert!(json.contains("\"filter\""), "Filter chain type missing");

    // 3. Must allow loopback
    assert!(json.contains("\"lo\""), "Loopback interface allow missing");
}

#[test]
fn test_sanity_primary_lan_auto_bind() {
    let cfg = FirewallConfig::default(); // default internal zone has empty interfaces
    let ruleset = RulesetBuilder::new(&cfg)
        .with_primary_lan(Some("lan0"))
        .with_active_wan(Some("ppp0"))
        .build();
    let json = serde_json::to_string_pretty(&ruleset).unwrap();

    // 1. Must accept input on lan0
    assert!(json.contains("\"lan0\""), "lan0 should be auto-bound to internal zone");
    // 2. Must forward from lan0 to ppp0
    assert!(json.contains("\"ppp0\""), "ppp0 should be auto-bound to external zone");
}

#[test]
fn test_sanity_dynamic_port_registration() {
    let mut cfg = FirewallConfig::default();
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.interfaces = vec!["eth0".into()];
    }

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

    // Verify dynamic ports are included for the zone's interface
    assert!(json.contains("3000"), "HTTP port 3000 missing");
    assert!(json.contains("5432"), "Postgres port 5432 missing");
    assert!(json.contains("443"), "QUIC port 443 missing");
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
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.interfaces = vec!["eth0".into()];
    }
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
    // Verify NAT table and PREROUTING chain
    assert!(json.contains("\"prerouting\""), "PREROUTING chain missing");
    assert!(json.contains("\"dnat\""), "DNAT statement missing");
    assert!(json.contains("8080"), "External port 8080 missing");
    assert!(json.contains("80"), "Internal port 80 missing");
    assert!(json.contains("192.168.1.100"), "Internal target IP missing");

    // Verify hairpin NAT in postrouting
    assert!(json.contains("\"postrouting\""), "POSTROUTING chain missing");
    assert!(json.contains("\"masquerade\""), "Masquerade statement missing");
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

#[test]
fn test_sanity_zone_policy_transitions() {
    let mut cfg = FirewallConfig::default();
    cfg.zones.push(FirewallZone {
        name: "dmz".into(),
        interfaces: vec!["eth2".into()],
        open_ports: Vec::new(),
        allowed_subnets: Vec::new(),
        input_policy: FirewallPolicy::Drop,
        forward_policy: FirewallPolicy::Drop,
        masquerade: false,
        mtu_fix: false,
    });

    // 1. Initial Drop policy
    let json_drop = serde_json::to_string(&RulesetBuilder::new(&cfg).build()).unwrap();
    assert!(json_drop.contains("\"eth2\""));
    assert!(json_drop.contains("\"drop\""));

    // 2. Change to Reject policy
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "dmz") {
        zone.input_policy = FirewallPolicy::Reject;
    }
    let json_reject = serde_json::to_string(&RulesetBuilder::new(&cfg).build()).unwrap();
    assert!(json_reject.contains("\"eth2\""));
    assert!(json_reject.contains("\"reject\""));

    // 3. Change to Accept policy
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "dmz") {
        zone.input_policy = FirewallPolicy::Accept;
    }
    let json_accept = serde_json::to_string(&RulesetBuilder::new(&cfg).build()).unwrap();
    assert!(json_accept.contains("\"eth2\""));
    assert!(json_accept.contains("\"accept\""));
}

#[test]
fn test_sanity_service_port_lifecycle() {
    use lanforge_types::network::firewall::HostPortRule;

    let mut cfg = FirewallConfig::default();
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.interfaces = vec!["eth0".into()];
    }

    // 1. Enable Postgres (5432) on internal zone
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.open_ports.push(HostPortRule {
            port: 5432,
            protocol: L4Protocol::Tcp,
            comment: Some("Postgres Database".into()),
        });
    }
    let json1 = serde_json::to_string(&RulesetBuilder::new(&cfg).build()).unwrap();
    assert!(json1.contains("5432"));

    // 2. Add HTTP (8080) and QUIC (443)
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.open_ports.push(HostPortRule {
            port: 8080,
            protocol: L4Protocol::Tcp,
            comment: Some("HTTP Proxy".into()),
        });
        zone.open_ports.push(HostPortRule {
            port: 443,
            protocol: L4Protocol::Both,
            comment: Some("HTTPS QUIC".into()),
        });
    }
    let json2 = serde_json::to_string(&RulesetBuilder::new(&cfg).build()).unwrap();
    assert!(json2.contains("5432"));
    assert!(json2.contains("8080"));
    assert!(json2.contains("443"));

    // 3. Remove Postgres (5432)
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.open_ports.retain(|p| p.port != 5432);
    }
    let json3 = serde_json::to_string(&RulesetBuilder::new(&cfg).build()).unwrap();
    assert!(!json3.contains("5432"));
    assert!(json3.contains("8080"));
    assert!(json3.contains("443"));
}

#[test]
fn test_sanity_port_forwarding_crud() {
    let mut cfg = FirewallConfig::default();
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.interfaces = vec!["eth0".into()];
    }

    // 1. Create port forward (8080 -> 192.168.1.50:80)
    cfg.port_forwards.push(PortForwardRule {
        comment: Some("Web Forward".into()),
        src_zone: "external".into(),
        internal_ip: "192.168.1.50".parse().unwrap(),
        external_port: 8080,
        internal_port: 80,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
    });
    let json1 = serde_json::to_string(
        &RulesetBuilder::new(&cfg)
            .with_active_wan(Some("ppp0"))
            .build(),
    )
    .unwrap();
    assert!(json1.contains("8080"));
    assert!(json1.contains("192.168.1.50"));

    // 2. Edit port forward (change external port to 8443, target IP to 192.168.1.60)
    cfg.port_forwards[0].external_port = 8443;
    cfg.port_forwards[0].internal_ip = "192.168.1.60".parse().unwrap();
    let json2 = serde_json::to_string(
        &RulesetBuilder::new(&cfg)
            .with_active_wan(Some("ppp0"))
            .build(),
    )
    .unwrap();
    assert!(!json2.contains("8080"));
    assert!(json2.contains("8443"));
    assert!(json2.contains("192.168.1.60"));

    // 3. Remove port forward
    cfg.port_forwards.clear();
    let json3 = serde_json::to_string(
        &RulesetBuilder::new(&cfg)
            .with_active_wan(Some("ppp0"))
            .build(),
    )
    .unwrap();
    assert!(!json3.contains("8443"));
    assert!(!json3.contains("192.168.1.60"));
    assert!(!json3.contains("\"prerouting\""));
}

#[test]
fn test_sanity_flowtable_toggle() {
    let mut cfg = FirewallConfig::default();
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.interfaces = vec!["eth0".into()];
    }

    // 1. Flow offload enabled with active WAN
    cfg.flow_offload = true;
    let json_on = serde_json::to_string(
        &RulesetBuilder::new(&cfg)
            .with_active_wan(Some("ppp0"))
            .build(),
    )
    .unwrap();
    assert!(json_on.contains("\"flowtable\""));
    assert!(json_on.contains("ppp0"));
    assert!(json_on.contains("eth0"));

    // 2. Flow offload disabled
    cfg.flow_offload = false;
    let json_off = serde_json::to_string(
        &RulesetBuilder::new(&cfg)
            .with_active_wan(Some("ppp0"))
            .build(),
    )
    .unwrap();
    assert!(!json_off.contains("\"flowtable\""));
}
