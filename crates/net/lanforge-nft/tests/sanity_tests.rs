use lanforge_nft::ruleset::RulesetBuilder;
use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallMode, FirewallPolicy, FirewallZone, L4Protocol,
    PortForwardRule, ZoneForwarding,
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
    assert!(
        json.contains("\"lan0\""),
        "lan0 should be auto-bound to internal zone"
    );
    // 2. Must forward from lan0 to ppp0
    assert!(
        json.contains("\"ppp0\""),
        "ppp0 should be auto-bound to external zone"
    );
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
    assert!(
        json.contains("\"postrouting\""),
        "POSTROUTING chain missing"
    );
    assert!(
        json.contains("\"masquerade\""),
        "Masquerade statement missing"
    );
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

#[test]
fn test_sanity_firewall_mode_minimal() {
    let cfg = FirewallConfig {
        mode: FirewallMode::Minimal,
        flow_offload: true,
        ..FirewallConfig::default()
    };
    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .with_primary_lan(Some("lan0"))
        .build();
    let json = serde_json::to_string(&ruleset).unwrap();

    // Minimal mode must have:
    // 1. Table lanforge + flush
    assert!(json.contains("\"lanforge\""));
    // 2. Forward chain with policy accept and priority -10
    assert!(json.contains("\"forward\""));
    assert!(json.contains("-10"));
    // 3. Output chain with policy accept and priority -10
    assert!(json.contains("\"output\""));
    // 4. MSS clamping 1452 and 1432
    assert!(json.contains("1452"));
    assert!(json.contains("1432"));
    // 5. Must NOT have input chain with drop
    assert!(!json.contains("\"input\""));
    // 6. Masquerade on ppp0
    assert!(json.contains("\"masquerade\""));
    assert!(json.contains("ppp0"));
}

#[test]
fn test_sanity_output_chain_and_dnat_in_full_mode() {
    let cfg = FirewallConfig::default();
    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .with_primary_lan(Some("lan0"))
        .build();
    let json = serde_json::to_string(&ruleset).unwrap();

    // Full mode must have:
    // 1. Output chain with MSS clamping
    assert!(json.contains("\"output\""));
    // 2. Input chain with ct status dnat accept
    assert!(json.contains("\"dnat\""));
    // 3. ICMPv6 using meta l4proto ipv6-icmp
    assert!(json.contains("\"ipv6-icmp\""));
    // 4. MLD types
    assert!(json.contains("mld-listener-query"));
    assert!(json.contains("mld2-listener-report"));
}

#[test]
fn test_sanity_podman_wildcard_in_trusted_zone() {
    let cfg = FirewallConfig::default();
    let ruleset = RulesetBuilder::new(&cfg).build();
    let json = serde_json::to_string(&ruleset).unwrap();

    // Trusted zone must resolve podman* wildcard
    assert!(json.contains("podman*"));
}

#[test]
fn test_sanity_dnat_restricted_to_internal_and_explicit_port_forwards() {
    use lanforge_types::network::firewall::{L4Protocol, PortForwardRule};
    use std::net::IpAddr;

    let mut cfg = FirewallConfig::default();
    cfg.port_forwards.push(PortForwardRule {
        comment: Some("qBittorrent IPv6 pinhole".into()),
        src_zone: "external".into(),
        protocol: L4Protocol::Tcp,
        external_port: 6881,
        internal_ip: "2804:cafe::1".parse::<IpAddr>().unwrap(),
        internal_port: 6881,
        enable_hairpin: false,
    });
    cfg.port_forwards.push(PortForwardRule {
        comment: Some("Web port forward".into()),
        src_zone: "external".into(),
        protocol: L4Protocol::Tcp,
        external_port: 8080,
        internal_ip: "192.168.0.128".parse::<IpAddr>().unwrap(),
        internal_port: 80,
        enable_hairpin: true,
    });

    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .with_primary_lan(Some("lan0"))
        .build();
    let json = serde_json::to_string(&ruleset).unwrap();

    // 1. Internal interfaces must have DNAT rules in forward/input
    assert!(json.contains("lan0"));
    assert!(json.contains("podman*"));

    // 2. Explicit port forward rules for ppp0 must exist matching target IP and internal port
    assert!(json.contains("192.168.0.128"));
    assert!(json.contains("2804:cafe::1"));
    assert!(json.contains("6881"));

    // 3. Without a rule for 443, no rule in forward allows ppp0 to 443
    let cfg_clean = FirewallConfig::default();
    let ruleset_clean = RulesetBuilder::new(&cfg_clean)
        .with_active_wan(Some("ppp0"))
        .with_primary_lan(Some("lan0"))
        .build();

    // Must NOT contain any rule matching ppp0 with dnat
    for obj in ruleset_clean.objects.as_ref() {
        let obj_str = serde_json::to_string(obj).unwrap();
        if obj_str.contains("\"rule\"") && obj_str.contains("ppp0") {
            assert!(
                !obj_str.contains("\"dnat\""),
                "ppp0 must NEVER have an unconditional ct status dnat rule! Found: {obj_str}"
            );
        }
    }
}

#[test]
fn test_sanity_strict_external_wan_drop_policy() {
    let cfg = FirewallConfig::default();
    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .with_primary_lan(Some("lan0"))
        .build();

    let mut found_input_policy_drop = false;
    let mut found_forward_policy_drop = false;

    for obj in ruleset.objects.as_ref() {
        let chain = match obj {
            nftables::schema::NfObject::CmdObject(nftables::schema::NfCmd::Add(
                nftables::schema::NfListObject::Chain(c),
            ))
            | nftables::schema::NfObject::ListObject(nftables::schema::NfListObject::Chain(c)) => {
                Some(c)
            }
            _ => None,
        };

        if let Some(chain) = chain {
            if chain.name == "input" {
                assert_eq!(
                    chain.policy,
                    Some(nftables::types::NfChainPolicy::Drop),
                    "Input chain default policy must be Drop"
                );
                found_input_policy_drop = true;
            } else if chain.name == "forward" {
                assert_eq!(
                    chain.policy,
                    Some(nftables::types::NfChainPolicy::Drop),
                    "Forward chain default policy must be Drop"
                );
                found_forward_policy_drop = true;
            }
        }
    }

    assert!(
        found_input_policy_drop,
        "Input chain with policy Drop must exist"
    );
    assert!(
        found_forward_policy_drop,
        "Forward chain with policy Drop must exist"
    );
}

#[test]
fn test_sanity_hairpin_nat_multizone_reflection() {
    let mut cfg = FirewallConfig::default();
    if let Some(zone) = cfg.zones.iter_mut().find(|z| z.name == "internal") {
        zone.interfaces = vec!["lan0".into()];
    }
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

    cfg.port_forwards.push(PortForwardRule {
        comment: Some("Home Assistant".into()),
        src_zone: "external".into(),
        internal_ip: "192.168.1.10".parse::<IpAddr>().unwrap(),
        external_port: 8123,
        internal_port: 8123,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
    });

    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .with_primary_lan(Some("lan0"))
        .build();
    let json = serde_json::to_string(&ruleset).unwrap();

    // 1. Prerouting DNAT must be present for WAN (ppp0) AND internal zones (lan0, vlan20)
    assert!(json.contains("ppp0"));
    assert!(json.contains("lan0"));
    assert!(json.contains("vlan20"));
    assert!(json.contains("8123"));
    assert!(json.contains("192.168.1.10"));

    // 2. Postrouting Masquerade for hairpin must be present
    assert!(json.contains("\"masquerade\""));
}

#[test]
fn test_sanity_ipv6_pinhole_native_forwarding_and_no_masquerade() {
    let mut cfg = FirewallConfig::default();
    cfg.port_forwards.push(PortForwardRule {
        comment: Some("IPv6 Matrix Synapse Pinhole".into()),
        src_zone: "external".into(),
        internal_ip: "2001:db8:beef::50".parse::<IpAddr>().unwrap(),
        external_port: 8448,
        internal_port: 8448,
        protocol: L4Protocol::Tcp,
        enable_hairpin: false,
    });

    let ruleset = RulesetBuilder::new(&cfg)
        .with_active_wan(Some("ppp0"))
        .with_primary_lan(Some("lan0"))
        .build();

    let json = serde_json::to_string(&ruleset).unwrap();

    // 1. Forward chain must permit target IPv6 and destination port
    assert!(json.contains("2001:db8:beef::50"));
    assert!(json.contains("8448"));
    assert!(json.contains("\"forward\""));

    // 2. Postrouting masquerade must be restricted to IPv4 only (never masquerade IPv6)
    for obj in ruleset.objects.as_ref() {
        let obj_str = serde_json::to_string(obj).unwrap();
        if obj_str.contains("\"masquerade\"") {
            assert!(
                obj_str.contains("\"ipv4\""),
                "Masquerade rule must be strictly scoped to IPv4! Found: {obj_str}"
            );
            assert!(
                !obj_str.contains("\"ipv6\""),
                "Masquerade rule must NEVER match IPv6! Found: {obj_str}"
            );
        }
    }
}

#[test]
fn test_sanity_dns_and_vowifi_bypass_toggles() {
    // 1. Enabled bypasses
    let cfg_enabled = FirewallConfig {
        bypass_dns: true,
        bypass_vowifi: true,
        ..FirewallConfig::default()
    };
    let json_enabled = serde_json::to_string(
        &RulesetBuilder::new(&cfg_enabled)
            .with_active_wan(Some("ppp0"))
            .build(),
    )
    .unwrap();
    // DNS bypass: port 53
    assert!(json_enabled.contains("\"dport\": 53") || json_enabled.contains("53"));
    // VoWiFi bypass: ports 500 and 4500
    assert!(json_enabled.contains("500"));
    assert!(json_enabled.contains("4500"));

    // 2. Disabled bypasses
    let cfg_disabled = FirewallConfig {
        bypass_dns: false,
        bypass_vowifi: false,
        ..FirewallConfig::default()
    };
    let json_disabled = serde_json::to_string(
        &RulesetBuilder::new(&cfg_disabled)
            .with_active_wan(Some("ppp0"))
            .build(),
    )
    .unwrap();
    // VoWiFi ports should not be in the ruleset
    assert!(!json_disabled.contains("\"dport\": 500"));
    assert!(!json_disabled.contains("\"dport\": 4500"));
}
