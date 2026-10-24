use lanforge_api::api::{
    AllowlistEntry, DnsUpstreamConfig, HostConfigEntry, Response, SystemConfigExport,
};
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::{EventBus, LanforgeEvent, NetworkEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::device::{Ipv6AddrOrSuffix, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::DnsRecordType;
use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockRuleAction, AdblockUrlKind, BlockingMode, RewriteAnswer, RewriteRule,
};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::update::DeviceUpdate;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, SystemTime};

async fn init_test_context() -> ClientContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            config_path: "memory".to_string(),
            ..Default::default()
        })
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open_in_memory());
    let ctx = LanforgeContext::new(bus, table, None);

    let mut worker =
        lanforge_db::worker::DbWorker::new(DatabaseConfig::default(), ctx.clone(), db, log_db);
    let ctx_worker = ctx.clone();
    tokio::spawn(async move {
        let _ = worker.serve(&ctx_worker).await;
    });

    ClientContext {
        current_gua: None,
        uptime_secs: 100,
        ctx,
        active_clients: Arc::new(AtomicUsize::new(1)),
    }
}

#[tokio::test]
async fn test_dispatch_status() {
    let client_ctx = init_test_context().await;
    let res = client_ctx.handle_status().await;
    assert!(matches!(res, Response::Status(_)));
}

#[tokio::test]
async fn test_dispatch_devices() {
    let client_ctx = init_test_context().await;
    let res = client_ctx
        .handle_devices(None, None, None, None, None, None)
        .await;
    if let Response::Devices(d) = res {
        assert_eq!(d.devices.len(), 0);
        assert_eq!(d.meta.total, 0);
    } else {
        panic!("Expected Response::Devices");
    }
}

#[tokio::test]
async fn test_dispatch_hosts_crud() {
    let client_ctx = init_test_context().await;

    // 1. Initial hosts should be empty
    let res = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res {
        assert_eq!(h.hosts.len(), 0);
    } else {
        panic!("Expected Response::Hosts");
    }

    // 2. Add a host
    let entry = HostConfigEntry {
        mac: MacAddr::parse("00:11:22:33:44:55").unwrap(),
        hostname: "test-host".to_string(),
        v4_fixed: Some("192.168.1.100".parse().unwrap()),
        v6_suffix: None,
        origin: Origin::Static,
        ignore_dns_log: false,
        ignored_log_domains: Vec::new(),
    };
    let add_res = client_ctx.handle_host_add(entry).await;
    assert!(matches!(add_res, Response::Success(_)));

    // 3. Verify host is listed
    let res2 = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res2 {
        assert_eq!(h.hosts.len(), 1);
        assert_eq!(h.hosts[0].mac, MacAddr::parse("00:11:22:33:44:55").unwrap());
        assert_eq!(h.hosts[0].hostname, "test-host");
    } else {
        panic!("Expected Response::Hosts");
    }

    // 4. Remove host
    let remove_res = client_ctx
        .handle_host_remove(MacAddr::parse("00:11:22:33:44:55").unwrap())
        .await;
    assert!(matches!(remove_res, Response::Success(_)));

    // 5. Verify hosts empty again
    let res3 = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res3 {
        assert_eq!(h.hosts.len(), 0);
    } else {
        panic!("Expected Response::Hosts");
    }
}

#[tokio::test]
async fn test_dispatch_system_config_import_export() {
    let client_ctx = init_test_context().await;

    // 1. Initial export should be empty/default
    let res = client_ctx.handle_system_config_export().await;
    if let Response::SystemConfig(cfg) = res {
        assert!(cfg.hosts.is_empty());
        assert!(cfg.dns_rewrites.is_empty());
        assert!(cfg.dns_upstreams.is_empty());
        assert!(cfg.dns_adblock_urls.is_empty());
        assert!(cfg.dns_allowlist.is_empty());
    } else {
        panic!("Expected Response::SystemConfig");
    }

    // 2. Create a populated SystemConfigExport
    let import_cfg = SystemConfigExport {
        hosts: vec![HostConfigEntry {
            mac: MacAddr::parse("11:22:33:44:55:66").unwrap(),
            hostname: "sys-import-host".to_string(),
            v4_fixed: Some("192.168.10.50".parse().unwrap()),
            v6_suffix: None,
            origin: Origin::Static,
            ignore_dns_log: false,
            ignored_log_domains: Vec::new(),
        }],
        dns_rewrites: vec![RewriteRule {
            id: None,
            domain: "import.lan".to_string(),
            rtype: DnsRecordType::A,
            answer: RewriteAnswer::A("192.168.10.1".parse().unwrap()),
        }],
        dns_upstreams: vec![DnsUpstreamConfig {
            name: Some("quad9".to_string()),
            addr: "9.9.9.9:53".parse().unwrap(),
            protocol: UpstreamProtocol::Udp,
            domain: Some("quad9".to_string()),
        }],
        dns_adblock_config: AdblockDbConfig {
            enabled: true,
            blocking_mode: BlockingMode::NullIp,
            blocking_ip_v4: Some("0.0.0.0".parse().unwrap()),
            blocking_ip_v6: Some("::".parse().unwrap()),
            refresh_time: lanforge_types::network::dns::adblock::TimeOfDay { hour: 4, minute: 30 },
        },
        dns_adblock_urls: if cfg!(feature = "adblock") {
            vec![AdblockUrlEntry {
                id: None,
                name: Some("adblock-hosts".to_string()),
                url: "https://example.com/adblock.hosts".to_string(),
                kind: AdblockUrlKind::Blocklist,
                format: lanforge_types::network::dns::adblock::AdblockSourceFormat::Auto,
            }]
        } else {
            vec![]
        },
        dns_allowlist: if cfg!(feature = "adblock") {
            vec![AllowlistEntry {
                id: 0,
                domain: "allowed-import.lan".to_string(),
            }]
        } else {
            vec![]
        },
        dns_adblock_rules: if cfg!(feature = "adblock") {
            Some(vec![lanforge_types::network::dns::adblock::AdblockRuleEntry {
                id: None,
                name: Some("custom-blocked".to_string()),
                domain: "custom-blocked.com".to_string(),
                action: AdblockRuleAction::Block,
                enabled: true,
            }])
        } else {
            None
        },
        overwrite: true,
        ..Default::default()
    };

    // 3. Import the configuration
    let import_res = client_ctx.handle_system_config_import(import_cfg).await;
    if let Response::Error { error } = &import_res {
        panic!("Import failed with error: {error}");
    }
    assert!(matches!(import_res, Response::SystemConfigImport(_)));

    // 4. Export again and verify all fields match what was imported
    let res_after = client_ctx.handle_system_config_export().await;
    if let Response::SystemConfig(cfg) = res_after {
        assert_eq!(cfg.hosts.len(), 1);
        assert_eq!(
            cfg.hosts[0].mac,
            MacAddr::parse("11:22:33:44:55:66").unwrap()
        );
        assert_eq!(cfg.hosts[0].hostname, "sys-import-host");

        assert_eq!(cfg.dns_rewrites.len(), 1);
        assert_eq!(cfg.dns_rewrites[0].domain, "import.lan");
        assert_eq!(
            cfg.dns_rewrites[0].answer,
            RewriteAnswer::A("192.168.10.1".parse().unwrap())
        );

        assert_eq!(cfg.dns_upstreams.len(), 1);
        assert_eq!(cfg.dns_upstreams[0].addr, "9.9.9.9:53".parse().unwrap());
        assert_eq!(cfg.dns_upstreams[0].protocol, UpstreamProtocol::Udp);
        assert_eq!(cfg.dns_upstreams[0].domain.as_deref(), Some("quad9"));

        assert!(cfg.dns_adblock_config.enabled);
        assert_eq!(cfg.dns_adblock_config.blocking_mode, BlockingMode::NullIp);
        assert_eq!(
            cfg.dns_adblock_config.refresh_time,
            lanforge_types::network::dns::adblock::TimeOfDay { hour: 4, minute: 30 }
        );

        if cfg!(feature = "adblock") {
            assert_eq!(cfg.dns_adblock_urls.len(), 1);
            assert_eq!(
                cfg.dns_adblock_urls[0].url,
                "https://example.com/adblock.hosts"
            );
            assert_eq!(cfg.dns_adblock_urls[0].kind, AdblockUrlKind::Blocklist);

            assert_eq!(cfg.dns_allowlist.len(), 1);
            assert_eq!(cfg.dns_allowlist[0].domain, "allowed-import.lan");

            let rules = cfg.dns_adblock_rules.as_ref().expect("rules present");
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].domain, "custom-blocked.com");
            assert_eq!(rules[0].action, AdblockRuleAction::Block);
            assert!(rules[0].enabled);
        } else {
            assert_eq!(cfg.dns_adblock_urls.len(), 0);
            assert_eq!(cfg.dns_allowlist.len(), 0);
        }
    } else {
        panic!("Expected Response::SystemConfig");
    }
}

#[tokio::test]
async fn test_dns_rewrite_add_dynamic() {
    use std::str::FromStr;

    let client_ctx = init_test_context().await;
    let rule = RewriteRule {
        id: None,
        domain: "*.eonteam.xyz".to_string(),
        rtype: DnsRecordType::CNAME,
        answer: RewriteAnswer::from_str("dev:raspie").unwrap(),
    };
    let res = client_ctx.handle_dns_rewrite_add(rule).await;
    assert!(matches!(res, Response::Success(_)));

    // Try loading rewrites back
    let load_res = client_ctx.handle_dns_rewrites().await;
    if let Response::DnsRewrites(r) = load_res {
        assert_eq!(r.rewrites.len(), 1);
        assert_eq!(r.rewrites[0].domain, "*.eonteam.xyz");
        assert_eq!(r.rewrites[0].rtype, DnsRecordType::CNAME);
        assert_eq!(
            r.rewrites[0].answer,
            RewriteAnswer::from_str("dev:raspie").unwrap()
        );
    } else {
        panic!("Expected DnsRewrites response");
    }
}

#[tokio::test]
async fn test_dispatch_host_set_invalid_ip_ignored() {
    let client_ctx = init_test_context().await;

    // 1. Add a valid static host configuration
    let entry = HostConfigEntry {
        mac: MacAddr::parse("00:11:22:33:44:55").unwrap(),
        hostname: "test-host".to_string(),
        v4_fixed: Some("192.168.1.100".parse().unwrap()),
        v6_suffix: None,
        origin: Origin::Static,
        ignore_dns_log: false,
        ignored_log_domains: Vec::new(),
    };
    let add_res = client_ctx.handle_host_add(entry).await;
    assert!(matches!(add_res, Response::Success(_)));

    // 2. Call handle_host_set with an invalid IP address
    let _ = client_ctx
        .handle_host_set(
            MacAddr::parse("00:11:22:33:44:55").unwrap(),
            "v4_static".to_string(),
            "invalid-ip-string".to_string(),
        )
        .await;

    // 3. Verify that the configuration in the state remains unchanged (still 192.168.1.100)
    let res = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res {
        assert_eq!(h.hosts.len(), 1);
        assert_eq!(h.hosts[0].v4_fixed, Some("192.168.1.100".parse().unwrap()));
    } else {
        panic!("Expected Response::Hosts");
    }
}

#[tokio::test]
async fn test_dispatch_system_config_import_overwrite() {
    let client_ctx = init_test_context().await;

    // 1. Seed some initial host configurations
    let entry1 = HostConfigEntry {
        mac: MacAddr::parse("00:00:00:00:00:01").unwrap(),
        hostname: "old-host-1".to_string(),
        v4_fixed: Some("192.168.1.10".parse().unwrap()),
        v6_suffix: None,
        origin: Origin::Static,
        ignore_dns_log: false,
        ignored_log_domains: Vec::new(),
    };
    let _ = client_ctx.handle_host_add(entry1).await;

    // 2. Prepare import configuration (contains "new-host-2")
    let new_entry = HostConfigEntry {
        mac: MacAddr::parse("00:00:00:00:00:02").unwrap(),
        hostname: "new-host-2".to_string(),
        v4_fixed: Some("192.168.1.20".parse().unwrap()),
        v6_suffix: None,
        origin: Origin::Static,
        ignore_dns_log: false,
        ignored_log_domains: Vec::new(),
    };

    // Case A: Import with overwrite = false
    let import_cfg_merge = SystemConfigExport {
        hosts: vec![new_entry.clone()],
        dns_rewrites: vec![],
        dns_upstreams: vec![],
        dns_adblock_config: Default::default(),
        dns_adblock_urls: vec![],
        dns_allowlist: vec![],
        overwrite: false,
        ..Default::default()
    };
    let merge_res = client_ctx
        .handle_system_config_import(import_cfg_merge)
        .await;
    assert!(matches!(merge_res, Response::SystemConfigImport(_)));

    // Verify both hosts exist (merged)
    let res = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res {
        assert_eq!(
            h.hosts.len(),
            2,
            "Expected both old and new hosts to be present"
        );
        assert!(h.hosts.iter().any(|x| x.hostname == "old-host-1"));
        assert!(h.hosts.iter().any(|x| x.hostname == "new-host-2"));
    } else {
        panic!("Expected Response::Hosts");
    }

    // Case B: Import with overwrite = true
    let new_entry_3 = HostConfigEntry {
        mac: MacAddr::parse("00:00:00:00:00:03").unwrap(),
        hostname: "new-host-3".to_string(),
        v4_fixed: Some("192.168.1.30".parse().unwrap()),
        v6_suffix: None,
        origin: Origin::Static,
        ignore_dns_log: false,
        ignored_log_domains: Vec::new(),
    };
    let import_cfg_overwrite = SystemConfigExport {
        hosts: vec![new_entry_3],
        dns_rewrites: vec![],
        dns_upstreams: vec![],
        dns_adblock_config: Default::default(),
        dns_adblock_urls: vec![],
        dns_allowlist: vec![],
        overwrite: true,
        ..Default::default()
    };
    let overwrite_res = client_ctx
        .handle_system_config_import(import_cfg_overwrite)
        .await;
    assert!(matches!(overwrite_res, Response::SystemConfigImport(_)));

    // Verify only the new imported host exists (old ones cleared)
    let res = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res {
        assert_eq!(h.hosts.len(), 1, "Expected previous hosts to be wiped");
        assert_eq!(h.hosts[0].hostname, "new-host-3");
    } else {
        panic!("Expected Response::Hosts");
    }
}

#[tokio::test]
async fn lease_release_removes_all_leases_from_pool() {
    let client_ctx = init_test_context().await;
    let mut rx = client_ctx.ctx.bus().subscribe();

    let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let res = client_ctx.handle_lease_release(mac, None).await;

    assert!(matches!(res, Response::Success(_)));

    let timed_event = rx.recv().await.unwrap();
    if let LanforgeEvent::Network(NetworkEvent::LeaseReleaseRequested {
        mac: evt_mac,
        target: evt_target,
    }) = timed_event.event
    {
        assert_eq!(evt_mac, mac);
        assert!(evt_target.is_none());
    } else {
        panic!("Expected LeaseReleaseRequested event");
    }
}

#[tokio::test]
async fn wol_sends_packet_to_correct_device() {
    let client_ctx = init_test_context().await;

    let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let ip = "192.168.1.100".parse().unwrap();
    let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

    // Seed the device in state so it has a hostname hint and IP
    let _ = client_ctx
        .ctx
        .apply(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    let _ = client_ctx.ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "target-device".to_string(),
    });

    let mut rx = client_ctx.ctx.bus().subscribe();

    // Call WOL by hostname
    let res = client_ctx.handle_wol("target-device".to_string()).await;
    assert!(matches!(res, Response::Success(_)));

    let timed_event = rx.recv().await.unwrap();
    if let LanforgeEvent::Network(NetworkEvent::WolTriggered {
        mac: evt_mac,
        ip_hint: evt_ip,
    }) = timed_event.event
    {
        assert_eq!(evt_mac, mac);
        assert_eq!(evt_ip, Some(ip));
    } else {
        panic!("Expected WolTriggered event");
    }
}

#[tokio::test]
async fn test_static_host_deletion_should_purge_all_leases() {
    let client_ctx = init_test_context().await;
    let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();

    // 1. Add host config
    let entry = HostConfigEntry {
        mac,
        hostname: "test-host".to_string(),
        v4_fixed: Some("192.168.1.100".parse().unwrap()),
        v6_suffix: None,
        origin: Origin::Static,
        ignore_dns_log: false,
        ignored_log_domains: Vec::new(),
    };
    let add_res = client_ctx.handle_host_add(entry).await;
    assert!(matches!(add_res, Response::Success(_)));

    // 2. Grant lease information in memory context
    let ip = "192.168.1.100".parse().unwrap();
    let expires = SystemTime::now() + std::time::Duration::from_secs(3600);
    let _ = client_ctx
        .ctx
        .apply(DeviceUpdate::V4LeaseGranted { mac, ip, expires });

    // Verify device has lease in memory context
    {
        let dev = client_ctx.ctx.get_device(&mac).unwrap();
        assert_eq!(dev.origin, Origin::Static);
        assert!(dev.v4.ip().is_some());
    }

    // 3. Remove host
    let remove_res = client_ctx.handle_host_remove(mac).await;
    assert!(matches!(remove_res, Response::Success(_)));

    // 4. Verify device is purged from memory context
    assert!(client_ctx.ctx.get_device(&mac).is_none());
}

#[tokio::test]
async fn test_static_host_creation_creates_all_leases_for_specific_mac() {
    use lanforge_dhcp::v4::pool::IpPool;
    use lanforge_dhcp::v6::pool::Ipv6Pool;
    use lanforge_types::identifiers::Duid;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let client_ctx = init_test_context().await;
    let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let duid = Duid::new(vec![1, 2, 3, 4]);
    let v6_suffix = Ipv6AddrOrSuffix::parse("::100").unwrap();

    // 1. Add static host configuration via API
    let entry = HostConfigEntry {
        mac,
        hostname: "test-static".to_string(),
        v4_fixed: Some("192.168.1.100".parse().unwrap()),
        v6_suffix: Some(v6_suffix),
        origin: Origin::Static,
        ignore_dns_log: false,
        ignored_log_domains: Vec::new(),
    };
    let add_res = client_ctx.handle_host_add(entry).await;
    assert!(matches!(add_res, Response::Success(_)));

    // Associate DUID to MAC in memory context so that DHCPv6 allocate can resolve DUID to MAC
    let _ = client_ctx.ctx.apply(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 1,
    });

    // 2. Instantiate pools and allocate
    let mut v4_pool = IpPool::new(vec![Dhcpv4Pool {
        range_start: "192.168.1.50".parse().unwrap(),
        range_end: "192.168.1.150".parse().unwrap(),
        lease_time: Some(Duration::from_hours(24).as_secs() as u32),
        ..Default::default()
    }]);

    let mut v6_pool = Ipv6Pool::new(
        &[Dhcpv6Pool {
            address: Some("fd00::/64".to_string()),
            range_start: None,
            range_end: None,
            lease_time: Some(Duration::from_hours(24).as_secs() as u32),
            ..Default::default()
        }],
        Some("fd00::".parse().unwrap()),
        64,
    );

    // 3. Allocate and verify static addresses are returned
    let allocated_v4 = v4_pool.allocate(&client_ctx.ctx, mac, None).unwrap();
    assert_eq!(allocated_v4, "192.168.1.100".parse::<Ipv4Addr>().unwrap());

    let allocated_v6 = v6_pool.allocate(&client_ctx.ctx, &duid, 1, Some(mac), None);
    assert_eq!(allocated_v6.len(), 1);
    assert_eq!(allocated_v6[0], "fd00::100".parse::<Ipv6Addr>().unwrap());
}
