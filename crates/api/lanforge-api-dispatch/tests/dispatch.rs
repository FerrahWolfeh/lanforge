use lanforge_api::api::{
    AllowlistEntry, DnsUpstreamConfig, HostConfigEntry, Response, SystemConfigExport,
};
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::{EventBus, LanforgeEvent, NetworkEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
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
        let h = ServiceHandle::new(lanforge_types::system::ServiceId::Db, ctx_worker.clone());
        let _ = worker.serve(&ctx_worker, &h).await;
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
        boot_file: None,
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
            boot_file: None,
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
            refresh_time: lanforge_types::network::dns::adblock::TimeOfDay {
                hour: 4,
                minute: 30,
            },
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
            Some(vec![
                lanforge_types::network::dns::adblock::AdblockRuleEntry {
                    id: None,
                    name: Some("custom-blocked".to_string()),
                    domain: "custom-blocked.com".to_string(),
                    action: AdblockRuleAction::Block,
                    enabled: true,
                },
            ])
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
            lanforge_types::network::dns::adblock::TimeOfDay {
                hour: 4,
                minute: 30
            }
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
        boot_file: None,
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
        boot_file: None,
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
        boot_file: None,
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
        boot_file: None,
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

/// `host remove` drops the reservation (owner decision 2026-10-28): the device stays, as a
/// discovered device again, without its static address; purging forgets it entirely.
#[tokio::test]
async fn removing_a_static_host_demotes_it_and_purging_forgets_it() {
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
        boot_file: None,
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

    // 3. Remove host: a discovered device again
    let remove_res = client_ctx.handle_host_remove(mac).await;
    assert!(matches!(remove_res, Response::Success(_)));
    let dev = client_ctx.ctx.get_device(&mac).expect("the device stays");
    assert_eq!(dev.origin, Origin::Dynamic);
    assert!(!matches!(
        dev.v4,
        lanforge_types::device::IPv4State::Static(_)
    ));
    assert!(client_ctx.ctx.static_hosts().is_empty());

    // 4. Purge forgets it
    let res = client_ctx.handle_purge(mac).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
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
        boot_file: None,
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

// ---------------------------------------------------------------------------
// PPPoE is file-owned: an API change is written to `[pppoe]` before it is applied
// ---------------------------------------------------------------------------

fn pppoe_with(username: &str) -> lanforge_types::network::pppoe::PppoeConfig {
    let mut cfg = lanforge_types::network::pppoe::PppoeConfig {
        enabled: true,
        username: username.into(),
        password: "secret".into(),
        ..Default::default()
    };
    cfg.nftables.bypass_vowifi = false;
    cfg
}

#[tokio::test]
async fn pppoe_update_is_written_to_the_config_file() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);

    let cfg = pppoe_with("api-user");
    let res = client_ctx.handle_update_pppoe_config(cfg.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let text = std::fs::read_to_string(&path).unwrap();
    let file = lanforge_api::config_file::ConfigFile::parse(&text).unwrap();
    assert_eq!(file.pppoe, cfg, "every field reaches the file");
    assert!(text.contains("# mine") && text.contains("iface = \"lan0\""));
    assert_eq!(client_ctx.ctx.get_pppoe_config(), Some(cfg));
}

#[tokio::test]
async fn pppoe_update_is_rejected_when_the_file_cannot_take_it() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "[system\nbroken").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);
    let before = client_ctx.ctx.get_pppoe_config();

    let res = client_ctx
        .handle_update_pppoe_config(pppoe_with("lost"))
        .await;

    assert!(matches!(res, Response::Error { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_pppoe_config(), before, "not applied");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[system\nbroken");
}

#[tokio::test]
async fn pppoe_update_on_read_only_config_applies_in_memory_and_says_so() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "[system]\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(false);

    let cfg = pppoe_with("ram-only");
    let res = client_ctx.handle_update_pppoe_config(cfg.clone()).await;

    let Response::Success(ok) = res else {
        panic!("{res:?}");
    };
    assert!(ok.message.contains("not saved"), "{}", ok.message);
    assert_eq!(client_ctx.ctx.get_pppoe_config(), Some(cfg));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[system]\n");
}

#[tokio::test]
async fn traffic_update_is_written_to_the_config_file() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);

    let mut cfg = lanforge_types::network::TrafficConfig::default();
    cfg.sqm.enabled = true;
    cfg.sqm.rtt_ms = Some(25);
    cfg.sqm.raw_cake_args = Some("ack-filter".into());
    let res = client_ctx.handle_update_traffic_config(cfg.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let text = std::fs::read_to_string(&path).unwrap();
    let file = lanforge_api::config_file::ConfigFile::parse(&text).unwrap();
    assert_eq!(file.traffic, cfg, "every field reaches the file");
    assert!(text.contains("# mine"));
    assert_eq!(client_ctx.ctx.get_traffic_config(), Some(cfg));
}

// ---------------------------------------------------------------------------
// Firewall is file-owned: saved before it applies; a trial (auto-rollback) is not saved
// ---------------------------------------------------------------------------

fn file_firewall(path: &std::path::Path) -> lanforge_types::network::firewall::FirewallConfig {
    let text = std::fs::read_to_string(path).unwrap();
    let (fw, issues) = lanforge_api::config_file::ConfigFile::parse(&text)
        .unwrap()
        .firewall
        .to_config();
    assert!(issues.is_empty(), "{issues:?}");
    fw
}

async fn firewall_ctx() -> (ClientContext, tempfile::TempDir, std::path::PathBuf) {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);
    (client_ctx, dir, path)
}

fn with_forward(port: u16) -> lanforge_types::network::firewall::FirewallConfig {
    let mut fw = lanforge_types::network::firewall::FirewallConfig::default();
    fw.port_forwards
        .push(lanforge_types::network::firewall::PortForwardRule {
            comment: Some("game".into()),
            src_zone: "external".into(),
            internal_ip: "192.0.2.7".parse().unwrap(),
            external_port: port,
            internal_port: port,
            protocol: lanforge_types::network::firewall::L4Protocol::Udp,
            enable_hairpin: true,
        });
    fw
}

#[tokio::test]
async fn firewall_update_is_written_to_the_config_file() {
    let (client_ctx, _dir, path) = firewall_ctx().await;
    let fw = with_forward(7777);
    let res = client_ctx.handle_update_firewall_config(fw.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert_eq!(file_firewall(&path), fw);
    assert_eq!(client_ctx.ctx.get_firewall_config(), Some(fw));
}

#[tokio::test]
async fn firewall_with_a_zone_defined_twice_is_refused() {
    let (client_ctx, _dir, path) = firewall_ctx().await;
    let mut fw = lanforge_types::network::firewall::FirewallConfig::default();
    fw.zones.push(fw.zones[0].clone());
    let before = client_ctx.ctx.get_firewall_config();

    let res = client_ctx.handle_update_firewall_config(fw).await;

    assert!(matches!(res, Response::Error { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_firewall_config(), before);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[system]\niface = \"lan0\"\n"
    );
}

#[tokio::test]
async fn firewall_trial_is_saved_only_when_confirmed() {
    use lanforge_types::network::firewall::FirewallCommitRequest;

    let (client_ctx, _dir, path) = firewall_ctx().await;
    let saved = with_forward(7777);
    assert!(matches!(
        client_ctx
            .handle_update_firewall_config(saved.clone())
            .await,
        Response::Success(_)
    ));

    let candidate = with_forward(8888);
    let Response::FirewallValidation(report) =
        client_ctx.handle_firewall_propose(candidate.clone()).await
    else {
        panic!("propose");
    };
    let tx_id = report.tx_id.clone().expect("valid candidate");
    let res = client_ctx
        .handle_firewall_commit(FirewallCommitRequest {
            tx_id: tx_id.clone(),
            auto_rollback_secs: Some(60),
        })
        .await;
    assert!(matches!(res, Response::FirewallCommit(_)), "{res:?}");
    assert_eq!(
        client_ctx.ctx.get_firewall_config(),
        Some(candidate.clone())
    );
    assert_eq!(file_firewall(&path), saved, "a trial is not saved");

    let res = client_ctx.handle_firewall_confirm(tx_id).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert_eq!(file_firewall(&path), candidate, "confirmed: saved");
}

#[tokio::test]
async fn dhcp_updates_are_written_to_the_config_file() {
    use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};

    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);

    let pool = Dhcpv4Pool {
        name: Some("lan".into()),
        range_start: "192.168.1.100".parse().unwrap(),
        range_end: "192.168.1.200".parse().unwrap(),
        ntp_servers: vec!["192.0.2.123".parse().unwrap()],
        boot_file: Some("pxelinux.0".into()),
        ..Default::default()
    };
    let res = client_ctx
        .handle_update_dhcp_pools_config(vec![pool.clone()], vec![Dhcpv6Pool::default()])
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    // The unnamed v6 pool is named as the file names it.
    let v6 = client_ctx.ctx.get_dhcp_v6_pools();
    assert_eq!(v6[0].name.as_deref(), Some("pool-1"));

    let mut options = client_ctx.ctx.get_dhcp_options();
    options.v4.raw_options.insert(43, "vendor".into());
    options.tftp.enabled = true;
    let res = client_ctx.handle_update_dhcp_options(options.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let text = std::fs::read_to_string(&path).unwrap();
    let (file, issues) = lanforge_api::config_file::ConfigFile::parse(&text)
        .unwrap()
        .dhcp_settings();
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(
        file.options, options,
        "every option reaches the file, TFTP too"
    );
    assert_eq!(
        file.v4_pools,
        vec![pool.clone()],
        "the options update kept the pools"
    );
    assert!(text.contains("# mine"));
    assert_eq!(client_ctx.ctx.get_dhcp_options(), options);
    assert_eq!(client_ctx.ctx.get_dhcp_v4_pools(), vec![pool]);
}

#[tokio::test]
async fn a_dhcp_pool_the_file_cannot_hold_is_refused_and_not_applied() {
    use lanforge_types::network::dhcp::Dhcpv4Pool;

    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "[system]\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);
    let before = client_ctx.ctx.get_dhcp_v4_pools();

    let reversed = Dhcpv4Pool {
        name: Some("lan".into()),
        range_start: "192.168.1.200".parse().unwrap(),
        range_end: "192.168.1.100".parse().unwrap(),
        ..Default::default()
    };
    let res = client_ctx
        .handle_update_dhcp_pools_config(vec![reversed], Vec::new())
        .await;
    assert!(matches!(res, Response::Error { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_dhcp_v4_pools(), before);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[system]\n");
}

#[tokio::test]
async fn ra_update_is_written_to_the_config_file_without_the_lan_interface() {
    use lanforge_types::network::ra::{PrefixLifetime, RAPrefix};

    let client_ctx = init_test_context().await;
    client_ctx.ctx.set_target_interface_name("lan0".into());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);

    let mut cfg = client_ctx.ctx.get_ra_server_config();
    cfg.iface = Some("lan0".into());
    cfg.hop_limit = 128;
    let mut ula = RAPrefix::ula("fd00:1::/64");
    ula.valid_lifetime = PrefixLifetime::Infinity;
    ula.router_addr = false;
    cfg.prefixes = vec![ula, RAPrefix::gua_dynamic()];
    let res = client_ctx.handle_update_ra_config(cfg.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let text = std::fs::read_to_string(&path).unwrap();
    let file = lanforge_api::config_file::ConfigFile::parse(&text).unwrap();
    assert_eq!(file.ra.iface, None, "follows [system] iface");
    let (from_file, issues) = file.ra.to_config();
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(
        from_file.prefixes, cfg.prefixes,
        "infinity and the R flag reach the file"
    );
    assert_eq!(from_file.hop_limit, 128);
    assert!(text.contains("# mine"));
    assert_eq!(
        client_ctx.ctx.get_ra_server_config(),
        cfg,
        "applied as sent"
    );

    // A prefix the file cannot hold is refused, nothing applied.
    let mut bad = cfg.clone();
    bad.prefixes[0].address = Some("not-ipv6".into());
    let res = client_ctx.handle_update_ra_config(bad).await;
    assert!(matches!(res, Response::Error { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_ra_server_config(), cfg);
}

/// Host changes reach `[hosts]` before they apply: the reservation and the boot file are
/// written (comments kept), the DNS log switch is not (a WebUI setting, kept on the device).
#[tokio::test]
async fn host_changes_are_written_to_the_config_file() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    std::fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);
    let mac = MacAddr::parse("04:d9:f5:0a:25:94").unwrap();

    let entry = HostConfigEntry {
        mac,
        hostname: "solarium".into(),
        v4_fixed: Some("192.168.0.128".parse().unwrap()),
        v6_suffix: Ipv6AddrOrSuffix::parse("::501"),
        origin: Origin::Static,
        ignore_dns_log: true,
        ignored_log_domains: Vec::new(),
        boot_file: Some("pxelinux.0".into()),
    };
    let res = client_ctx.handle_host_add(entry).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let res = client_ctx
        .handle_host_set(mac, "v4".into(), "192.168.0.129".into())
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let text = std::fs::read_to_string(&path).unwrap();
    let (hosts, issues) = lanforge_api::config_file::ConfigFile::parse(&text)
        .unwrap()
        .static_hosts();
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(hosts, client_ctx.ctx.static_hosts());
    assert_eq!(hosts[0].v4, Some("192.168.0.129".parse().unwrap()));
    assert_eq!(hosts[0].boot_file.as_deref(), Some("pxelinux.0"));
    assert!(text.contains("# mine"));
    assert!(!text.contains("dns ="), "{text}");
    assert!(
        client_ctx.ctx.get_device(&mac).unwrap().ignore_dns_log,
        "kept on the device"
    );

    // A value the file cannot hold is refused, nothing written or applied.
    let res = client_ctx
        .handle_host_set(mac, "v6".into(), "::zz".into())
        .await;
    assert!(matches!(res, Response::Error { .. }), "{res:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

    // Removing it empties `[hosts]`; the device stays.
    let res = client_ctx.handle_host_remove(mac).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("[hosts"), "{text}");
    assert!(client_ctx.ctx.get_device(&mac).is_some());
}

/// An update without a boot file (the WebUI does not send one) keeps the host's.
#[tokio::test]
async fn a_host_update_without_a_boot_file_keeps_it() {
    let client_ctx = init_test_context().await;
    let mac = MacAddr::parse("04:d9:f5:0a:25:94").unwrap();
    let res = client_ctx
        .handle_host_set(mac, "boot_file".into(), "pxelinux.0".into())
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let entry = HostConfigEntry {
        mac,
        hostname: "solarium".into(),
        v4_fixed: Some("192.168.0.128".parse().unwrap()),
        origin: Origin::Static,
        ..Default::default()
    };
    let res = client_ctx.handle_host_add(entry).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert_eq!(
        client_ctx.ctx.static_hosts()[0].boot_file.as_deref(),
        Some("pxelinux.0")
    );
}
