use std::fs;
#[cfg(feature = "adblock")]
use std::iter;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
#[cfg(feature = "adblock")]
use tempfile::tempdir;
#[cfg(feature = "adblock")]
use tokio::sync::broadcast::Receiver;
use tokio::task::yield_now;
use tokio::time::sleep;

use crate::ClientContext;
use lanforge_api::api::{
    AllowlistEntry, DnsUpstreamConfig, HostConfigEntry, Response, SystemConfigExport,
};
#[cfg(feature = "adblock")]
use lanforge_api::config_file::AdblockSettings;
use lanforge_api::config_file::{ConfigFile, DnsSettings};
#[cfg(feature = "adblock")]
use lanforge_core::bus::TimedEvent;
use lanforge_core::bus::{DnsEvent, EventBus, LanforgeEvent, NetworkEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_db::worker::DbWorker;
use lanforge_db_core::Stores;
use lanforge_types::device::{Device, DeviceClass, IPv4State, Ipv6AddrOrSuffix, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockRuleAction, AdblockRuleEntry, AdblockSourceFormat, AdblockUrlKind,
    BlockingMode, RewriteAnswer, RewriteRule, TimeOfDay,
};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::firewall::{
    FirewallCommitRequest, FirewallConfig, L4Protocol, PortForwardRule,
};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::RaServerConfig;
use lanforge_types::network::{DnsRecordType, TrafficConfig};
use lanforge_types::system::ServiceId;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};

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

    let mut worker = DbWorker::new(DatabaseConfig::default(), ctx.clone(), db, log_db);
    let ctx_worker = ctx.clone();
    tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Db, ctx_worker.clone());
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
            refresh_time: TimeOfDay {
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
                format: AdblockSourceFormat::Auto,
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
            Some(vec![AdblockRuleEntry {
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
            TimeOfDay {
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

            // The allowlist of an (older) export becomes allow rules of the rules file; an
            // export carries every manual rule as written there.
            assert_eq!(cfg.dns_allowlist.len(), 0);
            let rules = cfg.dns_adblock_rules.as_ref().expect("rules present");
            let rules: Vec<_> = rules
                .iter()
                .map(|r| (r.domain.as_str(), r.action, r.enabled))
                .collect();
            assert_eq!(
                rules,
                [
                    ("@@||allowed-import.lan^", AdblockRuleAction::Allow, true),
                    ("||custom-blocked.com^", AdblockRuleAction::Block, true),
                ]
            );
            let Response::DnsAllowlist(allowlist) = client_ctx.handle_dns_allowlist(None).await
            else {
                panic!("Expected Response::DnsAllowlist");
            };
            assert_eq!(allowlist.allowlist.len(), 1);
            assert_eq!(allowlist.allowlist[0].domain, "allowed-import.lan");
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
    // A device answer is not a CNAME: refused, nothing applied.
    let wrong = RewriteRule {
        id: None,
        domain: "*.eonteam.xyz".to_string(),
        rtype: DnsRecordType::CNAME,
        answer: RewriteAnswer::from_str("dev:raspie").unwrap(),
    };
    let res = client_ctx.handle_dns_rewrite_add(wrong).await;
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert!(client_ctx.ctx.get_dns_rewrites().is_empty());

    let rule = RewriteRule {
        id: None,
        domain: "*.eonteam.xyz".to_string(),
        rtype: DnsRecordType::Device,
        answer: RewriteAnswer::from_str("dev:raspie").unwrap(),
    };
    let res = client_ctx.handle_dns_rewrite_add(rule).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    // Try loading rewrites back
    let load_res = client_ctx.handle_dns_rewrites().await;
    if let Response::DnsRewrites(r) = load_res {
        assert_eq!(r.rewrites.len(), 1);
        assert_eq!(r.rewrites[0].domain, "*.eonteam.xyz");
        assert_eq!(r.rewrites[0].rtype, DnsRecordType::Device);
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
    let expires = SystemTime::now() + Duration::from_secs(3600);

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
    let expires = SystemTime::now() + Duration::from_secs(3600);
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
    assert!(!matches!(dev.v4, IPv4State::Static(_)));
    assert!(client_ctx.ctx.static_hosts().is_empty());

    // 4. Purge forgets it
    let res = client_ctx.handle_purge(mac).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert!(client_ctx.ctx.get_device(&mac).is_none());
}

/// The manual prune runs the in-memory prune (one rule, one retention clock): a device the
/// admin classified stays in memory and in the database even without a name or an address.
#[tokio::test]
async fn manual_prune_keeps_a_device_with_admin_settings() {
    let client_ctx = init_test_context().await;
    while client_ctx.ctx.storage_handle().is_none() {
        yield_now().await;
    }
    let storage = client_ctx.ctx.storage_handle().unwrap();
    let mac = MacAddr::parse("02:00:00:00:00:31").unwrap();
    let _ = client_ctx.ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            class: FieldUpdate::Set(DeviceClass::Printer),
            origin: Origin::Dynamic,
            ..CliHostUpdate::default()
        }),
    });
    let dev = client_ctx
        .ctx
        .get_device(&mac)
        .expect("the update creates it");
    assert!(!dev.has_address() && dev.hostname.name.is_empty());
    let dev = Device::clone(&dev);
    storage
        .call(move |s: &Stores| s.db().upsert_device(&dev))
        .await
        .unwrap();

    let res = client_ctx.handle_db_prune().await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    assert!(client_ctx.ctx.get_device(&mac).is_some());
    let stored = storage
        .call(|s: &Stores| s.db().load_all_devices())
        .await
        .unwrap();
    assert!(
        stored.iter().any(|d| d.mac == mac),
        "deleted from the database"
    );
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

fn pppoe_with(username: &str) -> PppoeConfig {
    let mut cfg = PppoeConfig {
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
    fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);

    let cfg = pppoe_with("api-user");
    let res = client_ctx.handle_update_pppoe_config(cfg.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let text = fs::read_to_string(&path).unwrap();
    let file = ConfigFile::parse(&text).unwrap();
    assert_eq!(file.pppoe, cfg, "every field reaches the file");
    assert!(text.contains("# mine") && text.contains("iface = \"lan0\""));
    assert_eq!(client_ctx.ctx.get_pppoe_config(), Some(cfg));
}

#[tokio::test]
async fn pppoe_update_is_rejected_when_the_file_cannot_take_it() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "[system\nbroken").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);
    let before = client_ctx.ctx.get_pppoe_config();

    let res = client_ctx
        .handle_update_pppoe_config(pppoe_with("lost"))
        .await;

    assert!(matches!(res, Response::Error { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_pppoe_config(), before, "not applied");
    assert_eq!(fs::read_to_string(&path).unwrap(), "[system\nbroken");
}

#[tokio::test]
async fn pppoe_update_on_read_only_config_applies_in_memory_and_says_so() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "[system]\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(false);

    let cfg = pppoe_with("ram-only");
    let res = client_ctx.handle_update_pppoe_config(cfg.clone()).await;

    let Response::Success(ok) = res else {
        panic!("{res:?}");
    };
    assert!(ok.message.contains("not saved"), "{}", ok.message);
    assert_eq!(client_ctx.ctx.get_pppoe_config(), Some(cfg));
    assert_eq!(fs::read_to_string(&path).unwrap(), "[system]\n");
}

#[tokio::test]
async fn traffic_update_is_written_to_the_config_file() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);

    let mut cfg = TrafficConfig::default();
    cfg.sqm.enabled = true;
    cfg.sqm.rtt_ms = Some(25);
    cfg.sqm.raw_cake_args = Some("ack-filter".into());
    let res = client_ctx.handle_update_traffic_config(cfg.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let text = fs::read_to_string(&path).unwrap();
    let file = ConfigFile::parse(&text).unwrap();
    assert_eq!(file.traffic, cfg, "every field reaches the file");
    assert!(text.contains("# mine"));
    assert_eq!(client_ctx.ctx.get_traffic_config(), Some(cfg));
}

// ---------------------------------------------------------------------------
// Firewall is file-owned: saved before it applies; a trial (auto-rollback) is not saved
// ---------------------------------------------------------------------------

fn file_firewall(path: &Path) -> FirewallConfig {
    let text = fs::read_to_string(path).unwrap();
    let (fw, issues) = ConfigFile::parse(&text).unwrap().firewall.to_config();
    assert!(issues.is_empty(), "{issues:?}");
    fw
}

async fn firewall_ctx() -> (ClientContext, TempDir, PathBuf) {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "[system]\niface = \"lan0\"\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);
    (client_ctx, dir, path)
}

fn with_forward(port: u16) -> FirewallConfig {
    let mut fw = FirewallConfig::default();
    fw.port_forwards.push(PortForwardRule {
        comment: Some("game".into()),
        src_zone: "external".into(),
        internal_ip: "192.0.2.7".parse().unwrap(),
        external_port: port,
        internal_port: port,
        protocol: L4Protocol::Udp,
        enable_hairpin: true,
        family: None,
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
    let mut fw = FirewallConfig::default();
    fw.zones.push(fw.zones[0].clone());
    let before = client_ctx.ctx.get_firewall_config();

    let res = client_ctx.handle_update_firewall_config(fw).await;

    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_firewall_config(), before);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "[system]\niface = \"lan0\"\n"
    );
}

#[tokio::test]
async fn firewall_trial_is_saved_only_when_confirmed() {
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
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
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

    let text = fs::read_to_string(&path).unwrap();
    let (file, issues) = ConfigFile::parse(&text).unwrap().dhcp_settings();
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
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "[system]\n").unwrap();
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
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_dhcp_v4_pools(), before);
    assert_eq!(fs::read_to_string(&path).unwrap(), "[system]\n");
}

#[tokio::test]
async fn ra_update_is_written_to_the_config_file_without_the_lan_interface() {
    use lanforge_types::network::ra::{PrefixLifetime, RAPrefix};

    let client_ctx = init_test_context().await;
    client_ctx.ctx.set_target_interface_name("lan0".into());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
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

    let text = fs::read_to_string(&path).unwrap();
    let file = ConfigFile::parse(&text).unwrap();
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
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_ra_server_config(), cfg);
}

/// `[pppoe]` values the client cannot run on are refused before they are written: MRU 0
/// reached `PPPIOCSMRU`, a 0 s reconnect delay loops against the ISP, 0 PADI retries never
/// dials. Echo 0 (off) is a legal value.
#[tokio::test]
async fn pppoe_update_the_client_cannot_run_on_is_refused() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "[system]\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);
    let before = client_ctx.ctx.get_pppoe_config();

    type Edit = fn(&mut PppoeConfig);
    let cases: [(&str, Edit); 6] = [
        ("mru 0", |c| c.mru = 0),
        ("mru 1279", |c| c.mru = 1279),
        ("mru 1500", |c| c.mru = 1500),
        ("reconnect delay 0", |c| c.reconnect_delay_secs = 0),
        ("padi retries 0", |c| c.discovery_padi_retries = 0),
        ("padi timeout 0", |c| c.discovery_padi_timeout_secs = 0),
    ];
    for (name, edit) in cases {
        let mut cfg = PppoeConfig::default();
        edit(&mut cfg);
        let res = client_ctx.handle_update_pppoe_config(cfg).await;
        assert!(matches!(res, Response::Rejected { .. }), "{name}: {res:?}");
        assert_eq!(client_ctx.ctx.get_pppoe_config(), before, "{name}: applied");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[system]\n",
            "{name}: written"
        );
    }

    let cfg = PppoeConfig {
        mru: 1280,
        lcp_echo_interval_secs: 0,
        lcp_echo_max_failures: 0,
        ..Default::default()
    };
    let res = client_ctx.handle_update_pppoe_config(cfg.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert_eq!(client_ctx.ctx.get_pppoe_config(), Some(cfg));
}

/// RA timing outside RFC 4861 §6.2.1 (and an MTU below 1280) is refused before it is written:
/// the RA service refuses to run on such a value, so accepting it took RA down.
#[tokio::test]
async fn ra_update_outside_rfc_ranges_is_refused() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "[system]\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);
    let before = client_ctx.ctx.get_ra_server_config();

    type Edit = fn(&mut RaServerConfig);
    let cases: [(&str, Edit); 7] = [
        ("max_interval 0", |c| c.max_interval_secs = 0),
        ("max_interval 1801", |c| c.max_interval_secs = 1801),
        ("min_interval 2", |c| c.min_interval_secs = Some(2)),
        ("min_interval > 0.75 max", |c| {
            c.max_interval_secs = 100;
            c.min_interval_secs = Some(76);
        }),
        ("lifetime below max_interval", |c| {
            c.max_interval_secs = 600;
            c.lifetime_secs = Some(300);
        }),
        ("lifetime 9001", |c| c.lifetime_secs = Some(9001)),
        ("mtu 1000", |c| c.mtu = Some(1000)),
    ];
    for (name, edit) in cases {
        let mut cfg = before.clone();
        edit(&mut cfg);
        let res = client_ctx.handle_update_ra_config(cfg).await;
        assert!(matches!(res, Response::Rejected { .. }), "{name}: {res:?}");
        assert_eq!(
            client_ctx.ctx.get_ra_server_config(),
            before,
            "{name}: applied"
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[system]\n",
            "{name}: written"
        );
    }

    // The edges are legal: lifetime 0 (not a default router), min 3 with max 4, MTU 1280.
    let mut edge = before.clone();
    edge.max_interval_secs = 4;
    edge.min_interval_secs = Some(3);
    edge.lifetime_secs = Some(0);
    edge.mtu = Some(1280);
    let res = client_ctx.handle_update_ra_config(edge.clone()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert_eq!(client_ctx.ctx.get_ra_server_config().max_interval_secs, 4);
}

/// Host changes reach `[hosts]` before they apply: the reservation and the boot file are
/// written (comments kept), the DNS log switch is not (a `WebUI` setting, kept on the device).
#[tokio::test]
async fn host_changes_are_written_to_the_config_file() {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "# mine\n[system]\niface = \"lan0\"\n").unwrap();
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

    let text = fs::read_to_string(&path).unwrap();
    let (hosts, issues) = ConfigFile::parse(&text).unwrap().static_hosts();
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
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert_eq!(fs::read_to_string(&path).unwrap(), text);

    // Removing it empties `[hosts]`; the device stays.
    let res = client_ctx.handle_host_remove(mac).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.contains("[hosts"), "{text}");
    assert!(client_ctx.ctx.get_device(&mac).is_some());
}

/// An update without a boot file (the `WebUI` does not send one) keeps the host's.
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

/// The owner's `[dns]` (approved file form, 2026-10-28), with a comment above it.
const OWNER_DNS: &str = "[system]\niface = \"lan0\"\n\n# resolvers\n[dns]\nenabled = true\n\
    listen = \"[::]:53\"\nupstream_mode = \"sequential\"\n\n[dns.upstreams.default]\n\
    addresses = [\"udp://1.1.1.1:53\", \"udp://1.0.0.1:53\"]\n\n[dns.rewrites]\n\
    \"*.eonteam.xyz\" = \"dev:pixie\"\n";

/// A client whose live DNS settings are `OWNER_DNS`, as the boot applies them.
async fn owner_dns_client(writable: bool) -> (ClientContext, TempDir) {
    let client_ctx = init_test_context().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, OWNER_DNS).unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(writable);
    let (dns, issues) = ConfigFile::parse(OWNER_DNS).unwrap().dns.to_config();
    assert!(issues.is_empty(), "{issues:?}");
    client_ctx.apply_dns_settings(dns);
    (client_ctx, dir)
}

fn dns_in_file(dir: &TempDir) -> (DnsSettings, String) {
    let text = fs::read_to_string(dir.path().join("lanforge.toml")).unwrap();
    let (dns, issues) = ConfigFile::parse(&text).unwrap().dns.to_config();
    assert!(issues.is_empty(), "{issues:?}\n{text}");
    (dns, text)
}

/// Every DNS change of the API reaches `[dns]` before it applies: the file keeps the group
/// names, the listener and the comment, and holds exactly what runs.
#[tokio::test]
async fn dns_changes_are_written_to_the_config_file() {
    use lanforge_types::network::dns::upstream::UpstreamMode;
    use std::str::FromStr;

    let (client_ctx, dir) = owner_dns_client(true).await;

    let res = client_ctx
        .handle_dns_rewrite_add(RewriteRule {
            id: None,
            domain: "nas.lan".into(),
            rtype: DnsRecordType::A,
            answer: RewriteAnswer::from_str("192.0.2.10").unwrap(),
        })
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let res = client_ctx
        .handle_dns_upstream_add("9.9.9.9:53".parse().unwrap(), UpstreamProtocol::Udp, None)
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let res = client_ctx
        .handle_dns_upstream_mode_set(UpstreamMode::Parallel)
        .await;
    assert!(matches!(res, Response::DnsUpstreamMode(_)), "{res:?}");
    let res = client_ctx
        .handle_dns_reverse_resolver_add("10.8.0.0/24".into(), "udp://10.8.0.1:53".into())
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let (dns, text) = dns_in_file(&dir);
    assert!(text.contains("# resolvers"), "{text}");
    assert!(text.contains("listen = \"[::]:53\""), "{text}");
    assert_eq!(dns.upstream_mode, UpstreamMode::Parallel);
    let names: Vec<_> = dns.upstreams.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(names, ["default", "default", "default"], "{text}");
    assert_eq!(dns.reverse.len(), 1);
    assert_eq!(
        dns.rewrites
            .iter()
            .map(|r| r.domain.as_str())
            .collect::<Vec<_>>(),
        ["*.eonteam.xyz", "nas.lan"]
    );
    // What runs is what the file holds.
    let ctx = &client_ctx.ctx;
    assert_eq!(
        ctx.get_dns_upstreams(),
        dns.upstreams
            .iter()
            .map(|u| u.target.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(ctx.get_dns_upstream_mode(), dns.upstream_mode);
    assert_eq!(ctx.get_dns_rewrites(), dns.rewrites);
    assert_eq!(ctx.all_reverse_resolvers(), dns.reverse);

    // Removing through the ids the listing gives.
    let Response::DnsRewrites(listed) = client_ctx.handle_dns_rewrites().await else {
        panic!("listing");
    };
    let nas = listed
        .rewrites
        .iter()
        .find(|r| r.domain == "nas.lan")
        .unwrap();
    let res = client_ctx.handle_dns_rewrite_remove(nas.id.unwrap()).await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let res = client_ctx
        .handle_dns_upstream_remove("9.9.9.9:53".parse().unwrap(), UpstreamProtocol::Udp, None)
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let res = client_ctx
        .handle_dns_reverse_resolver_remove("10.8.0.0/24".into())
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let res = client_ctx
        .handle_dns_upstream_mode_set(UpstreamMode::Sequential)
        .await;
    assert!(matches!(res, Response::DnsUpstreamMode(_)), "{res:?}");

    let (back, text) = dns_in_file(&dir);
    let owner = ConfigFile::parse(OWNER_DNS).unwrap().dns.to_config().0;
    assert_eq!(back, owner, "back to the owner's settings\n{text}");
}

/// A device keeps one IPv4 and one IPv6 fallback, as the file's table form: adding the second
/// family keeps the first, a new address of a family replaces that one, and a device rule
/// without fallback replaces both.
#[tokio::test]
async fn device_rewrite_keeps_one_fallback_per_family() {
    use std::str::FromStr;

    let (client_ctx, dir) = owner_dns_client(true).await;
    let add = |answer: &str| {
        let rule = RewriteRule {
            id: None,
            domain: "tv.lan".into(),
            rtype: DnsRecordType::Device,
            answer: RewriteAnswer::from_str(answer).unwrap(),
        };
        let client_ctx = &client_ctx;
        async move {
            let res = client_ctx.handle_dns_rewrite_add(rule).await;
            assert!(matches!(res, Response::Success(_)), "{res:?}");
        }
    };
    let tv = |dir: &tempfile::TempDir| {
        let (dns, text) = dns_in_file(dir);
        let answers: Vec<String> = dns
            .rewrites
            .iter()
            .filter(|r| r.domain == "tv.lan")
            .map(|r| r.answer.to_string())
            .collect();
        (answers, text)
    };

    add("dev:tv|192.0.2.20").await;
    add("dev:tv|2001:db8::20").await;
    let (answers, text) = tv(&dir);
    assert_eq!(
        answers,
        ["dev:tv|192.0.2.20", "dev:tv|2001:db8::20"],
        "{text}"
    );
    assert!(text.contains("fallback = ["), "one table item:\n{text}");

    add("dev:tv|192.0.2.21").await;
    assert_eq!(tv(&dir).0, ["dev:tv|192.0.2.21", "dev:tv|2001:db8::20"]);

    add("dev:tv|tv.example").await;
    assert_eq!(tv(&dir).0, ["dev:tv|tv.example"]);

    add("dev:tv").await;
    assert_eq!(tv(&dir).0, ["dev:tv"]);
    assert_eq!(
        client_ctx.ctx.get_dns_rewrites(),
        dns_in_file(&dir).0.rewrites
    );
}

/// A change the file form cannot hold, or a file that cannot be written, changes nothing.
#[tokio::test]
async fn a_refused_dns_change_writes_and_applies_nothing() {
    let (client_ctx, dir) = owner_dns_client(true).await;
    let res = client_ctx
        .handle_dns_rewrite_add(RewriteRule {
            id: None,
            domain: "mismatch.lan".into(),
            rtype: DnsRecordType::AAAA,
            answer: RewriteAnswer::A("192.0.2.1".parse().unwrap()),
        })
        .await;
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert_eq!(
        fs::read_to_string(dir.path().join("lanforge.toml")).unwrap(),
        OWNER_DNS
    );
    assert_eq!(client_ctx.ctx.get_dns_rewrites().len(), 1);

    fs::write(dir.path().join("lanforge.toml"), "[system\nbroken").unwrap();
    let res = client_ctx
        .handle_dns_upstream_set_default(vec!["9.9.9.9:53".parse().unwrap()])
        .await;
    assert!(matches!(res, Response::Error { .. }), "{res:?}");
    assert_eq!(client_ctx.ctx.get_dns_upstreams().len(), 2, "not applied");
}

/// A preset replaces the default upstreams in one change and keeps the domain-scoped ones; an
/// empty preset is refused (a resolver without upstreams is set in the file).
#[tokio::test]
async fn dns_default_upstreams_are_replaced_in_one_change() {
    let (client_ctx, dir) = owner_dns_client(true).await;
    let res = client_ctx
        .handle_dns_upstream_add(
            "10.8.0.1:53".parse().unwrap(),
            UpstreamProtocol::Udp,
            Some("corp.lan".into()),
        )
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let quad9: Vec<SocketAddr> = vec![
        "9.9.9.9:53".parse().unwrap(),
        "[2620:fe::fe]:53".parse().unwrap(),
    ];
    let res = client_ctx
        .handle_dns_upstream_set_default(quad9.clone())
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");

    let (dns, text) = dns_in_file(&dir);
    let in_file: Vec<_> = dns
        .upstreams
        .iter()
        .map(|u| (u.target.addr, u.target.domain.clone()))
        .collect();
    assert_eq!(
        in_file,
        vec![
            ("10.8.0.1:53".parse().unwrap(), Some("corp.lan".to_string())),
            (quad9[0], None),
            (quad9[1], None),
        ],
        "{text}"
    );
    assert_eq!(client_ctx.ctx.get_dns_upstreams().len(), 3);

    let res = client_ctx.handle_dns_upstream_set_default(Vec::new()).await;
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    assert_eq!(dns_in_file(&dir).0.upstreams.len(), 3, "file untouched");
    assert_eq!(
        client_ctx.ctx.get_dns_upstreams().len(),
        3,
        "memory untouched"
    );
}

#[tokio::test]
async fn dns_change_on_read_only_config_applies_in_memory_and_says_so() {
    let (client_ctx, dir) = owner_dns_client(false).await;
    let res = client_ctx.handle_dns_rewrite_clear().await;
    let Response::Success(ok) = res else {
        panic!("{res:?}");
    };
    assert!(ok.message.contains("not saved"), "{}", ok.message);
    assert!(client_ctx.ctx.get_dns_rewrites().is_empty());
    assert_eq!(
        fs::read_to_string(dir.path().join("lanforge.toml")).unwrap(),
        OWNER_DNS
    );
}

/// An overwriting import replaces the `[dns]` lists in one write; nothing goes to redb.
#[tokio::test]
async fn dns_import_overwrite_replaces_the_file_lists() {
    let (client_ctx, dir) = owner_dns_client(true).await;
    let export = SystemConfigExport {
        dns_upstreams: vec![DnsUpstreamConfig {
            name: Some("quad9".into()),
            addr: "9.9.9.9:53".parse().unwrap(),
            protocol: UpstreamProtocol::Udp,
            domain: None,
        }],
        dns_rewrites: vec![RewriteRule {
            id: None,
            domain: "nas.lan".into(),
            rtype: DnsRecordType::A,
            answer: RewriteAnswer::A("192.0.2.10".parse().unwrap()),
        }],
        overwrite: true,
        ..Default::default()
    };
    let res = client_ctx.handle_system_config_import(export).await;
    let Response::SystemConfigImport(r) = res else {
        panic!("{res:?}");
    };
    let dns_results: Vec<_> = r
        .results
        .iter()
        .filter(|x| format!("{:?}", x.section).starts_with("Dns"))
        .filter(|x| !format!("{:?}", x.section).starts_with("DnsAdblock"))
        .filter(|x| !format!("{:?}", x.section).starts_with("DnsAllow"))
        .collect();
    assert!(dns_results.iter().all(|x| x.success), "{dns_results:?}");

    let (dns, text) = dns_in_file(&dir);
    assert_eq!(dns.upstreams.len(), 1, "{text}");
    assert_eq!(dns.upstreams[0].name, "quad9");
    assert_eq!(dns.rewrites.len(), 1);
    assert_eq!(dns.rewrites[0].domain, "nas.lan");
    assert_eq!(client_ctx.ctx.get_dns_rewrites(), dns.rewrites);
}

/// The owner's `[adblock]` and global rules (approved file form, 2026-10-28).
#[cfg(feature = "adblock")]
const OWNER_ADBLOCK: &str = "[system]\niface = \"lan0\"\n\n# filtering\n[adblock]\nenabled = true\n\
    blocking_mode = \"nxdomain\"\nrefresh_time = \"03:00\"\nlists = [\"src-7cc6f305\"]\n\
    rules = \"adblock/global.rules\"\n\n[adblock.sources.src-7cc6f305]\n\
    url = \"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts\"\nformat = \"hosts\"\n";

#[cfg(feature = "adblock")]
const OWNER_RULES: &str = "! Bradesco\n@@||app-measurement.com^\n@@||www.googletagmanager.com^\n\
    @@||js-cdn.dynatrace.com^\n@@||analytics.google.com^\n";

/// A client whose live adblock settings and rules are the owner's, as the boot applies them.
#[cfg(feature = "adblock")]
async fn owner_adblock_client(writable: bool) -> (ClientContext, TempDir) {
    let client_ctx = init_test_context().await;
    let dir = tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, OWNER_ADBLOCK).unwrap();
    fs::create_dir(dir.path().join("adblock")).unwrap();
    fs::write(dir.path().join("adblock/global.rules"), OWNER_RULES).unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(writable);
    let (adblock, issues) = ConfigFile::parse(OWNER_ADBLOCK)
        .unwrap()
        .adblock
        .to_config();
    assert!(issues.is_empty(), "{issues:?}");
    client_ctx.apply_adblock_settings(&adblock);
    client_ctx
        .ctx
        .update_dns_adblock_rules(OWNER_RULES.to_string());
    (client_ctx, dir)
}

/// `[adblock]` and the rules file as the boot reads them, plus the `lanforge.toml` text.
#[cfg(feature = "adblock")]
fn adblock_in_files(dir: &TempDir) -> (AdblockSettings, String, String) {
    let text = fs::read_to_string(dir.path().join("lanforge.toml")).unwrap();
    let (adblock, issues) = ConfigFile::parse(&text).unwrap().adblock.to_config();
    assert!(issues.is_empty(), "{issues:?}\n{text}");
    let (rules, rule_issues) = adblock.load_rules(&dir.path().join("lanforge.toml"));
    assert!(rule_issues.is_empty(), "{rule_issues:?}");
    (adblock, rules.unwrap(), text)
}

/// Every adblock change of the API reaches `[adblock]` or the rules file before it applies:
/// what runs is what the files hold, the comment and the source name stay.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn adblock_changes_are_written_to_the_files() {
    use lanforge_types::network::dns::adblock::{BlockingMode, TimeOfDay};

    let (client_ctx, dir) = owner_adblock_client(true).await;
    let ok = |res: Response| assert!(matches!(res, Response::Success(_)), "{res:?}");

    ok(client_ctx
        .handle_dns_adblock_url_add(
            Some("oisd".into()),
            "https://small.oisd.nl".into(),
            AdblockUrlKind::Blocklist,
            None,
            None,
        )
        .await);
    ok(client_ctx
        .handle_dns_adblock_config_set(
            Some(BlockingMode::NullIp),
            None,
            None,
            Some(TimeOfDay::new(4, 30).unwrap()),
        )
        .await);
    ok(client_ctx
        .handle_dns_block("ads.example".into(), None)
        .await);
    ok(client_ctx
        .handle_dns_adblock_rule_add("||track.example^$important".into(), "block".into(), None)
        .await);
    // Allowing a blocked domain replaces its block rule.
    ok(client_ctx
        .handle_dns_allow("ads.example".into(), None)
        .await);
    ok(client_ctx
        .handle_dns_unallow("analytics.google.com".into(), None)
        .await);

    let (adblock, rules, text) = adblock_in_files(&dir);
    assert!(text.contains("# filtering\n[adblock]"), "{text}");
    assert_eq!(adblock.lists, ["src-7cc6f305", "oisd"], "{text}");
    assert_eq!(adblock.config.blocking_mode, BlockingMode::NullIp);
    assert_eq!(adblock.config.refresh_time, TimeOfDay::new(4, 30).unwrap());
    assert_eq!(
        rules,
        "! Bradesco\n@@||app-measurement.com^\n@@||www.googletagmanager.com^\n\
         @@||js-cdn.dynatrace.com^\n||track.example^$important\n@@||ads.example^\n"
    );
    assert_eq!(client_ctx.ctx.get_dns_adblock_rules(), rules);
    assert_eq!(client_ctx.ctx.get_dns_adblock(), adblock.config);
    assert_eq!(
        client_ctx.ctx.get_dns_adblock_urls(),
        adblock.global_sources().cloned().collect::<Vec<_>>()
    );

    // Disable, then remove, by the id the listing gives.
    let Response::DnsAdblockRules(listed) = client_ctx.handle_dns_adblock_rules(None).await else {
        panic!("Expected Response::DnsAdblockRules");
    };
    let track = listed
        .rules
        .iter()
        .find(|r| r.domain == "||track.example^$important")
        .and_then(|r| r.id)
        .unwrap();
    ok(client_ctx
        .handle_dns_adblock_rule_status(track, false, None)
        .await);
    assert!(
        adblock_in_files(&dir)
            .1
            .contains("# ||track.example^$important\n")
    );
    ok(client_ctx.handle_dns_adblock_rule_remove(track, None).await);
    assert!(!adblock_in_files(&dir).1.contains("track.example"));

    ok(client_ctx
        .handle_dns_adblock_url_remove(
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into(),
        )
        .await);
    let (adblock, _, _) = adblock_in_files(&dir);
    assert_eq!(adblock.lists, ["oisd"]);
    assert_eq!(adblock.sources.len(), 1);
}

/// A rule the rules file refuses (a `$client` modifier is never widened to everyone) and an
/// unknown id write and apply nothing.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn a_refused_adblock_change_writes_and_applies_nothing() {
    let (client_ctx, dir) = owner_adblock_client(true).await;
    for res in [
        client_ctx
            .handle_dns_adblock_rule_add(
                "||x.example^$client=10.0.0.1".into(),
                "block".into(),
                None,
            )
            .await,
        client_ctx
            .handle_dns_adblock_url_add(
                None,
                "ftp://example.com/list".into(),
                AdblockUrlKind::Blocklist,
                None,
                None,
            )
            .await,
    ] {
        assert!(matches!(res, Response::Rejected { .. }), "{res:?}");
    }
    let res = client_ctx.handle_dns_adblock_rule_remove(42, None).await;
    assert!(matches!(res, Response::NotFound { .. }), "{res:?}");
    let (_, rules, text) = adblock_in_files(&dir);
    assert_eq!(rules, OWNER_RULES);
    assert_eq!(text, OWNER_ADBLOCK);
    assert_eq!(client_ctx.ctx.get_dns_adblock_rules(), OWNER_RULES);
    assert_eq!(client_ctx.ctx.get_dns_adblock_urls().len(), 1);
}

#[cfg(feature = "adblock")]
#[tokio::test]
async fn adblock_change_on_read_only_config_applies_in_memory_and_says_so() {
    let (client_ctx, dir) = owner_adblock_client(false).await;
    let res = client_ctx
        .handle_dns_block("ads.example".into(), None)
        .await;
    let Response::Success(ok) = res else {
        panic!("{res:?}");
    };
    assert!(ok.message.contains("not saved"), "{}", ok.message);
    assert!(
        client_ctx
            .ctx
            .get_dns_adblock_rules()
            .ends_with("||ads.example^\n")
    );
    let (_, rules, text) = adblock_in_files(&dir);
    assert_eq!(
        (rules.as_str(), text.as_str()),
        (OWNER_RULES, OWNER_ADBLOCK)
    );
}

/// Blocking through the rules endpoint is the same write as `dns_block`: watchers hear
/// `AdblockBlock` either way (the rules endpoint used to block silently).
#[cfg(feature = "adblock")]
#[tokio::test]
async fn every_block_path_announces_the_block() {
    let (client_ctx, _dir) = owner_adblock_client(true).await;
    let mut rx = client_ctx.ctx.bus().subscribe_dns();
    let blocked = |rx: &mut Receiver<_>| {
        iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|e: TimedEvent| match e.event {
                LanforgeEvent::Dns(DnsEvent::AdblockBlock(d)) => Some(d),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    let res = client_ctx
        .handle_dns_adblock_rule_add("ads.example".into(), "block".into(), None)
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert_eq!(blocked(&mut rx), ["ads.example"]);

    let res = client_ctx
        .handle_dns_block("track.example".into(), None)
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert_eq!(blocked(&mut rx), ["track.example"]);

    let res = client_ctx
        .handle_dns_adblock_rule_add("bank.example".into(), "allow".into(), None)
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    assert!(blocked(&mut rx).is_empty());
}

/// A pasted list lands in the rules file in one change: every rule appended after the owner's,
/// the junk reported with its line, the TOML untouched. The owner's Bradesco allow survives a
/// list that blocks the same domain.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn a_pasted_list_is_imported_in_one_write() {
    let (client_ctx, dir) = owner_adblock_client(true).await;
    let pasted = "# copied from a forum\nads.example\n0.0.0.0 pixel.example\n\
                  analytics.google.com\nnot a rule\n";
    let res = client_ctx
        .handle_dns_adblock_rules_import(pasted.into(), "block".into(), None)
        .await;
    let Response::DnsAdblockRulesImport(report) = res else {
        panic!("{res:?}");
    };
    assert_eq!(
        (report.added, report.conflicts, report.rejected_total),
        (2, 1, 1)
    );
    assert_eq!(report.rejected[0].line, 5);
    assert!(report.saved);
    let expected = format!("{OWNER_RULES}||ads.example^\n0.0.0.0 pixel.example\n");
    let (_, rules, text) = adblock_in_files(&dir);
    assert_eq!(rules, expected);
    assert_eq!(text, OWNER_ADBLOCK);
    assert_eq!(client_ctx.ctx.get_dns_adblock_rules(), expected);

    let res = client_ctx
        .handle_dns_adblock_rules_import("x.example".into(), "drop".into(), None)
        .await;
    assert!(matches!(res, Response::Rejected { .. }), "{res:?}");

    // A read-only configuration takes the list in memory and says it is not saved.
    let (client_ctx, dir) = owner_adblock_client(false).await;
    let res = client_ctx
        .handle_dns_adblock_rules_import("ads.example".into(), "block".into(), None)
        .await;
    let Response::DnsAdblockRulesImport(report) = res else {
        panic!("{res:?}");
    };
    assert!(!report.saved);
    assert!(
        client_ctx
            .ctx
            .get_dns_adblock_rules()
            .ends_with("||ads.example^\n")
    );
    assert_eq!(adblock_in_files(&dir).1, OWNER_RULES);
}

/// Without a rules file, the first manual rule creates `adblock/global.rules` and names it in
/// `[adblock]`.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn the_first_rule_creates_the_rules_file() {
    let client_ctx = init_test_context().await;
    let dir = tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    fs::write(&path, "[adblock]\nenabled = true\n").unwrap();
    client_ctx.ctx.set_config_path(&path);
    client_ctx.ctx.set_config_writable(true);

    let res = client_ctx
        .handle_dns_allow("bank.example".into(), None)
        .await;
    assert!(matches!(res, Response::Success(_)), "{res:?}");
    let (adblock, rules, _) = adblock_in_files(&dir);
    assert_eq!(adblock.rules.as_deref(), Some("adblock/global.rules"));
    assert_eq!(rules, "@@||bank.example^\n");
    let Response::DnsAllowlist(list) = client_ctx.handle_dns_allowlist(None).await else {
        panic!("Expected Response::DnsAllowlist");
    };
    assert_eq!(list.allowlist.len(), 1);
    assert_eq!(list.allowlist[0].domain, "bank.example");
}

/// With DNS not serving, the configured upstreams are listed unmeasured. They used to come back
/// "healthy, 1.2 ms, last success 0 s ago" — numbers nobody measured.
#[tokio::test]
async fn upstreams_without_dns_are_unmeasured() {
    use lanforge_types::network::dns::upstream::UpstreamTarget;

    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.update_dns_upstreams(vec!["udp://9.9.9.9:53".parse::<UpstreamTarget>().unwrap()]);

    let Response::DnsUpstreams(res) = ClientContext::new(ctx).handle_dns_upstreams().await else {
        panic!("upstreams response");
    };
    let [up] = res.upstreams.as_slice() else {
        panic!("one configured upstream: {:?}", res.upstreams);
    };
    assert_eq!(up.target.to_string(), "9.9.9.9:53");
    assert_eq!((up.rtt_ewma_us, up.last_rtt_us), (0, 0));
    assert_eq!(up.status.as_str(), "unknown");
    assert_eq!(up.last_success_secs_ago, None);
}

/// A query answered a moment ago is in the log at once: the DB worker batches the query log
/// (60 s / 100 lines), so the log read writes that batch first.
#[tokio::test]
async fn a_fresh_query_is_in_the_log_at_once() {
    use lanforge_types::network::dns::{QueryLogEntry, QueryResult, TransportProtocol};

    let client = init_test_context().await;
    let storage = loop {
        if let Some(s) = client.ctx.storage_handle() {
            break s;
        }
        yield_now().await;
    };
    // The worker answers storage calls only from `serve`, after it subscribed to the bus.
    storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .unwrap();
    // The periodic flush ticks once at start; let it pass so only the 60 s tick is left.
    sleep(Duration::from_millis(20)).await;

    let _ = client
        .ctx
        .bus()
        .publish(LanforgeEvent::Dns(DnsEvent::QueryResolved(Arc::new(
            QueryLogEntry {
                // Recent: the log store prunes lines older than a week.
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                src_ip: "192.168.1.20".parse().unwrap(),
                domain: Arc::from("example.org"),
                upstream_us: 0,
                qtype: DnsRecordType::A,
                result: QueryResult::Forwarded,
                cached: false,
                src_mac: None,
                answer: None,
                protocol: TransportProtocol::Udp,
                filter: None,
                coalesce_id: None,
                repeats: 1,
            },
        ))));
    // The query was answered before the admin opened the log.
    sleep(Duration::from_millis(50)).await;

    let res = client
        .handle_dns_query_log(None, None, None, None, None, false, None)
        .await;
    let Response::DnsQueryLog(log) = res else {
        panic!("{res:?}");
    };
    assert_eq!(log.total, 1);
    assert_eq!(&*log.entries[0].domain, "example.org");
}
