use lanforge_api::api::{
    AllowlistEntry, DnsUpstreamConfig, HostConfigEntry, Response, SystemConfigExport,
};
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::DnsRecordType;
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockUrlKind, BlockingMode, RewriteAnswer, RewriteRule,
};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

async fn init_test_context() -> ClientContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open("sqlite::memory:").await.unwrap());
    let ctx = LanforgeContext::new(bus, table, None);

    ClientContext {
        current_gua: None,
        uptime_secs: 100,
        last_scan_secs_ago: 5,
        ctx,
        db,
        log_db,
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
async fn test_dispatch_topology() {
    let client_ctx = init_test_context().await;
    let res = client_ctx.handle_topology().await;
    assert!(matches!(res, Response::Topology(_)));
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
        }],
        dns_rewrites: vec![RewriteRule {
            id: None,
            domain: "import.lan".to_string(),
            rtype: DnsRecordType::A,
            answer: RewriteAnswer::A("192.168.10.1".parse().unwrap()),
        }],
        dns_upstreams: vec![DnsUpstreamConfig {
            addr: "9.9.9.9:53".parse().unwrap(),
            protocol: UpstreamProtocol::Udp,
            domain: Some("quad9".to_string()),
        }],
        dns_adblock_config: AdblockDbConfig {
            enabled: true,
            blocking_mode: BlockingMode::NullIp,
            blocking_ip_v4: Some("0.0.0.0".parse().unwrap()),
            blocking_ip_v6: Some("::".parse().unwrap()),
            refresh_hours: 12,
            refresh_at_night: true,
        },
        dns_adblock_urls: vec![AdblockUrlEntry {
            id: None,
            url: "https://example.com/adblock.hosts".to_string(),
            kind: AdblockUrlKind::Blocklist,
        }],
        dns_allowlist: vec![AllowlistEntry {
            id: 0,
            domain: "allowed-import.lan".to_string(),
        }],
        overwrite: true,
    };

    // 3. Import the configuration
    let import_res = client_ctx.handle_system_config_import(import_cfg).await;
    if let Response::Error { error } = &import_res {
        panic!("Import failed with error: {error}");
    }
    assert!(matches!(import_res, Response::Success(_)));

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
        assert_eq!(cfg.dns_adblock_config.refresh_hours, 12);

        assert_eq!(cfg.dns_adblock_urls.len(), 1);
        assert_eq!(
            cfg.dns_adblock_urls[0].url,
            "https://example.com/adblock.hosts"
        );
        assert_eq!(cfg.dns_adblock_urls[0].kind, AdblockUrlKind::Blocklist);

        assert_eq!(cfg.dns_allowlist.len(), 1);
        assert_eq!(cfg.dns_allowlist[0].domain, "allowed-import.lan");
    } else {
        panic!("Expected Response::SystemConfig");
    }
}
