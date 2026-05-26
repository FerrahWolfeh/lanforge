use lanforge_api::api::Response;
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::Ipv6Prefix;
use lanforge_types::system::SystemStatus;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, SystemTime};

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
        uptime_secs: 10,
        last_scan_secs_ago: 5,
        ctx,
        db,
        log_db,
        active_clients: Arc::new(AtomicUsize::new(0)),
    }
}

#[tokio::test]
async fn test_host_list_returns_static_and_cli_only() {
    let mut ctx = init_test_context().await;
    ctx.uptime_secs = 10;
    ctx.last_scan_secs_ago = 5;
    let ctx_handle = ctx.ctx.clone();

    // 1. Add a CLI device
    let mac_cli = MacAddr::parse("00:00:00:00:00:01").unwrap();
    let _ = ctx_handle.apply(DeviceUpdate::CliHostUpdated {
        mac: mac_cli,
        update: CliHostUpdate {
            duid: FieldUpdate::NoChange,
            hostname: FieldUpdate::Set("cli-host".to_string()),
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        },
    });

    // 2. Add a Dynamic device
    let mac_dyn = MacAddr::parse("00:00:00:00:00:02").unwrap();
    let _ = ctx_handle.apply(DeviceUpdate::V4LeaseGranted {
        mac: mac_dyn,
        ip: "192.168.1.10".parse::<Ipv4Addr>().unwrap(),
        expires: SystemTime::now() + Duration::from_secs(3600),
    });

    // 3. Add a Static device
    let mac_static = MacAddr::parse("00:00:00:00:00:03").unwrap();
    let _ = ctx_handle.apply(DeviceUpdate::CliHostUpdated {
        mac: mac_static,
        update: CliHostUpdate {
            duid: FieldUpdate::NoChange,
            hostname: FieldUpdate::Set("static-host".to_string()),
            v4_static: FieldUpdate::Set("192.168.1.5".parse::<Ipv4Addr>().unwrap()),
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        },
    });

    // 4. handle_hosts (called by HostList) should return ONLY CLI and Static
    let resp = ctx.handle_hosts().await;
    if let Response::Hosts(d) = resp {
        assert_eq!(
            d.hosts.len(),
            2,
            "Should return ONLY CLI and Static devices, NOT dynamic ones"
        );
        assert!(
            d.hosts
                .iter()
                .any(|dev| dev.mac == mac_cli && dev.origin == Origin::Static)
        );
        assert!(
            d.hosts
                .iter()
                .any(|dev| dev.mac == mac_static && dev.origin == Origin::Static)
        );
        // Dynamic host should not be in d.hosts
        assert!(!d.hosts.iter().any(|dev| dev.mac == mac_dyn));
    } else {
        panic!("Expected Response::Hosts, got {resp:?}");
    }

    // 5. handle_devices (called by Devices) should still return all 3
    let resp = ctx.handle_devices(None, None, None, None, None, None).await;
    if let Response::Devices(d) = resp {
        assert_eq!(
            d.devices.len(),
            3,
            "Devices list should still show everything"
        );
    }
}

#[tokio::test]
async fn test_api_status_reports_gua_and_ula() {
    let ctx_handle = init_test_context().await;
    let gua = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
    let ula = "fd00::".parse::<Ipv6Addr>().unwrap();

    let status = SystemStatus {
        ula_prefix: Some(Ipv6Prefix::from(ula)),
        ..Default::default()
    };
    ctx_handle.ctx.set_status(status);

    let ctx = ClientContext {
        current_gua: Some(gua),
        uptime_secs: 100,
        last_scan_secs_ago: 10,
        ctx: ctx_handle.ctx,
        db: ctx_handle.db,
        log_db: ctx_handle.log_db,
        active_clients: ctx_handle.active_clients,
    };

    let resp = ctx.handle_status().await;
    if let Response::Status(s) = resp {
        assert_eq!(s.network.gua, Some(gua));
        assert_eq!(s.network.ula, Some(ula));
        assert_eq!(s.uptime_secs, 100);
    } else {
        panic!("Expected Response::Status, got {resp:?}");
    }
}
