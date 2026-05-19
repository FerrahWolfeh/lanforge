#![cfg(test)]

use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::{CliHostUpdate, DeviceUpdate, FieldUpdate, MacAddr, Origin};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::api::Response;
use crate::config::ApiConfig;
use crate::server::ClientContext;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use std::sync::atomic::AtomicUsize;

fn make_dummy_config() -> ApiConfig {
    ApiConfig::dummy()
}

async fn init_test_context() -> (LanforgeContext, Arc<LanforgeDb>, Arc<LogDb>) {
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
    (LanforgeContext::new(bus, table, None), db, log_db)
}

#[tokio::test]
async fn test_host_list_returns_static_and_cli_only() {
    let (ctx_handle, db, log_db) = init_test_context().await;
    let cfg = Arc::new(make_dummy_config());

    let ctx = ClientContext {
        current_gua: None,
        uptime_secs: 10,
        last_scan_secs_ago: 5,
        cfg,
        ctx: ctx_handle.clone(),
        db,
        log_db,
        active_clients: Arc::new(AtomicUsize::new(0)),
    };

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
        ip: "192.168.1.10".parse().unwrap(),
        expires: SystemTime::now() + Duration::from_hours(1),
    });

    // 3. Add a Static device
    let mac_static = MacAddr::parse("00:00:00:00:00:03").unwrap();
    let _ = ctx_handle.apply(DeviceUpdate::CliHostUpdated {
        mac: mac_static,
        update: CliHostUpdate {
            duid: FieldUpdate::NoChange,
            hostname: FieldUpdate::Set("static-host".to_string()),
            v4_static: FieldUpdate::Set("192.168.1.5".parse().unwrap()),
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
                .any(|dev| dev.mac == mac_cli.to_string() && dev.origin == "cli")
        );
        assert!(
            d.hosts
                .iter()
                .any(|dev| dev.mac == mac_static.to_string() && dev.origin == "static")
        );
        // Dynamic host should not be in d.hosts
        assert!(!d.hosts.iter().any(|dev| dev.mac == mac_dyn.to_string()));
    } else {
        panic!("Expected Response::Hosts, got {resp:?}");
    }

    // 5. handle_devices (called by Devices) should still return all 3
    let resp = ctx.handle_devices(None, None, None, None).await;
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
    let (ctx_handle, db, log_db) = init_test_context().await;

    let gua = "2001:db8::1".to_string();
    let ula = "fd00::".to_string();
    let mut cfg = make_dummy_config();
    cfg.ula_prefix = Some(ula.clone());
    let cfg = Arc::new(cfg);

    let ctx = ClientContext {
        current_gua: Some(gua.clone()),
        uptime_secs: 100,
        last_scan_secs_ago: 10,
        cfg: cfg.clone(),
        ctx: ctx_handle,
        db,
        log_db,
        active_clients: Arc::new(AtomicUsize::new(0)),
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

#[tokio::test]
async fn test_dump_command_simulation() {
    use tokio::io::duplex;

    let (ctx_handle, db, log_db) = init_test_context().await;
    let cfg = Arc::new(make_dummy_config());

    // 1. Add a device to state
    let mac = MacAddr::parse("00:00:00:00:00:0a").unwrap();
    let _ = ctx_handle.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: CliHostUpdate {
            duid: FieldUpdate::NoChange,
            hostname: FieldUpdate::Set("dump-target".to_string()),
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        },
    });

    let ctx = ClientContext {
        current_gua: None,
        uptime_secs: 123,
        last_scan_secs_ago: 45,
        cfg,
        ctx: ctx_handle,
        db,
        log_db,
        active_clients: Arc::new(AtomicUsize::new(0)),
    };

    // 2. Create duplex stream
    let (client, server) = duplex(1024);

    // 3. Spawn server (handle_client)
    let server_handle = tokio::spawn(async move {
        crate::server::handle_client(server, ctx)
            .await
            .expect("handle_client failed");
    });

    // 4. Connect with RPC Client
    let mut client = crate::rpc::LanforgeRpcClient::new(client);

    // 5. Call context_dump
    let state = client
        .context_dump(false, false)
        .await
        .expect("RPC call failed");

    // 6. Verify response
    assert!(
        state.devices.contains_key(&mac),
        "Dumped state missing target device"
    );
    assert_eq!(
        state.devices.get(&mac).unwrap().hostname.name,
        "dump-target",
        "Hostname mismatch in dumped state"
    );

    // 7. Cleanup (closing connection should terminate handle_client)
    drop(client);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_granular_querying() {
    let (ctx_handle, db, log_db) = init_test_context().await;
    let cfg = Arc::new(make_dummy_config());

    // Add a device
    let mac = MacAddr::parse("00:00:00:00:00:01").unwrap();
    let _ = ctx_handle.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: CliHostUpdate {
            duid: FieldUpdate::NoChange,
            hostname: FieldUpdate::Set("host1".to_string()),
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        },
    });

    // Add an orphan
    let ip_v6 = "2001:db8::dead:beef".parse().unwrap();
    let _ = ctx_handle.apply(DeviceUpdate::V6LeaseGranted {
        mac: None,
        duid: "00:01:00:01:2d:65:6d:73".parse().unwrap(),
        iaid: 1,
        ip: ip_v6,
        expires: SystemTime::now() + Duration::from_hours(1),
    });

    let ctx = ClientContext {
        current_gua: None,
        uptime_secs: 10,
        last_scan_secs_ago: 5,
        cfg,
        ctx: ctx_handle,
        db,
        log_db,
        active_clients: Arc::new(AtomicUsize::new(0)),
    };

    // Test only_devices
    let resp = ctx.handle_context_dump(true, false).await;
    if let Response::ContextDump(state) = resp {
        assert!(!state.devices.is_empty());
        assert!(state.discovery.orphaned_v6.is_empty());
    } else {
        panic!("Expected ContextDump");
    }

    // Test only_orphans
    let resp = ctx.handle_context_dump(false, true).await;
    if let Response::ContextDump(state) = resp {
        assert!(state.devices.is_empty());
        assert!(!state.discovery.orphaned_v6.is_empty());
    } else {
        panic!("Expected ContextDump");
    }
}
