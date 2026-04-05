#![cfg(test)]

use lanforge_core::bus::{EventBus, ManagedTable};
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::Origin;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::{DeviceUpdate, FieldUpdate};
use std::sync::Arc;

use crate::api::Response;
use crate::config::ApiConfig;
use crate::server::ClientContext;

fn make_dummy_config() -> ApiConfig {
    ApiConfig::dummy()
}

#[tokio::test]
async fn test_host_list_returns_static_and_cli_only() {
    let bus = Arc::new(EventBus::new());
    let table = Arc::new(ManagedTable::from_table(
        bus.clone(),
        lanforge_core::state::DeviceTable::new(),
        None,
    ));

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        LanforgeContext::init(bus.clone(), table.clone());
    }));

    let t = LanforgeContext::table();
    let cfg = Arc::new(make_dummy_config());

    let ctx = ClientContext {
        current_gua: None,
        uptime_secs: 10,
        last_scan_secs_ago: 5,
        cfg,
    };

    // 1. Add a CLI device
    let mac_cli = MacAddr::parse("00:00:00:00:00:01").unwrap();
    let _ = t.update(&DeviceUpdate::CliHostUpdated {
        mac: mac_cli,
        hostname: FieldUpdate::Set("cli-host".to_string()),
        v4_static: FieldUpdate::NoChange,
        v6_suffix: FieldUpdate::NoChange,
        origin: Origin::Cli,
    });

    // 2. Add a Dynamic device
    let mac_dyn = MacAddr::parse("00:00:00:00:00:02").unwrap();
    let _ = t.update(&DeviceUpdate::V4LeaseGranted {
        mac: mac_dyn,
        ip: "192.168.1.10".parse().unwrap(),
        expires: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
    });

    // 3. Add a TOML device
    let mac_toml = MacAddr::parse("00:00:00:00:00:03").unwrap();
    {
        let mut w = t.write();
        let mac = mac_toml;
        let hostname = "toml-host".to_string();
        let v4_ip = Some("192.168.1.5".parse().unwrap());
        let v6_suffix = None;
        w.add_static_device(mac, hostname, v4_ip, v6_suffix);
    }

    // 4. handle_hosts (called by HostList) should return ONLY CLI and TOML
    let resp = ctx.handle_hosts().await;
    if let Response::Hosts(d) = resp {
        assert_eq!(
            d.hosts.len(),
            2,
            "Should return ONLY CLI and TOML devices, NOT dynamic ones"
        );
        assert!(
            d.hosts
                .iter()
                .any(|dev| dev.mac == mac_cli.to_string() && dev.origin == "cli")
        );
        assert!(
            d.hosts
                .iter()
                .any(|dev| dev.mac == mac_toml.to_string() && dev.origin == "toml")
        );
        // Dynamic host should not be in d.hosts
        assert!(!d.hosts.iter().any(|dev| dev.mac == mac_dyn.to_string()));
    } else {
        panic!("Expected Response::Hosts, got {:?}", resp);
    }

    // 5. handle_devices (called by Devices) should still return all 3
    let resp = ctx.handle_devices(None).await;
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
    let bus = Arc::new(EventBus::new());
    let table = Arc::new(ManagedTable::from_table(
        bus.clone(),
        lanforge_core::state::DeviceTable::new(),
        None,
    ));

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        LanforgeContext::init(bus.clone(), table.clone());
    }));

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
    };

    let resp = ctx.handle_status().await;
    if let Response::Status(s) = resp {
        assert_eq!(s.network.gua, Some(gua));
        assert_eq!(s.network.ula, Some(ula));
        assert_eq!(s.uptime_secs, 100);
    } else {
        panic!("Expected Response::Status, got {:?}", resp);
    }
}
