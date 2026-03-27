#![cfg(test)]

use std::sync::Arc;

use lanforge_core::bus::{EventBus, ManagedTable};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::DeviceUpdate;

use crate::config::{Config, DhcpV4Cfg, DhcpV6Cfg, DnsCfg, RaCfg};
use crate::control::api::{Interfaces, Response};

use super::server::ClientContext;

fn make_dummy_config() -> Config {
    Config {
        command: crate::config::Command::Run { only: None },
        iface_lan: "eth0".to_string(),
        target_prefix: "fd00::/64".to_string(),
        leases_db: "/tmp/leases.db".to_string(),
        debounce_secs: 5,
        fallback_mins: 60,
        control_socket: "/tmp/lanforge.sock".to_string(),
        ra_enabled: true,
        ra_toml: RaCfg::default(),
        dhcpv4_enabled: true,
        dhcpv4_toml: DhcpV4Cfg::default(),
        dhcpv6_enabled: true,
        dhcpv6_toml: DhcpV6Cfg::default(),
        dns_enabled: true,
        dns_toml: DnsCfg::default(),
        devices: Vec::new(),
    }
}

#[tokio::test]
async fn test_host_list_returns_static_and_cli_only() {
    let bus = Arc::new(EventBus::new());
    let table = Arc::new(ManagedTable::new(bus.clone()));
    let cfg = Arc::new(make_dummy_config());
    let ifaces = Interfaces {
        lan: "eth0".to_string(),
    };

    let ctx = ClientContext {
        ifaces,
        table: table.clone(),
        current_gua: None,
        bus: bus.clone(),
        uptime_secs: 10,
        last_scan_secs_ago: 5,
        cfg,
    };

    // 1. Add a CLI device
    let mac_cli = MacAddr::parse("00:00:00:00:00:01").unwrap();
    table
        .update(DeviceUpdate::CliHostUpdated {
            mac: mac_cli,
            hostname: Some(Some("cli-host".to_string())),
            v4_static: None,
            v6_suffix: None,
        })
        .await;

    // 2. Add a Dynamic device
    let mac_dyn = MacAddr::parse("00:00:00:00:00:02").unwrap();
    table
        .update(DeviceUpdate::V4LeaseGranted {
            mac: mac_dyn,
            ip: "192.168.1.10".parse().unwrap(),
            expires: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        })
        .await;

    // 3. Add a TOML device
    let mac_toml = MacAddr::parse("00:00:00:00:00:03").unwrap();
    {
        let mut w = table.write();
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
