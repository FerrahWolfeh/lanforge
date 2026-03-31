#![cfg(test)]

use crate::bus::{DeviceChange, EventBus, LanforgeEvent, ManagedTable};
use crate::device::Origin;
use crate::identifiers::MacAddr;
use crate::state::update::{DeviceUpdate, FieldUpdate};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

fn make_bus() -> Arc<EventBus> {
    Arc::new(EventBus::new())
}

#[tokio::test]
async fn new_device_publishes_discovered_and_updated() {
    let bus = make_bus();
    let mut rx = bus.subscribe();
    let table = ManagedTable::new(bus);

    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
    let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

    let _ = table.update(&DeviceUpdate::V4LeaseGranted { mac, ip, expires });

    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(
        events
            .iter()
            .any(|e| matches!(e, LanforgeEvent::DeviceDiscovered { .. })),
        "Deve publicar DeviceDiscovered para device novo"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, LanforgeEvent::DeviceUpdated { .. })),
        "Deve publicar DeviceUpdated"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, LanforgeEvent::DeviceTableDirty)),
        "Deve publicar DeviceTableDirty"
    );
}

#[tokio::test]
async fn known_device_does_not_publish_discovered() {
    let bus = make_bus();
    let table = ManagedTable::new(bus.clone());
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

    let _ = table.update(&DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.0.10".parse().unwrap(),
        expires,
    });

    let mut rx = bus.subscribe();

    let _ = table.update(&DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.0.11".parse().unwrap(),
        expires,
    });

    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(
        !events
            .iter()
            .any(|e| matches!(e, LanforgeEvent::DeviceDiscovered { .. })),
        "Device já conhecido não deve gerar DeviceDiscovered"
    );
}

#[tokio::test]
async fn ndp_seen_publishes_nothing() {
    let bus = make_bus();
    let table = ManagedTable::new(bus.clone());
    let mut rx = bus.subscribe();

    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: std::net::Ipv6Addr = "fe80::1".parse().unwrap();

    let _ = table.update(&DeviceUpdate::NdpSeen { mac, ip });

    let count = {
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        n
    };
    assert_eq!(count, 0, "NdpSeen não deve publicar eventos");
}

#[tokio::test]
async fn cli_host_update_publishes_events() {
    let bus = make_bus();
    let table = ManagedTable::new(bus.clone());
    let mut rx = bus.subscribe();

    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let _ = table.update(&DeviceUpdate::CliHostUpdated {
        mac,
        hostname: FieldUpdate::Set("cli-host".to_string()),
        v4_static: FieldUpdate::NoChange,
        v6_suffix: FieldUpdate::NoChange,
        origin: Origin::Cli,
    });

    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(
        events.iter().any(|e| matches!(
            e,
            LanforgeEvent::DeviceUpdated {
                mac: _,
                change: DeviceChange::HostnameChanged { .. }
            }
        )),
        "Deve publicar HostnameChanged"
    );

    let _ = table.update(&DeviceUpdate::CliHostUpdated {
        mac,
        hostname: FieldUpdate::NoChange,
        v4_static: FieldUpdate::Set("1.2.3.4".parse().unwrap()),
        v6_suffix: FieldUpdate::NoChange,
        origin: Origin::Cli,
    });

    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(
        events.iter().any(|e| matches!(
            e,
            LanforgeEvent::DeviceUpdated {
                mac: _,
                change: DeviceChange::V4StaticChanged { .. }
            }
        )),
        "Deve publicar V4StaticChanged"
    );
}
