#![cfg(test)]

use crate::bus::{AdminChange, DeviceEvent, EventBus, LanforgeEvent};
use crate::context::LanforgeContext;
use crate::context::state::State;
use lanforge_types::device::Origin;
use lanforge_types::events::TimedEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn make_bus() -> Arc<EventBus> {
    Arc::new(EventBus::new())
}

#[tokio::test]
async fn new_device_publishes_discovered_and_updated() {
    let bus = make_bus();
    let mut rx = bus.subscribe();
    let ctx = LanforgeContext::new(bus, State::new(), None);

    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted { mac, ip, expires });

    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(
        events.iter().any(|e: &crate::bus::TimedEvent| matches!(
            e.event,
            LanforgeEvent::Device(DeviceEvent::Discovered { .. })
        )),
        "Deve publicar DeviceDiscovered para device novo"
    );
    assert!(
        events.iter().any(|e: &crate::bus::TimedEvent| matches!(
            e.event,
            LanforgeEvent::Device(DeviceEvent::NetworkUpdate { .. })
        )),
        "Deve publicar DeviceUpdated"
    );
}

#[tokio::test]
async fn known_device_does_not_publish_discovered() {
    let bus = make_bus();
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.0.10".parse().unwrap(),
        expires,
    });

    let mut rx = bus.subscribe();

    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.0.11".parse().unwrap(),
        expires,
    });

    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(
        !events.iter().any(|e: &TimedEvent| matches!(
            e.event,
            LanforgeEvent::Device(DeviceEvent::Discovered { .. })
        )),
        "Device já conhecido não deve gerar DeviceDiscovered"
    );
}

#[tokio::test]
async fn ndp_seen_publishes_nothing() {
    let bus = make_bus();
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let mut rx = bus.subscribe();

    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv6Addr = "fe80::1".parse().unwrap();

    let _ = ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip,
        is_active: true,
    });

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
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let mut rx = bus.subscribe();

    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: CliHostUpdate {
            hostname: FieldUpdate::Set("cli-host".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        },
    });

    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(
        events.iter().any(|e| matches!(
            &e.event,
            LanforgeEvent::Device(DeviceEvent::AdminUpdate {
                change,
                ..
            }) if matches!(**change, AdminChange::HostnameChanged { ref hostname } if hostname == "cli-host")
        )),
        "Deve publicar HostnameChanged"
    );

    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: CliHostUpdate {
            hostname: FieldUpdate::NoChange,
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::Set("1.2.3.4".parse().unwrap()),
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        },
    });

    let mut events = vec![];
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(
        events.iter().any(|e| matches!(
            &e.event,
            LanforgeEvent::Device(DeviceEvent::AdminUpdate {
                change,
                ..
            }) if matches!(**change, AdminChange::V4StaticChanged { ip: Some(ref ip) } if *ip == "1.2.3.4".parse::<Ipv4Addr>().unwrap())
        )),
        "Deve publicar V4StaticChanged"
    );
}
