#![cfg(test)]

use crate::bus::{
    AdminChange, DeviceEvent, DnsEvent, EventBus, FirewallEvent, LanforgeEvent, NetworkEvent,
    PppoeEvent, StorageEvent, SystemEvent, TimedEvent, TrafficEvent,
};
use crate::context::LanforgeContext;
use crate::context::state::State;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::firewall::L4Protocol;
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
        events.iter().any(|e: &TimedEvent| matches!(
            e.event,
            LanforgeEvent::Device(DeviceEvent::Discovered { .. })
        )),
        "Must publish DeviceDiscovered for a newly observed device"
    );
    assert!(
        events.iter().any(|e: &TimedEvent| matches!(
            e.event,
            LanforgeEvent::Device(DeviceEvent::NetworkUpdate { .. })
        )),
        "Must publish DeviceUpdated/NetworkUpdate"
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
        "Already known device must not generate DeviceDiscovered"
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
    assert_eq!(count, 0, "NdpSeen must not publish events");
}

#[tokio::test]
async fn cli_host_update_publishes_events() {
    let bus = make_bus();
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let mut rx = bus.subscribe();

    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::Set("cli-host".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
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
        "Must publish HostnameChanged"
    );

    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::NoChange,
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::Set("1.2.3.4".parse().unwrap()),
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
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
        "Must publish V4StaticChanged"
    );
}

#[tokio::test]
async fn topic_partitioning_isolates_unrelated_events() {
    let bus = make_bus();
    let mut dns_rx = bus.subscribe_dns();
    let mut net_rx = bus.subscribe_network();
    let mut global_rx = bus.subscribe();

    // 1. Publish a DNS event
    let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));

    // DNS and Global receive it
    assert!(matches!(
        dns_rx.try_recv().unwrap().event,
        LanforgeEvent::Dns(DnsEvent::CacheFlush)
    ));
    assert!(matches!(
        global_rx.try_recv().unwrap().event,
        LanforgeEvent::Dns(DnsEvent::CacheFlush)
    ));
    // Network should NOT receive it
    assert!(net_rx.try_recv().is_err());

    // 2. Publish a Network event
    let _ = bus.publish(LanforgeEvent::Network(NetworkEvent::InterfaceUpdated {
        ifindex: 2,
    }));

    // Network and Global receive it
    assert!(matches!(
        net_rx.try_recv().unwrap().event,
        LanforgeEvent::Network(NetworkEvent::InterfaceUpdated { ifindex: 2 })
    ));
    assert!(matches!(
        global_rx.try_recv().unwrap().event,
        LanforgeEvent::Network(NetworkEvent::InterfaceUpdated { ifindex: 2 })
    ));
    // DNS should NOT receive it
    assert!(dns_rx.try_recv().is_err());

    // 3. Publish System Shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

    // ALL topic channels receive shutdown immediately
    assert!(matches!(
        dns_rx.try_recv().unwrap().event,
        LanforgeEvent::System(SystemEvent::Shutdown)
    ));
    assert!(matches!(
        net_rx.try_recv().unwrap().event,
        LanforgeEvent::System(SystemEvent::Shutdown)
    ));
    assert!(matches!(
        global_rx.try_recv().unwrap().event,
        LanforgeEvent::System(SystemEvent::Shutdown)
    ));
}

#[tokio::test]
async fn topic_routing_matrix() {
    let bus = make_bus();
    let mut sys_rx = bus.subscribe_system();
    let mut net_rx = bus.subscribe_network();
    let mut dev_rx = bus.subscribe_device();
    let mut dns_rx = bus.subscribe_dns();
    let mut pppoe_rx = bus.subscribe_pppoe();
    let mut fw_rx = bus.subscribe_firewall();
    let mut trf_rx = bus.subscribe_traffic();
    let mut stg_rx = bus.subscribe_storage();

    // 1. ConfigRaChanged -> system and network
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigRaChanged));
    assert!(matches!(
        sys_rx.try_recv().unwrap().event,
        LanforgeEvent::System(SystemEvent::ConfigRaChanged)
    ));
    assert!(matches!(
        net_rx.try_recv().unwrap().event,
        LanforgeEvent::System(SystemEvent::ConfigRaChanged)
    ));
    assert!(dev_rx.try_recv().is_err());
    assert!(dns_rx.try_recv().is_err());

    // 2. ConfigDhcpV4Changed -> system and device
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed));
    assert!(matches!(
        sys_rx.try_recv().unwrap().event,
        LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed)
    ));
    assert!(matches!(
        dev_rx.try_recv().unwrap().event,
        LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed)
    ));
    assert!(net_rx.try_recv().is_err());
    assert!(dns_rx.try_recv().is_err());

    // 3. PPPoE SessionUp -> pppoe AND dns (for upstream resolver updates)
    let pppoe_details = lanforge_types::events::PppoeSessionUp {
        interface: "ppp0".to_string(),
        ac_mac: None,
        ac_name: None,
        session_id: 42,
        mru: 1492,
        ipv4: Some("100.64.0.1".parse().unwrap()),
        ipv4_peer: Some("100.64.0.254".parse().unwrap()),
        dns: vec!["1.1.1.1".parse().unwrap()],
        ipv6_link_local: true,
    };
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
        pppoe_details,
    ))));
    assert!(matches!(
        pppoe_rx.try_recv().unwrap().event,
        LanforgeEvent::Pppoe(PppoeEvent::SessionUp(_))
    ));
    assert!(matches!(
        dns_rx.try_recv().unwrap().event,
        LanforgeEvent::Pppoe(PppoeEvent::SessionUp(_))
    ));
    assert!(net_rx.try_recv().is_err());
    assert!(fw_rx.try_recv().is_err());

    // 4. FirewallEvent -> firewall only
    let _ = bus.publish(LanforgeEvent::Firewall(
        FirewallEvent::PortReleaseRequested {
            service: "test".to_string(),
            port: 8080,
            protocol: L4Protocol::Tcp,
        },
    ));
    assert!(matches!(
        fw_rx.try_recv().unwrap().event,
        LanforgeEvent::Firewall(FirewallEvent::PortReleaseRequested { .. })
    ));
    assert!(sys_rx.try_recv().is_err());
    assert!(net_rx.try_recv().is_err());

    // 5. TrafficEvent -> traffic only
    let _ = bus.publish(LanforgeEvent::Traffic(Box::new(
        TrafficEvent::RulesetChanged,
    )));
    assert!(
        matches!(trf_rx.try_recv().unwrap().event, LanforgeEvent::Traffic(t) if matches!(*t, TrafficEvent::RulesetChanged))
    );
    assert!(fw_rx.try_recv().is_err());
    assert!(sys_rx.try_recv().is_err());

    // 6. StorageEvent -> storage only
    let _ = bus.publish(LanforgeEvent::Storage(StorageEvent::DbLogClean));
    assert!(matches!(
        stg_rx.try_recv().unwrap().event,
        LanforgeEvent::Storage(StorageEvent::DbLogClean)
    ));
    assert!(sys_rx.try_recv().is_err());
    assert!(dev_rx.try_recv().is_err());
}

#[tokio::test]
async fn subscriber_lifecycle_and_zero_receiver_efficiency() {
    let bus = EventBus::new();

    // With 0 receivers, publish returns 0 receivers notified
    let sent = bus.publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
    assert_eq!(sent, 0);

    // Subscribe one global listener
    let mut rx = bus.subscribe();
    let sent = bus.publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
    assert_eq!(sent, 1);

    let event = rx.recv().await.unwrap();
    assert!(matches!(
        event.event,
        LanforgeEvent::Dns(DnsEvent::CacheFlush)
    ));

    drop(rx);
    // After dropping, count returns to 0
    let sent = bus.publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
    assert_eq!(sent, 0);
}
