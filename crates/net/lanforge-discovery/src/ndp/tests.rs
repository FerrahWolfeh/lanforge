use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use lanforge_core::bus::{DeviceEvent, EventBus, LanforgeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::utils::{ip_matches_prefix, mac_from_eui64_link_local};
use lanforge_types::{identifiers::MacAddr, network::NeighborEvent, update::DeviceUpdate};
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::{
    AddressFamily, RouteNetlinkMessage,
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourHeader, NeighbourMessage, NeighbourState,
    },
};

use crate::ndp::config::MonitorConfig;
use crate::ndp::utils::{extract_neigh_info, parse_neighbor_msg};
use crate::ndp::{DiscoveryService, IfNameCache};

fn create_test_discovery_service(
    ctx: LanforgeContext,
    target_ifindexes: Vec<u32>,
) -> DiscoveryService {
    let (conn, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(conn);
    let (_tx, messages) = tokio::sync::broadcast::channel(16);
    let cfg = MonitorConfig {
        enabled: true,
        ping_enabled: false,
        ping_interval_secs: 60,
        batch_interval_ms: 50,
        ..Default::default()
    };
    DiscoveryService::new(cfg, handle, messages, target_ifindexes, ctx)
}

fn is_relevant_neigh_event(msg: &NetlinkMessage<RouteNetlinkMessage>, target_prefix: &str) -> bool {
    match &msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(neigh)) => {
            if neigh.header.state == NeighbourState::Incomplete {
                return false;
            }
            neigh_matches_prefix(neigh, target_prefix)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(neigh)) => {
            neigh_matches_prefix(neigh, target_prefix)
        }
        _ => false,
    }
}

fn neigh_matches_prefix(neigh: &NeighbourMessage, target_prefix: &str) -> bool {
    neigh.attributes.iter().any(|attr| {
        matches!(
            attr,
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip))
            if ip.to_string().starts_with(target_prefix)
        )
    })
}

fn mock_neigh_msg(
    state: NeighbourState,
    ip: IpAddr,
    mac: Option<[u8; 6]>,
    is_delete: bool,
) -> NetlinkMessage<RouteNetlinkMessage> {
    let addr = match ip {
        IpAddr::V6(a) => NeighbourAddress::Inet6(a),
        IpAddr::V4(a) => NeighbourAddress::Inet(a),
    };
    let mut attributes = vec![NeighbourAttribute::Destination(addr)];
    if let Some(m) = mac {
        attributes.push(NeighbourAttribute::LinkLayerAddress(m.to_vec()));
    }

    let header = NeighbourHeader {
        family: AddressFamily::Inet6,
        ifindex: 2,
        state,
        ..Default::default()
    };

    let mut neigh = NeighbourMessage::default();
    neigh.header = header;
    neigh.attributes = attributes;

    let payload = if is_delete {
        RouteNetlinkMessage::DelNeighbour(neigh)
    } else {
        RouteNetlinkMessage::NewNeighbour(neigh)
    };

    NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(payload),
    )
}

// --- extract_neigh_info ---

#[test]
fn extract_neigh_info_returns_typed_event() {
    let ip: IpAddr = "fe80::1".parse().unwrap();
    let mac_bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let msg = mock_neigh_msg(NeighbourState::Reachable, ip, Some(mac_bytes), false);
    let event = extract_neigh_info(&msg).expect("should extract event");

    assert_eq!(*event.ip(), ip);
    assert_eq!(event.mac(), Some(MacAddr(mac_bytes)));
    if let NeighborEvent::Added {
        ifindex, is_active, ..
    } = event
    {
        assert_eq!(ifindex, 2);
        assert!(is_active, "Reachable should be active");
    } else {
        panic!("expected NeighborEvent::Added");
    }
}

#[test]
fn extract_neigh_info_handles_stale_as_inactive() {
    let ip: IpAddr = "fe80::1".parse().unwrap();
    let mac_bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let msg = mock_neigh_msg(NeighbourState::Stale, ip, Some(mac_bytes), false);
    let event = extract_neigh_info(&msg).expect("should extract event");

    if let NeighborEvent::Added { is_active, .. } = event {
        assert!(!is_active, "Stale should be inactive");
    } else {
        panic!("expected NeighborEvent::Added");
    }
}

#[test]
fn extract_neigh_info_ignores_incomplete() {
    let ip: IpAddr = "fe80::1".parse().unwrap();
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let msg_incomplete = mock_neigh_msg(NeighbourState::Incomplete, ip, Some(mac), false);

    assert!(extract_neigh_info(&msg_incomplete).is_none());
}

#[test]
fn extract_neigh_info_handles_failed() {
    let ip: IpAddr = "fe80::1".parse().unwrap();
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let msg_failed = mock_neigh_msg(NeighbourState::Failed, ip, Some(mac), false);
    let event = extract_neigh_info(&msg_failed).expect("should extract Failed");
    assert!(matches!(event, NeighborEvent::Failed { .. }));
}

#[test]
fn extract_neigh_info_requires_both_ip_and_mac() {
    let ip: IpAddr = "fe80::1".parse().unwrap();
    // Missing MAC
    let msg = mock_neigh_msg(NeighbourState::Reachable, ip, None, false);
    assert!(extract_neigh_info(&msg).is_none());
}

// --- NeighborEvent::to_device_update ---

#[test]
fn to_device_update_gua_becomes_slaac_observed() {
    let gua_prefix =
        lanforge_types::network::Ipv6Prefix::from_addr("fd97:f00d:cafe:3731::".parse().unwrap());
    let slaac_ip: Ipv6Addr = "fd97:f00d:cafe:3731::abcd".parse().unwrap();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let event = NeighborEvent::Added {
        ip: slaac_ip.into(),
        mac,
        ifindex: 2,
        is_active: true,
    };
    let update = event.to_device_update(Some(&gua_prefix), None);

    assert!(
        matches!(update, Some(DeviceUpdate::SlaacObserved { addr, .. }) if addr == slaac_ip),
        "IP in GUA prefix should become SlaacObserved"
    );
}

#[test]
fn to_device_update_link_local_becomes_ndp_seen() {
    let gua_prefix =
        lanforge_types::network::Ipv6Prefix::from_addr("fd97:f00d:cafe:3731::".parse().unwrap());
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let event = NeighborEvent::Added {
        ip: link_local.into(),
        mac,
        ifindex: 2,
        is_active: true,
    };
    let update = event.to_device_update(Some(&gua_prefix), None);

    assert!(
        matches!(update, Some(DeviceUpdate::NdpSeen { .. })),
        "Link-local should become NdpSeen"
    );
}

#[test]
fn to_device_update_no_prefix_always_ndp_seen() {
    let ip: Ipv6Addr = "fd97:f00d:cafe:3731::1".parse().unwrap();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let event = NeighborEvent::Added {
        ip: ip.into(),
        mac,
        ifindex: 2,
        is_active: true,
    };
    // No prefix configured — never assume SLAAC
    let update = event.to_device_update(None, None);

    assert!(matches!(update, Some(DeviceUpdate::NdpSeen { .. })));
}

// --- is_relevant_neigh_event ---

#[test]
fn is_relevant_event_matches_prefix_and_state() {
    let target_prefix = "fd97:f00d:cafe:3731::";
    let valid_ip: Ipv6Addr = "fd97:f00d:cafe:3731::1234".parse().unwrap();
    let invalid_ip: Ipv6Addr = "2001:db8::1234".parse().unwrap();

    let msg_valid = mock_neigh_msg(NeighbourState::Reachable, valid_ip.into(), None, false);
    let msg_invalid = mock_neigh_msg(NeighbourState::Reachable, invalid_ip.into(), None, false);
    let msg_incomplete = mock_neigh_msg(NeighbourState::Incomplete, valid_ip.into(), None, false);

    assert!(is_relevant_neigh_event(&msg_valid, target_prefix));
    assert!(!is_relevant_neigh_event(&msg_invalid, target_prefix));
    assert!(!is_relevant_neigh_event(&msg_incomplete, target_prefix));
}

// --- EUI-64 ---

#[test]
fn mac_from_eui64_valid() {
    // MAC: 3c:0a:7a:d8:11:78  →  U/L bit inverted: 0x3C ^ 0x02 = 0x3E
    let ip: Ipv6Addr = "fe80::3e0a:7aff:fed8:1178".parse().unwrap();
    let mac = mac_from_eui64_link_local(&ip);
    assert_eq!(mac, Some(MacAddr([0x3c, 0x0a, 0x7a, 0xd8, 0x11, 0x78])));
}

#[test]
fn mac_from_eui64_ignores_non_link_local() {
    let ip: Ipv6Addr = "2001:db8::3e0a:7aff:fed8:1178".parse().unwrap();
    assert_eq!(mac_from_eui64_link_local(&ip), None);
}

#[test]
fn mac_from_eui64_ignores_privacy_extensions() {
    let ip: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
    assert_eq!(mac_from_eui64_link_local(&ip), None);
}

// --- ip_matches_prefix ---

#[test]
fn ip_matches_prefix_same_64() {
    let prefix: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
    let inside: Ipv6Addr = "fd97:f00d:cafe:3731::dead:beef".parse().unwrap();
    let outside: Ipv6Addr = "fd97:f00d:cafe:3732::1".parse().unwrap();

    assert!(ip_matches_prefix(&inside, &prefix));
    assert!(!ip_matches_prefix(&outside, &prefix));
}

#[test]
fn parse_neighbor_msg_only_active() {
    let ip: Ipv6Addr = "fe80::1".parse().unwrap();
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    // 1. Valid message (Reachable)
    let mut msg = NeighbourMessage::default();
    msg.header.state = NeighbourState::Reachable;
    msg.header.family = AddressFamily::Inet6;
    msg.attributes = vec![
        NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip)),
        NeighbourAttribute::LinkLayerAddress(mac.to_vec()),
    ];
    let event = parse_neighbor_msg(msg).expect("should parse");
    if let NeighborEvent::Added { is_active, .. } = event {
        assert!(is_active);
    } else {
        panic!("expected Added");
    }

    // 2. Invalid message (Failed)
    let mut msg_fail = NeighbourMessage::default();
    msg_fail.header.state = NeighbourState::Failed;
    assert!(parse_neighbor_msg(msg_fail).is_none());
}

#[test]
fn extract_neigh_info_handles_delete() {
    let ip: IpAddr = "fe80::1".parse().unwrap();
    // In RTM_DELNEIGH, MAC may be absent
    let msg = mock_neigh_msg(NeighbourState::Failed, ip, None, true);
    let event = extract_neigh_info(&msg).expect("should extract delete");

    assert_eq!(event, NeighborEvent::Deleted { ip, ifindex: 2 });
}

#[tokio::test]
async fn test_discovery_flush_neighbor_batch() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus, State::new(), None);
    let mut dev_rx = ctx.bus().subscribe_device();

    let service = create_test_discovery_service(ctx.clone(), vec![2]);

    let batch = vec![
        (
            MacAddr([1, 2, 3, 4, 5, 1]),
            "192.168.1.101".parse().unwrap(),
            true,
        ),
        (
            MacAddr([1, 2, 3, 4, 5, 2]),
            "192.168.1.102".parse().unwrap(),
            true,
        ),
        (
            MacAddr([1, 2, 3, 4, 5, 3]),
            "192.168.1.103".parse().unwrap(),
            true,
        ),
    ];

    service.flush_neighbor_batch(batch);

    // Verify all 3 devices are in state
    assert_eq!(ctx.with_state(|s| s.devices.len()), 3);

    // Verify summary event published
    let mut found_summary = false;
    while let Ok(timed_event) = dev_rx.try_recv() {
        if let LanforgeEvent::Device(DeviceEvent::NeighborBatchSummary { total, new, .. }) =
            timed_event.event
        {
            assert_eq!(total, 3);
            assert_eq!(new, 3);
            found_summary = true;
            break;
        }
    }
    assert!(
        found_summary,
        "NeighborBatchSummary must be published on bus"
    );
}

#[tokio::test]
async fn test_discovery_process_neighbor_event_batch_accumulation() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus, State::new(), None);
    let service = create_test_discovery_service(ctx.clone(), vec![2]);

    let mut ifname_cache = IfNameCache::new();
    let mut pending_batch = Vec::new();

    // 1. Add 49 neighbor events: should NOT flush
    for i in 1..=49 {
        let event = NeighborEvent::Added {
            mac: MacAddr([0xAA, 0xBB, 0x00, 0x00, 0x00, i]),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)),
            is_active: true,
            ifindex: 2,
        };
        service.process_neighbor_event(
            &event,
            &mut ifname_cache,
            &ctx,
            &mut pending_batch,
            None,
            None,
        );
    }

    assert_eq!(
        pending_batch.len(),
        49,
        "Batch should buffer 49 events without flushing"
    );
    assert_eq!(
        ctx.with_state(|s| s.devices.len()),
        0,
        "No devices should be committed yet"
    );

    // 2. Add the 50th event: must trigger automatic flush
    let event50 = NeighborEvent::Added {
        mac: MacAddr([0xAA, 0xBB, 0x00, 0x00, 0x00, 50]),
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        is_active: true,
        ifindex: 2,
    };
    service.process_neighbor_event(
        &event50,
        &mut ifname_cache,
        &ctx,
        &mut pending_batch,
        None,
        None,
    );

    assert_eq!(
        pending_batch.len(),
        0,
        "Batch must be emptied upon hitting threshold of 50"
    );
    assert_eq!(
        ctx.with_state(|s| s.devices.len()),
        50,
        "All 50 devices must now be committed to state"
    );
}

#[tokio::test]
async fn test_discovery_process_neighbor_event_flushes_pending_on_non_added() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus, State::new(), None);
    let service = create_test_discovery_service(ctx.clone(), vec![2]);

    let mut ifname_cache = IfNameCache::new();
    let mut pending_batch = Vec::new();

    // Buffer 5 events
    for i in 1..=5 {
        let event = NeighborEvent::Added {
            mac: MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, i]),
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
            is_active: true,
            ifindex: 2,
        };
        service.process_neighbor_event(
            &event,
            &mut ifname_cache,
            &ctx,
            &mut pending_batch,
            None,
            None,
        );
    }
    assert_eq!(pending_batch.len(), 5);
    assert_eq!(ctx.with_state(|s| s.devices.len()), 0);

    // Non-Added event (e.g. Failed) must flush pending batch before processing
    let non_added = NeighborEvent::Failed {
        ip: "10.0.0.99".parse().unwrap(),
        ifindex: 2,
    };
    service.process_neighbor_event(
        &non_added,
        &mut ifname_cache,
        &ctx,
        &mut pending_batch,
        None,
        None,
    );

    assert_eq!(
        pending_batch.len(),
        0,
        "Pending batch must be flushed on non-Added event"
    );
    assert_eq!(
        ctx.with_state(|s| s.devices.len()),
        5,
        "The 5 buffered devices must be committed"
    );
}

#[test]
fn test_ifname_cache() {
    let mut cache = IfNameCache::new();
    assert!(cache.cache.is_empty());

    // Insert dummy interface mapping
    cache.cache.insert(42, "eth42".to_string());
    assert_eq!(cache.get(42), Some("eth42"));

    // Cache lookup should succeed without kernel call
    assert_eq!(cache.get(42), Some("eth42"));

    // Non-existent interface index returns None
    assert_eq!(cache.get(999_999), None);
}
