use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use lanforge_core::{
    identifiers::MacAddr,
    ndp::NeighborEvent,
    state::DeviceUpdate,
    utils::{ip_matches_prefix, mac_from_eui64_link_local},
};
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::{
    AddressFamily, RouteNetlinkMessage,
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourHeader, NeighbourMessage, NeighbourState,
    },
};

use crate::ndp::utils::{extract_neigh_info, get_ipv4_subnet_iterable, parse_neighbor_msg};

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
        attributes.push(NeighbourAttribute::LinkLocalAddress(m.to_vec()));
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
    if let NeighborEvent::Added { ifindex, .. } = event {
        assert_eq!(ifindex, 2);
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
    // MAC ausente
    let msg = mock_neigh_msg(NeighbourState::Reachable, ip, None, false);
    assert!(extract_neigh_info(&msg).is_none());
}

// --- NeighborEvent::to_device_update ---

#[test]
fn to_device_update_gua_becomes_slaac_observed() {
    let gua_prefix: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
    let slaac_ip: Ipv6Addr = "fd97:f00d:cafe:3731::abcd".parse().unwrap();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let event = NeighborEvent::Added {
        ip: slaac_ip.into(),
        mac,
        ifindex: 2,
    };
    let update = event.to_device_update(Some(&gua_prefix), None);

    assert!(
        matches!(update, DeviceUpdate::SlaacObserved { addr, .. } if addr == slaac_ip),
        "IP in GUA prefix should become SlaacObserved"
    );
}

#[test]
fn to_device_update_link_local_becomes_ndp_seen() {
    let gua_prefix: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let event = NeighborEvent::Added {
        ip: link_local.into(),
        mac,
        ifindex: 2,
    };
    let update = event.to_device_update(Some(&gua_prefix), None);

    assert!(
        matches!(update, DeviceUpdate::NdpSeen { .. }),
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
    };
    // No prefix configured — never assume SLAAC
    let update = event.to_device_update(None, None);

    assert!(matches!(update, DeviceUpdate::NdpSeen { .. }));
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

    // 1. Mensagem válida (Reachable)
    let mut msg = NeighbourMessage::default();
    msg.header.state = NeighbourState::Reachable;
    msg.header.family = AddressFamily::Inet6;
    msg.attributes = vec![
        NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip)),
        NeighbourAttribute::LinkLocalAddress(mac.to_vec()),
    ];
    let event = parse_neighbor_msg(msg).expect("deve parsear");
    assert!(matches!(event, NeighborEvent::Added { .. }));

    // 2. Mensagem inválida (Failed)
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

#[test]
fn test_ipv4_subnet_iterable_24() {
    let ip: Ipv4Addr = "192.168.1.100".parse().unwrap();
    let mut range = get_ipv4_subnet_iterable(ip, 24);

    assert_eq!(
        range.next(),
        Some("192.168.1.1".parse::<Ipv4Addr>().unwrap())
    );
    assert_eq!(
        range.last(),
        Some("192.168.1.254".parse::<Ipv4Addr>().unwrap())
    );
}

#[test]
fn test_ipv4_subnet_iterable_30() {
    let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let mut range = get_ipv4_subnet_iterable(ip, 30);

    // /30 has 4 addresses: .0 (net), .1, .2, .3 (broadcast)
    // Usable: .1, .2
    assert_eq!(range.next(), Some("10.0.0.1".parse::<Ipv4Addr>().unwrap()));
    assert_eq!(range.next(), Some("10.0.0.2".parse::<Ipv4Addr>().unwrap()));
    assert_eq!(range.next(), None);
}
