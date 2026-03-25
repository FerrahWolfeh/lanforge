//! Wrapper do netlink para queries de vizinhos IPv6 e filtragem de eventos.
//!
//! Centraliza toda interação com o subsistema netlink do kernel.
//!
//! ## Fluxo de integração com o Manager
//!
//! ```text
//! kernel (RTM_NEWNEIGH)
//!     └─► extract_neigh_info()  →  Option<NeighborEvent>
//!                                          │
//!                                          ▼
//!                               NeighborEvent::to_device_update(prefix)
//!                                          │
//!                            ┌────────────┴────────────┐
//!                            ▼                          ▼
//!                    SlaacObserved              NdpSeen
//!                    (GUA no prefixo)           (link-local / outro)
//!                            │                          │
//!                            └────────────┬─────────────┘
//!                                         ▼
//!                               ManagedTable::update()
//! ```

use anyhow::Result;
use futures::stream::TryStreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
};
use rtnetlink::{Handle, IpVersion};
use std::net::Ipv6Addr;

use crate::device::MacAddr;
use crate::state::DeviceUpdate;

// ---------------------------------------------------------------------------
// NeighborEvent — struct tipada para eventos do kernel
// ---------------------------------------------------------------------------

/// Um evento de vizinho (IPv4 ou IPv6) observado pelo kernel (`RTM_NEWNEIGH`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighborEvent {
    Added {
        ip: std::net::IpAddr,
        mac: MacAddr,
        ifindex: u32,
    },
    Deleted {
        ip: std::net::IpAddr,
        ifindex: u32,
    },
}

impl NeighborEvent {
    pub fn ip(&self) -> &std::net::IpAddr {
        match self {
            NeighborEvent::Added { ip, .. } => ip,
            NeighborEvent::Deleted { ip, .. } => ip,
        }
    }

    pub fn mac(&self) -> Option<MacAddr> {
        match self {
            NeighborEvent::Added { mac, .. } => Some(*mac),
            NeighborEvent::Deleted { .. } => None,
        }
    }

    pub fn to_device_update(&self, gua_prefix: Option<&Ipv6Addr>) -> DeviceUpdate {
        match self {
            NeighborEvent::Added { ip, mac, .. } => match ip {
                std::net::IpAddr::V6(ip6) => {
                    let is_slaac = gua_prefix.is_some_and(|prefix| ip_matches_prefix(ip6, prefix));
                    if is_slaac {
                        DeviceUpdate::SlaacObserved {
                            mac: *mac,
                            addr: *ip6,
                        }
                    } else {
                        DeviceUpdate::NdpSeen {
                            mac: *mac,
                            ip: *ip6,
                        }
                    }
                }
                std::net::IpAddr::V4(ip4) => DeviceUpdate::ArpSeen {
                    mac: *mac,
                    ip: *ip4,
                },
            },
            NeighborEvent::Deleted { ip, .. } => DeviceUpdate::IpDeleted { ip: *ip },
        }
    }
}

/// Retorna true se `ip` pertence ao mesmo /64 que `prefix`.
fn ip_matches_prefix(ip: &Ipv6Addr, prefix: &Ipv6Addr) -> bool {
    let ip_segs = ip.segments();
    let prefix_segs = prefix.segments();
    // Compara os primeiros 4 segmentos (64 bits)
    ip_segs[..4] == prefix_segs[..4]
}

// ---------------------------------------------------------------------------
// Neighbour event filter (eventos do stream Netlink)
// ---------------------------------------------------------------------------

/// Retorna true se `msg` é um evento NEW ou DEL relevante para o prefixo alvo.
#[cfg(test)]
pub fn is_relevant_neigh_event(
    msg: &NetlinkMessage<RouteNetlinkMessage>,
    target_prefix: &str,
) -> bool {
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

#[cfg(test)]
fn neigh_matches_prefix(neigh: &NeighbourMessage, target_prefix: &str) -> bool {
    neigh.attributes.iter().any(|attr| {
        matches!(
            attr,
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip))
            if ip.to_string().starts_with(target_prefix)
        )
    })
}

// ---------------------------------------------------------------------------
// Extração de eventos do stream Netlink
// ---------------------------------------------------------------------------

/// Extrai um `NeighborEvent` de uma mensagem `RTM_NEWNEIGH`.
///
/// Retorna `None` se:
/// - Não for IPv6
/// - Estado ainda incompleto ou falho (MAC desconhecido)
/// - Faltar IP ou MAC nos atributos
pub fn extract_neigh_info(msg: &NetlinkMessage<RouteNetlinkMessage>) -> Option<NeighborEvent> {
    let (neigh, is_delete) = match &msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(n)) => (n, false),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(n)) => (n, true),
        _ => return None,
    };

    let mut ip_v4: Option<std::net::Ipv4Addr> = None;
    let mut ip_v6: Option<Ipv6Addr> = None;
    let mut mac: Option<MacAddr> = None;

    for attr in &neigh.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(i)) => ip_v6 = Some(*i),
            NeighbourAttribute::Destination(NeighbourAddress::Inet(i)) => ip_v4 = Some(*i),
            NeighbourAttribute::LinkLocalAddress(m) => {
                mac = MacAddr::from_slice(m);
            }
            _ => {}
        }
    }

    let ip = match neigh.header.family {
        AddressFamily::Inet6 => std::net::IpAddr::V6(ip_v6?),
        AddressFamily::Inet => std::net::IpAddr::V4(ip_v4?),
        _ => return None,
    };

    // Só barramos Incomplete/Failed quando estamos descobrindo um novo host.
    if !is_delete
        && matches!(
            neigh.header.state,
            NeighbourState::Incomplete | NeighbourState::Failed
        )
    {
        return None;
    }

    if is_delete {
        Some(NeighborEvent::Deleted {
            ip,
            ifindex: neigh.header.ifindex,
        })
    } else {
        // Se for adição, o MAC é estritamente necessário. Retorna None se não existir.
        Some(NeighborEvent::Added {
            ip,
            mac: mac?,
            ifindex: neigh.header.ifindex,
        })
    }
}

// ---------------------------------------------------------------------------
// Queries ao kernel (usa o Handle compartilhado)
// ---------------------------------------------------------------------------

/// Devolve todos os vizinhos IPv6 no prefixo alvo como `NeighborEvent`.
///
/// Substitui `get_ipv6_neighbors` que retornava `Vec<(String, String)>`.
pub async fn get_ipv6_neighbors(
    handle: &Handle,
    target_prefix: &str,
) -> Result<Vec<NeighborEvent>> {
    let mut neighbors = Vec::new();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    while let Some(msg) = stream.try_next().await? {
        if let Some(event) = parse_neighbor_msg(msg) {
            let matches = match event.ip() {
                std::net::IpAddr::V6(ip) => ip.to_string().starts_with(target_prefix),
                _ => false,
            };
            if matches {
                neighbors.push(event);
            }
        }
    }

    Ok(neighbors)
}

// /// Devolve todos os vizinhos IPv4 na mesma rede como `NeighborEvent`.
// pub async fn get_ipv4_neighbors(handle: &Handle) -> Result<Vec<NeighborEvent>> {
//     let mut neighbors = Vec::new();
//     let mut stream = handle
//         .neighbours()
//         .get()
//         .set_family(IpVersion::V4)
//         .execute();

//     while let Some(msg) = stream.try_next().await? {
//         if let Some(event) = parse_neighbor_msg(msg) {
//             neighbors.push(event);
//         }
//     }

//     Ok(neighbors)
// }

fn parse_neighbor_msg(msg: NeighbourMessage) -> Option<NeighborEvent> {
    if matches!(
        msg.header.state,
        NeighbourState::Incomplete | NeighbourState::Failed
    ) {
        return None;
    }

    let mut ip: Option<std::net::IpAddr> = None;
    let mut mac: Option<MacAddr> = None;
    let ifindex = msg.header.ifindex;

    for attr in msg.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) => {
                ip = Some(std::net::IpAddr::V6(addr));
            }
            NeighbourAttribute::Destination(NeighbourAddress::Inet(addr)) => {
                ip = Some(std::net::IpAddr::V4(addr));
            }
            NeighbourAttribute::LinkLocalAddress(bytes) => {
                mac = MacAddr::from_slice(&bytes);
            }
            _ => {}
        }
    }

    let ip = ip?;
    let mac = mac?;

    Some(NeighborEvent::Added { ip, mac, ifindex })
}

/// Procura o MAC de um vizinho IPv6 específico na tabela NDP do kernel.
///
/// Usado como fallback no `DHCPv6` quando o DUID não contém MAC (DUID-EN,
/// DUID-UUID) e o endereço link-local do peer não é EUI-64.
pub async fn lookup_mac_for_ipv6(handle: &Handle, ip: &Ipv6Addr) -> Option<MacAddr> {
    let target = ip.to_string();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    while let Ok(Some(msg)) = stream.try_next().await {
        if matches!(
            msg.header.state,
            NeighbourState::Incomplete | NeighbourState::Failed
        ) {
            continue;
        }

        let mut found_ip = false;
        let mut found_mac: Option<MacAddr> = None;

        for attr in &msg.attributes {
            match attr {
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr))
                    if addr.to_string() == target =>
                {
                    found_ip = true;
                }
                NeighbourAttribute::LinkLocalAddress(b) => {
                    found_mac = MacAddr::from_slice(b);
                }
                _ => {}
            }
        }

        if found_ip {
            return found_mac;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// EUI-64 helpers
// ---------------------------------------------------------------------------

/// Tenta recuperar o MAC de um endereço IPv6 link-local EUI-64.
///
/// Formato EUI-64:
/// ```text
/// MAC:  AA:BB:CC:DD:EE:FF
/// IID:  (AA^0x02):BB:CC:FF:FE:DD:EE:FF
///        ^^^^^^^^             ^^ ^^ ^^ bytes 11,12 = FF:FE (marcador)
/// ```
/// Retorna `None` se o endereço não for link-local ou não usar EUI-64.
pub const fn mac_from_eui64_link_local(ip: &Ipv6Addr) -> Option<MacAddr> {
    let o = ip.octets();
    if o[0] != 0xfe || (o[1] & 0xc0) != 0x80 {
        return None; // não é fe80::/10
    }
    if o[11] != 0xff || o[12] != 0xfe {
        return None; // não é EUI-64
    }
    // Reverte o bit U/L (bit 6 do primeiro octeto do IID)
    Some(MacAddr([o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]]))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
    use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

    fn mock_neigh_msg(
        state: NeighbourState,
        ip: std::net::IpAddr,
        mac: Option<[u8; 6]>,
        is_delete: bool,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let addr = match ip {
            std::net::IpAddr::V6(a) => NeighbourAddress::Inet6(a),
            std::net::IpAddr::V4(a) => NeighbourAddress::Inet(a),
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
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        let mac_bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let msg = mock_neigh_msg(NeighbourState::Reachable, ip, Some(mac_bytes), false);
        let event = extract_neigh_info(&msg).expect("deve extrair evento");

        assert_eq!(*event.ip(), ip);
        assert_eq!(event.mac(), Some(MacAddr(mac_bytes)));
        if let NeighborEvent::Added { ifindex, .. } = event {
            assert_eq!(ifindex, 2);
        } else {
            panic!("esperava NeighborEvent::Added");
        }
    }

    #[test]
    fn extract_neigh_info_ignores_incomplete_and_failed() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let msg_incomplete = mock_neigh_msg(NeighbourState::Incomplete, ip, Some(mac), false);
        let msg_failed = mock_neigh_msg(NeighbourState::Failed, ip, Some(mac), false);

        assert!(extract_neigh_info(&msg_incomplete).is_none());
        assert!(extract_neigh_info(&msg_failed).is_none());
    }

    #[test]
    fn extract_neigh_info_requires_both_ip_and_mac() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
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
        let update = event.to_device_update(Some(&gua_prefix));

        assert!(
            matches!(update, DeviceUpdate::SlaacObserved { addr, .. } if addr == slaac_ip),
            "IP no prefixo GUA deve virar SlaacObserved"
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
        let update = event.to_device_update(Some(&gua_prefix));

        assert!(
            matches!(update, DeviceUpdate::NdpSeen { .. }),
            "Link-local deve virar NdpSeen"
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
        // Sem prefixo configurado — nunca assume SLAAC
        let update = event.to_device_update(None);

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
        let msg_incomplete =
            mock_neigh_msg(NeighbourState::Incomplete, valid_ip.into(), None, false);

        assert!(is_relevant_neigh_event(&msg_valid, target_prefix));
        assert!(!is_relevant_neigh_event(&msg_invalid, target_prefix));
        assert!(!is_relevant_neigh_event(&msg_incomplete, target_prefix));
    }

    // --- EUI-64 ---

    #[test]
    fn mac_from_eui64_valid() {
        // MAC: 3c:0a:7a:d8:11:78  →  bit U/L invertido: 0x3C ^ 0x02 = 0x3E
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
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        // No RTM_DELNEIGH o MAC pode estar ausente
        let msg = mock_neigh_msg(NeighbourState::Failed, ip, None, true);
        let event = extract_neigh_info(&msg).expect("deve extrair delete");

        assert_eq!(event, NeighborEvent::Deleted { ip, ifindex: 2 });
    }
}
