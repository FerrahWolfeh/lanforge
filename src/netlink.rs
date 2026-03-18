//! Wrapper do netlink para queries de vizinhos IPv6 e filtragem de eventos.
//!
//! Centraliza toda interação com o subsistema netlink do kernel numa única
//! interface. O Handle é criado em main.rs e passado aqui por referência.

use anyhow::Result;
use futures::stream::TryStreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
};
use rtnetlink::{Handle, IpVersion};
use std::net::Ipv6Addr;

// ---------------------------------------------------------------------------
// Neighbour event filter
// ---------------------------------------------------------------------------

/// Returns true if `msg` is a NEW or DEL neighbour event for our target prefix.
pub fn is_relevant_neigh_event(
    msg: &NetlinkMessage<RouteNetlinkMessage>,
    target_prefix: &str,
) -> bool {
    match &msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(neigh)) => {
            // Only purely transient states should be completely ignored.
            // When an entry transitions to Failed, we WANT a scan so we can immediately drop it.
            if neigh.header.state == NeighbourState::Incomplete {
                return false;
            }
            neigh_matches_prefix(neigh, target_prefix)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(neigh)) => {
            // A deletion always warrants a rescan to remove the entry
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

/// Extrai proativamente IP e MAC de eventos Netlink (RTM_NEWNEIGH)
pub fn extract_neigh_info(
    msg: &NetlinkMessage<RouteNetlinkMessage>,
) -> Option<(Ipv6Addr, [u8; 6])> {
    if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(neigh)) = &msg.payload {
        if neigh.header.family != AddressFamily::Inet6 {
            return None;
        }

        // Ignora estados onde o MAC ainda não é conhecido
        if neigh.header.state == NeighbourState::Incomplete
            || neigh.header.state == NeighbourState::Failed
        {
            return None;
        }

        let mut ip = None;
        let mut mac = None;

        for attr in &neigh.attributes {
            match attr {
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(i)) => ip = Some(*i),
                NeighbourAttribute::LinkLocalAddress(m) if m.len() >= 6 => {
                    mac = Some([m[0], m[1], m[2], m[3], m[4], m[5]]);
                }
                _ => {}
            }
        }

        if let (Some(ip), Some(mac)) = (ip, mac) {
            return Some((ip, mac));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Netlink neighbour query (uses the shared Handle)
// ---------------------------------------------------------------------------

/// Procura o MAC de um vizinho IPv6 específico na tabela NDP do kernel.
///
/// Usado como fallback no DHCPv6 quando o DUID não contém MAC (DUID-EN, DUID-UUID)
/// e o endereço link-local do peer não é EUI-64.
/// O kernel sempre tem o par IP↔MAC para qualquer host que enviou um pacote recentemente.
pub async fn lookup_mac_for_ipv6(handle: &Handle, ip: &Ipv6Addr) -> Option<[u8; 6]> {
    let target = ip.to_string();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    while let Ok(Some(msg)) = stream.try_next().await {
        if msg.header.state == NeighbourState::Incomplete
            || msg.header.state == NeighbourState::Failed
        {
            continue;
        }
        let mut found_ip = false;
        let mut mac_bytes: Option<[u8; 6]> = None;

        for attr in &msg.attributes {
            match attr {
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr))
                    if addr.to_string() == target =>
                {
                    found_ip = true;
                }
                NeighbourAttribute::LinkLocalAddress(b) if b.len() == 6 => {
                    mac_bytes = Some([b[0], b[1], b[2], b[3], b[4], b[5]]);
                }
                _ => {}
            }
        }

        if found_ip {
            return mac_bytes;
        }
    }
    None
}

/// Tenta recuperar o MAC de um endereço IPv6 link-local EUI-64.
///
/// O IID EUI-64 é formado assim:
///   MAC:  AA:BB:CC:DD:EE:FF
///   IID:  (AA^0x02):BB:CC:FF:FE:DD:EE:FF
///
/// Ou seja: bytes 8,9,10 = primeiros 3 do MAC (bit U/L revertido no byte 8),
///           bytes 11,12 = FF:FE (marcador EUI-64),
///           bytes 13,14,15 = últimos 3 do MAC.
///
/// Retorna None se o endereço não for link-local ou não usar EUI-64.
pub fn mac_from_eui64_link_local(ip: &Ipv6Addr) -> Option<[u8; 6]> {
    let o = ip.octets();
    if o[0] != 0xfe || (o[1] & 0xc0) != 0x80 {
        return None; // não é fe80::/10
    }
    if o[11] != 0xff || o[12] != 0xfe {
        return None; // não é EUI-64 (privacy address ou manual)
    }
    // Reverte o bit U/L (bit 6 do primeiro octeto do IID)
    Some([o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]])
}

pub async fn get_ipv6_neighbors(
    handle: &Handle,
    target_prefix: &str,
) -> Result<Vec<(String, String)>> {
    let mut neighbors = Vec::new();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    while let Some(msg) = stream.try_next().await? {
        if let Some((ip, mac)) = parse_neighbor(msg)
            && ip.starts_with(target_prefix)
        {
            neighbors.push((ip, mac));
        }
    }

    Ok(neighbors)
}

fn parse_neighbor(msg: NeighbourMessage) -> Option<(String, String)> {
    if msg.header.state == NeighbourState::Incomplete || msg.header.state == NeighbourState::Failed
    {
        return None;
    }

    let mut ip_str = String::new();
    let mut mac_str = String::new();

    for attr in msg.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(ipv6)) => {
                ip_str = ipv6.to_string();
            }
            NeighbourAttribute::LinkLocalAddress(mac_bytes) => {
                mac_str = mac_bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":");
            }
            _ => {}
        }
    }

    if !ip_str.is_empty() && !mac_str.is_empty() {
        Some((ip_str, mac_str))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
    use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

    // -----------------------------------------------------------------------
    // Helper para gerar mensagens Netlink simuladas
    // -----------------------------------------------------------------------
    fn mock_neigh_msg(
        state: NeighbourState,
        ip: Ipv6Addr,
        mac: Option<[u8; 6]>,
        is_delete: bool,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut attributes = vec![NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip))];
        if let Some(m) = mac {
            attributes.push(NeighbourAttribute::LinkLocalAddress(m.to_vec()));
        }

        // Contornando o #[non_exhaustive] instanciando com default() e mutando depois
        let header = NeighbourHeader {
            family: AddressFamily::Inet6,
            ifindex: 1,
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

        // O mesmo vale para a NetlinkMessage para evitar problemas com versões futuras
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(payload),
        )
    }

    // -----------------------------------------------------------------------
    // Testes de Parse/Filtro Netlink
    // -----------------------------------------------------------------------

    #[test]
    fn extract_neigh_info_success() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let msg = mock_neigh_msg(NeighbourState::Reachable, ip, Some(mac), false);

        let extracted = extract_neigh_info(&msg);
        assert_eq!(extracted, Some((ip, mac)));
    }

    #[test]
    fn extract_neigh_info_ignores_incomplete_states() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // Estado Incomplete (MAC ainda sendo descoberto) não deve ser extraído
        let msg1 = mock_neigh_msg(NeighbourState::Incomplete, ip, Some(mac), false);
        assert_eq!(extract_neigh_info(&msg1), None);

        // Estado Failed (host não respondeu) também é ignorado
        let msg2 = mock_neigh_msg(NeighbourState::Failed, ip, Some(mac), false);
        assert_eq!(extract_neigh_info(&msg2), None);
    }

    #[test]
    fn is_relevant_event_matches_prefix_and_state() {
        let target_prefix = "fd97:f00d:cafe:3731::";
        let valid_ip: Ipv6Addr = "fd97:f00d:cafe:3731::1234".parse().unwrap();
        let invalid_ip: Ipv6Addr = "2001:db8::1234".parse().unwrap();

        let msg_valid = mock_neigh_msg(NeighbourState::Reachable, valid_ip, None, false);
        let msg_invalid = mock_neigh_msg(NeighbourState::Reachable, invalid_ip, None, false);
        let msg_incomplete = mock_neigh_msg(NeighbourState::Incomplete, valid_ip, None, false);

        assert!(
            is_relevant_neigh_event(&msg_valid, target_prefix),
            "Deve aceitar IP do prefixo alvo"
        );
        assert!(
            !is_relevant_neigh_event(&msg_invalid, target_prefix),
            "Deve ignorar prefixo alienígena"
        );
        assert!(
            !is_relevant_neigh_event(&msg_incomplete, target_prefix),
            "Deve ignorar estado Incomplete"
        );
    }

    // -----------------------------------------------------------------------
    // Testes de Matemática de IP (EUI-64)
    // -----------------------------------------------------------------------

    #[test]
    fn mac_from_eui64_valid() {
        // IP EUI-64 gerado a partir do MAC: 3c:0a:7a:d8:11:78
        // O bit U/L (bit 6 do primeiro octeto) é invertido, 0x3C vira 0x3E.
        let ip: Ipv6Addr = "fe80::3e0a:7aff:fed8:1178".parse().unwrap();

        let extracted_mac = mac_from_eui64_link_local(&ip);
        let expected_mac = [0x3c, 0x0a, 0x7a, 0xd8, 0x11, 0x78];

        assert_eq!(extracted_mac, Some(expected_mac));
    }

    #[test]
    fn mac_from_eui64_ignores_non_link_local() {
        // Um GUA usando EUI-64. Nossa função é estrita a link-local (fe80::)
        let ip: Ipv6Addr = "2001:db8::3e0a:7aff:fed8:1178".parse().unwrap();
        assert_eq!(mac_from_eui64_link_local(&ip), None);
    }

    #[test]
    fn mac_from_eui64_ignores_privacy_extensions() {
        // Link-local opaco aleatório (não contém FF:FE no meio)
        let ip: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
        assert_eq!(mac_from_eui64_link_local(&ip), None);
    }
}
