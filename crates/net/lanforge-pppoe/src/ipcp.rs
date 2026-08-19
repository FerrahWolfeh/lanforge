use crate::error::PppoeError;
use crate::session::PppoeSession;
use lanforge_types::identifiers::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::time::{timeout, Instant};
use tracing::{debug, warn};

pub const PPP_IPCP: u16 = 0x8021;
pub const PPP_IPV6CP: u16 = 0x8057;

pub const IPCP_OPT_IP: u8 = 3;
pub const IPCP_OPT_DNS1: u8 = 129;
pub const IPCP_OPT_DNS2: u8 = 131;

pub const IPV6CP_OPT_IFID: u8 = 1;

#[must_use]
pub fn mac_to_eui64_link_local(mac: MacAddr) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    bytes[8] = mac.0[0] ^ 0x02;
    bytes[9] = mac.0[1];
    bytes[10] = mac.0[2];
    bytes[11] = 0xff;
    bytes[12] = 0xfe;
    bytes[13] = mac.0[3];
    bytes[14] = mac.0[4];
    bytes[15] = mac.0[5];
    Ipv6Addr::from(bytes)
}

pub struct IpcpNegotiated {
    pub local_ip: Option<Ipv4Addr>,
    pub peer_ip: Option<Ipv4Addr>,
    pub dns: Vec<IpAddr>,
    pub local_v6_ll: Option<Ipv6Addr>,
    pub peer_v6_ll: Option<Ipv6Addr>,
}

pub async fn negotiate_ipcp(
    session: &PppoeSession,
    local_mac: MacAddr,
) -> Result<IpcpNegotiated, PppoeError> {
    let ipv4_res = negotiate_ipv4cp(session).await;
    let ipv6_res = negotiate_ipv6cp(session, local_mac).await;

    let (local_ip, peer_ip, dns) = match ipv4_res {
        Ok((lip, pip, dns_vec)) => (Some(lip), Some(pip), dns_vec),
        Err(e) => {
            warn!(error = %e, "IPv4 IPCP failed");
            (None, None, Vec::new())
        }
    };

    let (local_v6_ll, peer_v6_ll) = match ipv6_res {
        Ok((loc, peer)) => (Some(loc), peer),
        Err(e) => {
            debug!(error = %e, "IPv6CP not negotiated or rejected");
            (None, None)
        }
    };

    if local_ip.is_none() && local_v6_ll.is_none() {
        return Err(PppoeError::IpcpFailed(
            "Neither IPv4 nor IPv6CP could be negotiated".into(),
        ));
    }

    Ok(IpcpNegotiated {
        local_ip,
        peer_ip,
        dns,
        local_v6_ll,
        peer_v6_ll,
    })
}

fn build_ipcp_req(id: u8, ip: Ipv4Addr, dns1: Ipv4Addr, dns2: Ipv4Addr, req_dns: bool) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(32);
    pkt.extend_from_slice(&PPP_IPCP.to_be_bytes());
    pkt.push(0x01); // Configure-Request
    pkt.push(id);

    let mut opts = Vec::with_capacity(24);
    // Opt 3: IP Address
    opts.push(IPCP_OPT_IP);
    opts.push(6);
    opts.extend_from_slice(&ip.octets());

    if req_dns {
        // Opt 129: Primary DNS
        opts.push(IPCP_OPT_DNS1);
        opts.push(6);
        opts.extend_from_slice(&dns1.octets());

        // Opt 131: Secondary DNS
        opts.push(IPCP_OPT_DNS2);
        opts.push(6);
        opts.extend_from_slice(&dns2.octets());
    }

    #[allow(clippy::cast_possible_truncation)]
    let len = (4 + opts.len()) as u16;
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(&opts);
    pkt
}

fn build_ipcp_ack(id: u8, data: &[u8], len: usize) -> Vec<u8> {
    let mut ack_pkt = Vec::with_capacity(len + 2);
    ack_pkt.extend_from_slice(&PPP_IPCP.to_be_bytes());
    ack_pkt.push(0x02); // Ack
    ack_pkt.push(id);
    ack_pkt.extend_from_slice(&data[4..2 + len]);
    ack_pkt
}

fn parse_ipcp_nak(
    data: &[u8],
    len: usize,
    assigned_ip: &mut Ipv4Addr,
    assigned_dns1: &mut Ipv4Addr,
    assigned_dns2: &mut Ipv4Addr,
) {
    let mut offset = 4;
    let end = 2 + len;
    while offset + 2 <= end {
        let opt_type = data[offset];
        let opt_len = data[offset + 1] as usize;
        if opt_len < 2 || offset + opt_len > end {
            break;
        }

        if opt_type == IPCP_OPT_IP && opt_len == 6 {
            *assigned_ip = Ipv4Addr::new(
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
            );
        } else if opt_type == IPCP_OPT_DNS1 && opt_len == 6 {
            *assigned_dns1 = Ipv4Addr::new(
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
            );
        } else if opt_type == IPCP_OPT_DNS2 && opt_len == 6 {
            *assigned_dns2 = Ipv4Addr::new(
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
            );
        }
        offset += opt_len;
    }
}

fn parse_peer_ip(data: &[u8], len: usize) -> Option<Ipv4Addr> {
    let mut offset = 4;
    let end = 2 + len;
    while offset + 2 <= end {
        let opt_type = data[offset];
        let opt_len = data[offset + 1] as usize;
        if opt_len < 2 || offset + opt_len > end {
            break;
        }
        if opt_type == IPCP_OPT_IP && opt_len == 6 {
            return Some(Ipv4Addr::new(
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
            ));
        }
        offset += opt_len;
    }
    None
}

#[allow(clippy::too_many_lines)]
async fn negotiate_ipv4cp(
    session: &PppoeSession,
) -> Result<(Ipv4Addr, Ipv4Addr, Vec<IpAddr>), PppoeError> {
    let mut req_id = 1u8;
    let mut assigned_ip = Ipv4Addr::UNSPECIFIED;
    let mut assigned_dns1 = Ipv4Addr::UNSPECIFIED;
    let mut assigned_dns2 = Ipv4Addr::UNSPECIFIED;
    let mut req_dns = true;

    let mut my_ack_received = false;
    let mut peer_ack_sent = false;
    let mut peer_ip = Ipv4Addr::UNSPECIFIED;

    let mut req_pkt = build_ipcp_req(
        req_id,
        assigned_ip,
        assigned_dns1,
        assigned_dns2,
        req_dns,
    );
    session.send_ppp_frame(&req_pkt).await?;

    let ipcp_timeout = Duration::from_secs(10);
    let start = Instant::now();
    let mut buf = [0u8; 1500];

    while start.elapsed() < ipcp_timeout {
        if my_ack_received && peer_ack_sent {
            let mut dns = Vec::new();
            if assigned_dns1 != Ipv4Addr::UNSPECIFIED {
                dns.push(IpAddr::V4(assigned_dns1));
            }
            if assigned_dns2 != Ipv4Addr::UNSPECIFIED {
                dns.push(IpAddr::V4(assigned_dns2));
            }
            return Ok((assigned_ip, peer_ip, dns));
        }

        let Ok(Ok(n)) = timeout(Duration::from_secs(1), session.recv_ppp_frame(&mut buf)).await
        else {
            req_id = req_id.wrapping_add(1);
            req_pkt = build_ipcp_req(
                req_id,
                assigned_ip,
                assigned_dns1,
                assigned_dns2,
                req_dns,
            );
            session.send_ppp_frame(&req_pkt).await?;
            continue;
        };

        let data = if n >= 2 && buf[0] == 0xff && buf[1] == 0x03 {
            &buf[2..n]
        } else {
            &buf[..n]
        };

        if data.len() < 6 {
            continue;
        }

        let proto = u16::from_be_bytes([data[0], data[1]]);
        if proto != PPP_IPCP {
            continue;
        }

        let code = data[2];
        let id = data[3];
        let len = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < 2 + len {
            continue;
        }

        match code {
            0x01 => {
                // Configure-Request from peer (BRAS)
                if let Some(pip) = parse_peer_ip(data, len) {
                    peer_ip = pip;
                }
                let ack_pkt = build_ipcp_ack(id, data, len);
                session.send_ppp_frame(&ack_pkt).await?;
                peer_ack_sent = true;
            }
            0x02 if id == req_id => {
                // Configure-Ack from peer
                my_ack_received = true;
            }
            0x03 if id == req_id => {
                // Configure-Nak from peer (giving us our IP / DNS)
                parse_ipcp_nak(
                    data,
                    len,
                    &mut assigned_ip,
                    &mut assigned_dns1,
                    &mut assigned_dns2,
                );
                req_id = req_id.wrapping_add(1);
                req_pkt = build_ipcp_req(
                    req_id,
                    assigned_ip,
                    assigned_dns1,
                    assigned_dns2,
                    req_dns,
                );
                session.send_ppp_frame(&req_pkt).await?;
            }
            0x04 if id == req_id => {
                // Configure-Reject from peer (e.g. DNS options not supported)
                req_dns = false;
                req_id = req_id.wrapping_add(1);
                req_pkt = build_ipcp_req(
                    req_id,
                    assigned_ip,
                    assigned_dns1,
                    assigned_dns2,
                    req_dns,
                );
                session.send_ppp_frame(&req_pkt).await?;
            }
            _ => {}
        }
    }

    Err(PppoeError::IpcpFailed("IPv4 IPCP negotiation timed out".into()))
}

async fn negotiate_ipv6cp(
    session: &PppoeSession,
    local_mac: MacAddr,
) -> Result<(Ipv6Addr, Option<Ipv6Addr>), PppoeError> {
    let local_ll = mac_to_eui64_link_local(local_mac);
    let mut local_ifid = [0u8; 8];
    local_ifid.copy_from_slice(&local_ll.octets()[8..16]);

    let req_id = 1u8;
    let mut req_pkt = Vec::with_capacity(16);
    req_pkt.extend_from_slice(&PPP_IPV6CP.to_be_bytes());
    req_pkt.push(0x01); // Conf-Req
    req_pkt.push(req_id);
    req_pkt.extend_from_slice(&14u16.to_be_bytes());
    req_pkt.push(IPV6CP_OPT_IFID);
    req_pkt.push(10);
    req_pkt.extend_from_slice(&local_ifid);

    session.send_ppp_frame(&req_pkt).await?;

    let mut my_ack_received = false;
    let mut peer_ack_sent = false;
    let mut peer_ll = None;

    let timeout_dur = Duration::from_secs(3);
    let start = Instant::now();
    let mut buf = [0u8; 1500];

    while start.elapsed() < timeout_dur {
        if my_ack_received && peer_ack_sent {
            return Ok((local_ll, peer_ll));
        }

        let Ok(Ok(n)) = timeout(Duration::from_secs(1), session.recv_ppp_frame(&mut buf)).await
        else {
            continue;
        };

        let data = if n >= 2 && buf[0] == 0xff && buf[1] == 0x03 {
            &buf[2..n]
        } else {
            &buf[..n]
        };

        if data.len() < 6 {
            continue;
        }

        let proto = u16::from_be_bytes([data[0], data[1]]);
        if proto != PPP_IPV6CP {
            continue;
        }

        let code = data[2];
        let id = data[3];
        let len = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < 2 + len {
            continue;
        }

        match code {
            0x01 => {
                // Configure-Request from peer
                if len >= 14 && data[6] == IPV6CP_OPT_IFID && data[7] == 10 {
                    let mut peer_bytes = [0u8; 16];
                    peer_bytes[0] = 0xfe;
                    peer_bytes[1] = 0x80;
                    peer_bytes[8..16].copy_from_slice(&data[8..16]);
                    peer_ll = Some(Ipv6Addr::from(peer_bytes));
                }

                let mut ack_pkt = Vec::with_capacity(len + 2);
                ack_pkt.extend_from_slice(&PPP_IPV6CP.to_be_bytes());
                ack_pkt.push(0x02); // Ack
                ack_pkt.push(id);
                ack_pkt.extend_from_slice(&data[4..2 + len]);
                session.send_ppp_frame(&ack_pkt).await?;
                peer_ack_sent = true;
            }
            0x02 => {
                // Configure-Ack
                if id == req_id {
                    my_ack_received = true;
                }
            }
            0x04 => {
                // Configure-Reject
                return Err(PppoeError::IpcpFailed("IPv6CP rejected by peer".into()));
            }
            _ => {}
        }
    }

    if my_ack_received {
        Ok((local_ll, peer_ll))
    } else {
        Err(PppoeError::IpcpFailed("IPv6CP timed out".into()))
    }
}
