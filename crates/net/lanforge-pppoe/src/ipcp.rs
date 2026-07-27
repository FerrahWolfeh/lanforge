use crate::error::PppoeError;
use crate::session::PppoeSession;
use lanforge_types::identifiers::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
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

fn build_ipcp_req(id: u8, ip: Ipv4Addr, req_dns: bool) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&PPP_IPCP.to_be_bytes());
    pkt.push(0x01); // Configure-Request
    pkt.push(id);

    let mut opts = Vec::new();
    // Opt 3: IP Address
    opts.push(IPCP_OPT_IP);
    opts.push(6);
    opts.extend_from_slice(&ip.octets());

    if req_dns {
        // Opt 129: Primary DNS
        opts.push(IPCP_OPT_DNS1);
        opts.push(6);
        opts.extend_from_slice(&[0, 0, 0, 0]);

        // Opt 131: Secondary DNS
        opts.push(IPCP_OPT_DNS2);
        opts.push(6);
        opts.extend_from_slice(&[0, 0, 0, 0]);
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

fn parse_ipcp_nak(data: &[u8], len: usize, my_ip: &mut Ipv4Addr, dns_addrs: &mut Vec<IpAddr>) {
    let mut offset = 6;
    let end = 2 + len;
    while offset + 2 <= end {
        let opt_type = data[offset];
        let opt_len = data[offset + 1] as usize;
        if opt_len < 2 || offset + opt_len > end {
            break;
        }
        if opt_len == 6 {
            let ip = Ipv4Addr::new(
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
            );
            match opt_type {
                IPCP_OPT_IP => *my_ip = ip,
                IPCP_OPT_DNS1 | IPCP_OPT_DNS2
                    if !ip.is_unspecified() && !dns_addrs.contains(&IpAddr::V4(ip)) =>
                {
                    dns_addrs.push(IpAddr::V4(ip));
                }
                _ => {}
            }
        }
        offset += opt_len;
    }
}

fn check_dns_rejected(data: &[u8], len: usize) -> bool {
    let mut offset = 6;
    let end = 2 + len;
    while offset + 2 <= end {
        let opt_type = data[offset];
        let opt_len = data[offset + 1] as usize;
        if opt_len < 2 || offset + opt_len > end {
            break;
        }
        if opt_type == IPCP_OPT_DNS1 || opt_type == IPCP_OPT_DNS2 {
            return true;
        }
        offset += opt_len;
    }
    false
}

fn parse_ipcp_req_peer_ip(data: &[u8], len: usize) -> Option<Ipv4Addr> {
    let mut offset = 6;
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

async fn negotiate_ipv4cp(
    session: &PppoeSession,
) -> Result<(Ipv4Addr, Ipv4Addr, Vec<IpAddr>), PppoeError> {
    let mut req_id = 1u8;
    let mut my_ip = Ipv4Addr::UNSPECIFIED;
    let mut peer_ip = Ipv4Addr::UNSPECIFIED;
    let mut dns_addrs = Vec::new();

    let mut my_ack_rcvd = false;
    let mut peer_ack_sent = false;

    let mut request_dns = true;

    session
        .send_ppp_frame(&build_ipcp_req(req_id, my_ip, request_dns))
        .await?;

    let timeout = Duration::from_secs(10);
    let start = tokio::time::Instant::now();
    let mut buf = [0u8; 1500];

    while start.elapsed() < timeout {
        if my_ack_rcvd && peer_ack_sent {
            debug!(
                local = %my_ip,
                peer = %peer_ip,
                "IPCP negotiation complete"
            );
            return Ok((my_ip, peer_ip, dns_addrs));
        }

        let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(1), session.recv_ppp_frame(&mut buf)).await
        else {
            req_id = req_id.wrapping_add(1);
            session
                .send_ppp_frame(&build_ipcp_req(req_id, my_ip, request_dns))
                .await?;
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

        debug!(code, id, len, "Received IPCP frame");

        match code {
            0x02 => {
                // Configure-Ack
                if id == req_id {
                    my_ack_rcvd = true;
                    debug!("Received IPCP Configure-Ack");
                }
            }
            0x03 => {
                // Configure-Nak — server providing allocated IP and/or DNS
                if id == req_id {
                    parse_ipcp_nak(data, len, &mut my_ip, &mut dns_addrs);
                    req_id = req_id.wrapping_add(1);
                    session
                        .send_ppp_frame(&build_ipcp_req(req_id, my_ip, request_dns))
                        .await?;
                }
            }
            0x04 => {
                // Configure-Reject — server rejected DNS options
                if id == req_id {
                    if check_dns_rejected(data, len) {
                        request_dns = false;
                    }
                    req_id = req_id.wrapping_add(1);
                    session
                        .send_ppp_frame(&build_ipcp_req(req_id, my_ip, request_dns))
                        .await?;
                }
            }
            0x01 => {
                // Configure-Request from peer
                if let Some(ip) = parse_ipcp_req_peer_ip(data, len) {
                    peer_ip = ip;
                }

                let ack_pkt = build_ipcp_ack(id, data, len);
                session.send_ppp_frame(&ack_pkt).await?;
                peer_ack_sent = true;
            }
            _ => {}
        }
    }

    Err(PppoeError::IpcpFailed("IPCP negotiation timed out".into()))
}

#[must_use]
pub fn ifid_to_link_local(ifid: [u8; 8]) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    bytes[8..16].copy_from_slice(&ifid);
    Ipv6Addr::from(bytes)
}

async fn negotiate_ipv6cp(
    session: &PppoeSession,
    mac: MacAddr,
) -> Result<(Ipv6Addr, Option<Ipv6Addr>), PppoeError> {
    // Generate EUI-64 Interface Identifier from MAC
    let mut local_ifid = [0u8; 8];
    local_ifid[0] = mac.0[0] ^ 0x02; // Flip local/universal bit
    local_ifid[1] = mac.0[1];
    local_ifid[2] = mac.0[2];
    local_ifid[3] = 0xff;
    local_ifid[4] = 0xfe;
    local_ifid[5] = mac.0[3];
    local_ifid[6] = mac.0[4];
    local_ifid[7] = mac.0[5];

    let mut req_id = 1u8;

    let send_req = |id: u8| {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&PPP_IPV6CP.to_be_bytes());
        pkt.push(0x01); // Configure-Request
        pkt.push(id);

        let mut opts = Vec::new();
        opts.push(IPV6CP_OPT_IFID);
        opts.push(10);
        opts.extend_from_slice(&local_ifid);

        #[allow(clippy::cast_possible_truncation)]
        let len = (4 + opts.len()) as u16;
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(&opts);
        pkt
    };

    session.send_ppp_frame(&send_req(req_id)).await?;

    let timeout = Duration::from_secs(10);
    let start = tokio::time::Instant::now();
    let mut buf = [0u8; 1500];

    let mut my_ack = false;
    let mut peer_ack = false;
    let mut peer_v6_ll = None;

    while start.elapsed() < timeout {
        if my_ack && peer_ack {
            debug!("IPv6CP negotiation complete");
            return Ok((ifid_to_link_local(local_ifid), peer_v6_ll));
        }

        let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(1), session.recv_ppp_frame(&mut buf)).await
        else {
            req_id = req_id.wrapping_add(1);
            session.send_ppp_frame(&send_req(req_id)).await?;
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
            0x02 => {
                if id == req_id {
                    my_ack = true;
                }
            }
            0x01 => {
                // Parse peer IFID option
                let mut offset = 6;
                let end = 2 + len;
                while offset + 2 <= end {
                    let opt_type = data[offset];
                    let opt_len = data[offset + 1] as usize;
                    if opt_len < 2 || offset + opt_len > end {
                        break;
                    }
                    if opt_type == IPV6CP_OPT_IFID && opt_len == 10 {
                        let mut p_ifid = [0u8; 8];
                        p_ifid.copy_from_slice(&data[offset + 2..offset + 10]);
                        peer_v6_ll = Some(ifid_to_link_local(p_ifid));
                    }
                    offset += opt_len;
                }

                let mut ack_pkt = Vec::with_capacity(len + 2);
                ack_pkt.extend_from_slice(&PPP_IPV6CP.to_be_bytes());
                ack_pkt.push(0x02);
                ack_pkt.push(id);
                ack_pkt.extend_from_slice(&data[4..2 + len]);

                session.send_ppp_frame(&ack_pkt).await?;
                peer_ack = true;
            }
            _ => {}
        }
    }

    Err(PppoeError::Ipv6cpFailed("IPv6CP incomplete".into()))
}
