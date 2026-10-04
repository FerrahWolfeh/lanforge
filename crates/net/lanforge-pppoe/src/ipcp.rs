use crate::error::PppoeError;
use crate::lcp::{LCP_ECHO_REP, LCP_ECHO_REQ, PPP_LCP};
use crate::session::PppoeSession;
use lanforge_types::identifiers::MacAddr;
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::time::{Instant, timeout};
use tracing::{debug, info, warn};

pub const PPP_IPCP: u16 = 0x8021;
pub const PPP_IPV6CP: u16 = 0x8057;

pub const IPCP_OPT_IP: u8 = 3;
pub const IPCP_OPT_DNS1: u8 = 129;
pub const IPCP_OPT_DNS2: u8 = 131;

pub const IPV6CP_OPT_IFID: u8 = 1;

#[derive(Clone, Copy)]
pub struct PacketBuf<const N: usize> {
    pub buf: [u8; N],
    pub len: usize,
}

impl<const N: usize> std::ops::Deref for PacketBuf<N> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> AsRef<[u8]> for PacketBuf<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

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

#[derive(Debug, Clone)]
pub struct IpcpNegotiated {
    pub local_ip: Option<Ipv4Addr>,
    pub peer_ip: Option<Ipv4Addr>,
    pub dns: Vec<IpAddr>,
    pub local_v6_ll: Option<Ipv6Addr>,
    pub peer_v6_ll: Option<Ipv6Addr>,
}

fn build_ipcp_req(id: u8, ip: Ipv4Addr, dns1: Ipv4Addr, dns2: Ipv4Addr, req_dns: bool) -> PacketBuf<32> {
    let mut buf = [0u8; 32];
    buf[0..2].copy_from_slice(&PPP_IPCP.to_be_bytes());
    buf[2] = 0x01; // Configure-Request
    buf[3] = id;
    let opt_len: u16 = if req_dns { 18 } else { 6 };
    let len: u16 = 4 + opt_len;
    buf[4..6].copy_from_slice(&len.to_be_bytes());
    // Opt 3: IP Address
    buf[6] = IPCP_OPT_IP;
    buf[7] = 6;
    buf[8..12].copy_from_slice(&ip.octets());
    let total_len = if req_dns {
        // Opt 129: Primary DNS
        buf[12] = IPCP_OPT_DNS1;
        buf[13] = 6;
        buf[14..18].copy_from_slice(&dns1.octets());

        // Opt 131: Secondary DNS
        buf[18] = IPCP_OPT_DNS2;
        buf[19] = 6;
        buf[20..24].copy_from_slice(&dns2.octets());
        24
    } else {
        12
    };

    PacketBuf { buf, len: total_len }
}

fn build_control_ack(proto: u16, id: u8, data: &[u8], len: usize) -> SmallVec<[u8; 128]> {
    let mut ack_pkt = SmallVec::with_capacity(len + 2);
    ack_pkt.extend_from_slice(&proto.to_be_bytes());
    ack_pkt.push(0x02); // Configure-Ack
    ack_pkt.push(id);
    if data.len() >= 2 + len {
        ack_pkt.extend_from_slice(&data[4..2 + len]);
    }
    ack_pkt
}

#[inline]
fn build_ipcp_ack(id: u8, data: &[u8], len: usize) -> SmallVec<[u8; 128]> {
    build_control_ack(PPP_IPCP, id, data, len)
}

fn build_ipv6cp_req(id: u8, ifid: [u8; 8]) -> PacketBuf<16> {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&PPP_IPV6CP.to_be_bytes());
    buf[2] = 0x01; // Configure-Request
    buf[3] = id;
    buf[4..6].copy_from_slice(&14u16.to_be_bytes()); // 4 (header) + 10 (option)
    buf[6] = IPV6CP_OPT_IFID;
    buf[7] = 10;
    buf[8..16].copy_from_slice(&ifid);
    PacketBuf { buf, len: 16 }
}

#[inline]
fn build_ipv6cp_ack(id: u8, data: &[u8], len: usize) -> SmallVec<[u8; 128]> {
    build_control_ack(PPP_IPV6CP, id, data, len)
}

pub const fn parse_ipcp_nak(
    data: &[u8],
    len: usize,
    assigned_ip: &mut Ipv4Addr,
    assigned_dns1: &mut Ipv4Addr,
    assigned_dns2: &mut Ipv4Addr,
) {
    // Options in PPP Control Protocol packet begin at index 6 (after 2-byte proto + 1-byte code + 1-byte id + 2-byte len)
    let mut offset = 6;
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

#[must_use]
pub const fn parse_peer_ip(data: &[u8], len: usize) -> Option<Ipv4Addr> {
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

#[must_use]
pub fn parse_peer_v6_ifid(data: &[u8], len: usize) -> Option<Ipv6Addr> {
    let mut offset = 6;
    let end = 2 + len;
    while offset + 2 <= end {
        let opt_type = data[offset];
        let opt_len = data[offset + 1] as usize;
        if opt_len < 2 || offset + opt_len > end {
            break;
        }
        if opt_type == IPV6CP_OPT_IFID && opt_len == 10 && offset + 10 <= end {
            let mut peer_bytes = [0u8; 16];
            peer_bytes[0] = 0xfe;
            peer_bytes[1] = 0x80;
            peer_bytes[8..16].copy_from_slice(&data[offset + 2..offset + 10]);
            return Some(Ipv6Addr::from(peer_bytes));
        }
        offset += opt_len;
    }
    None
}

/// Unified concurrent IPCP (IPv4) and `IPv6CP` negotiation loop.
///
/// Both protocols run concurrently over the PPP session stream, preventing
/// packets of one protocol from being discarded while waiting for the other.
struct IpcpV4State {
    req_id: u8,
    assigned_ip: Ipv4Addr,
    assigned_dns1: Ipv4Addr,
    assigned_dns2: Ipv4Addr,
    req_dns: bool,
    my_ack_received: bool,
    peer_ack_sent: bool,
    peer_ip: Ipv4Addr,
    req_pkt: PacketBuf<32>,
}

impl IpcpV4State {
    fn new() -> Self {
        let req_id = 1u8;
        let assigned_ip = Ipv4Addr::UNSPECIFIED;
        let assigned_dns1 = Ipv4Addr::UNSPECIFIED;
        let assigned_dns2 = Ipv4Addr::UNSPECIFIED;
        let req_dns = true;
        let req_pkt = build_ipcp_req(req_id, assigned_ip, assigned_dns1, assigned_dns2, req_dns);
        Self {
            req_id,
            assigned_ip,
            assigned_dns1,
            assigned_dns2,
            req_dns,
            my_ack_received: false,
            peer_ack_sent: false,
            peer_ip: Ipv4Addr::UNSPECIFIED,
            req_pkt,
        }
    }

    const fn is_done(&self) -> bool {
        self.my_ack_received && self.peer_ack_sent
    }

    fn rebuild_req(&mut self) {
        self.req_id = self.req_id.wrapping_add(1);
        self.req_pkt = build_ipcp_req(
            self.req_id,
            self.assigned_ip,
            self.assigned_dns1,
            self.assigned_dns2,
            self.req_dns,
        );
    }
}

struct IpcpV6State {
    req_id: u8,
    local_ifid: [u8; 8],
    local_v6_ll: Ipv6Addr,
    my_ack_received: bool,
    peer_ack_sent: bool,
    peer_v6_ll: Option<Ipv6Addr>,
    rejected: bool,
    req_pkt: PacketBuf<16>,
}

impl IpcpV6State {
    fn new(local_mac: MacAddr) -> Self {
        let local_v6_ll = mac_to_eui64_link_local(local_mac);
        let mut local_ifid = [0u8; 8];
        local_ifid.copy_from_slice(&local_v6_ll.octets()[8..16]);
        let req_id = 1u8;
        let req_pkt = build_ipv6cp_req(req_id, local_ifid);
        Self {
            req_id,
            local_ifid,
            local_v6_ll,
            my_ack_received: false,
            peer_ack_sent: false,
            peer_v6_ll: None,
            rejected: false,
            req_pkt,
        }
    }

    const fn is_done(&self) -> bool {
        (self.my_ack_received && self.peer_ack_sent) || self.rejected
    }

    fn rebuild_req(&mut self) {
        self.req_id = self.req_id.wrapping_add(1);
        self.req_pkt = build_ipv6cp_req(self.req_id, self.local_ifid);
    }
}

async fn handle_ipcp_code(
    session: &PppoeSession,
    code: u8,
    id: u8,
    data: &[u8],
    len: usize,
    v4: &mut IpcpV4State,
) -> Result<(), PppoeError> {
    match code {
        0x01 => {
            if let Some(pip) = parse_peer_ip(data, len) {
                v4.peer_ip = pip;
            }
            let ack_pkt = build_ipcp_ack(id, data, len);
            session.send_ppp_frame(&ack_pkt).await?;
            v4.peer_ack_sent = true;
            info!(peer_ip = %v4.peer_ip, "Acknowledged BRAS IPv4 IPCP Configure-Request");
        }
        0x02 if id == v4.req_id => {
            v4.my_ack_received = true;
            info!(
                assigned_ip = %v4.assigned_ip,
                dns1 = %v4.assigned_dns1,
                dns2 = %v4.assigned_dns2,
                "BRAS acknowledged our IPv4 IPCP Configure-Request"
            );
        }
        0x03 if id == v4.req_id => {
            parse_ipcp_nak(
                data,
                len,
                &mut v4.assigned_ip,
                &mut v4.assigned_dns1,
                &mut v4.assigned_dns2,
            );
            info!(
                assigned_ip = %v4.assigned_ip,
                dns1 = %v4.assigned_dns1,
                dns2 = %v4.assigned_dns2,
                "Received IPv4 IPCP Configure-Nak from BRAS, confirming assignment"
            );
            v4.rebuild_req();
            session.send_ppp_frame(&v4.req_pkt).await?;
        }
        0x04 if id == v4.req_id => {
            warn!("BRAS rejected DNS options in IPv4 IPCP, retrying without DNS");
            v4.req_dns = false;
            v4.rebuild_req();
            session.send_ppp_frame(&v4.req_pkt).await?;
        }
        _ => {
            debug!(code, id, "Unhandled IPCP packet code");
        }
    }
    Ok(())
}

async fn handle_ipv6cp_code(
    session: &PppoeSession,
    code: u8,
    id: u8,
    data: &[u8],
    len: usize,
    v6: &mut IpcpV6State,
) -> Result<(), PppoeError> {
    match code {
        0x01 => {
            if let Some(peer_ll) = parse_peer_v6_ifid(data, len) {
                v6.peer_v6_ll = Some(peer_ll);
                info!(peer_ll = %peer_ll, "Extracted peer IPv6 link-local interface identifier");
            }
            let ack_pkt = build_ipv6cp_ack(id, data, len);
            session.send_ppp_frame(&ack_pkt).await?;
            v6.peer_ack_sent = true;
            info!("Acknowledged BRAS IPv6CP Configure-Request");
        }
        0x02 if id == v6.req_id => {
            v6.my_ack_received = true;
            info!(local_ll = %v6.local_v6_ll, "BRAS acknowledged our IPv6CP Configure-Request");
        }
        0x03 if id == v6.req_id => {
            if let Some(alt_ll) = parse_peer_v6_ifid(data, len) {
                v6.local_ifid.copy_from_slice(&alt_ll.octets()[8..16]);
            }
            v6.rebuild_req();
            session.send_ppp_frame(&v6.req_pkt).await?;
        }
        0x04 => {
            info!("BRAS rejected IPv6CP negotiation");
            v6.rejected = true;
        }
        _ => {
            debug!(code, id, "Unhandled IPv6CP packet code");
        }
    }
    Ok(())
}

async fn handle_lcp_echo(
    session: &PppoeSession,
    code: u8,
    id: u8,
    data: &[u8],
    len: usize,
) -> Result<(), PppoeError> {
    if code == LCP_ECHO_REQ {
        let mut rep = [0u8; 128];
        let payload_len = (len.saturating_sub(4)).min(120);
        rep[0..2].copy_from_slice(&PPP_LCP.to_be_bytes());
        rep[2] = LCP_ECHO_REP;
        rep[3] = id;
        #[allow(clippy::cast_possible_truncation)]
        let l = (4 + payload_len) as u16;
        rep[4..6].copy_from_slice(&l.to_be_bytes());
        rep[6..6 + payload_len].copy_from_slice(&data[6..6 + payload_len]);
        let _ = session.send_ppp_frame(&rep[..6 + payload_len]).await;
    }
    Ok(())
}

fn finalize_negotiation(
    v4: &IpcpV4State,
    v6: &IpcpV6State,
) -> Result<IpcpNegotiated, PppoeError> {
    let mut dns = Vec::new();
    if v4.assigned_dns1 != Ipv4Addr::UNSPECIFIED {
        dns.push(IpAddr::V4(v4.assigned_dns1));
    }
    if v4.assigned_dns2 != Ipv4Addr::UNSPECIFIED {
        dns.push(IpAddr::V4(v4.assigned_dns2));
    }

    let local_ip = if v4.my_ack_received && v4.assigned_ip != Ipv4Addr::UNSPECIFIED {
        Some(v4.assigned_ip)
    } else {
        None
    };

    let resolved_peer_ip = if local_ip.is_some() {
        if v4.peer_ip == Ipv4Addr::UNSPECIFIED {
            local_ip
        } else {
            Some(v4.peer_ip)
        }
    } else {
        None
    };

    let resolved_v6_ll = if v6.my_ack_received {
        Some(v6.local_v6_ll)
    } else {
        None
    };

    if local_ip.is_none() && resolved_v6_ll.is_none() {
        return Err(PppoeError::IpcpFailed(
            "Neither IPv4 nor IPv6 could be negotiated in IPCP phase".into(),
        ));
    }

    info!(
        ipv4 = ?local_ip,
        peer_v4 = ?resolved_peer_ip,
        dns_count = dns.len(),
        ipv6_ll = ?resolved_v6_ll,
        peer_v6_ll = ?v6.peer_v6_ll,
        "IPCP / IPv6CP negotiation complete"
    );

    Ok(IpcpNegotiated {
        local_ip,
        peer_ip: resolved_peer_ip,
        dns,
        local_v6_ll: resolved_v6_ll,
        peer_v6_ll: v6.peer_v6_ll,
    })
}

/// Unified concurrent IPCP (IPv4) and `IPv6CP` negotiation loop.
///
/// Both protocols run concurrently over the PPP session stream, preventing
/// packets of one protocol from being discarded while waiting for the other.
pub async fn negotiate_ipcp(
    session: &PppoeSession,
    local_mac: MacAddr,
) -> Result<IpcpNegotiated, PppoeError> {
    let mut v4 = IpcpV4State::new();
    let mut v6 = IpcpV6State::new(local_mac);

    session.send_ppp_frame(&v4.req_pkt).await?;
    session.send_ppp_frame(&v6.req_pkt).await?;

    let start = Instant::now();
    let total_timeout = Duration::from_secs(12);
    let mut last_retransmit = Instant::now();
    let retransmit_interval = Duration::from_millis(1500);

    let mut buf = [0u8; 1500];

    while start.elapsed() < total_timeout {
        if v4.is_done() && v6.is_done() {
            break;
        }

        if v4.is_done() && start.elapsed() > Duration::from_secs(4) {
            debug!("IPv4 negotiated successfully, IPv6CP negotiation finished/skipped");
            break;
        }

        if last_retransmit.elapsed() >= retransmit_interval {
            last_retransmit = Instant::now();
            if !v4.my_ack_received {
                v4.rebuild_req();
                let _ = session.send_ppp_frame(&v4.req_pkt).await;
            }
            if !v6.my_ack_received && !v6.rejected {
                v6.rebuild_req();
                let _ = session.send_ppp_frame(&v6.req_pkt).await;
            }
        }

        let Ok(Ok(n)) = timeout(Duration::from_millis(500), session.recv_ppp_frame(&mut buf)).await
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
        let code = data[2];
        let id = data[3];
        let len = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < 2 + len {
            continue;
        }

        match proto {
            PPP_IPCP => handle_ipcp_code(session, code, id, data, len, &mut v4).await?,
            PPP_IPV6CP => handle_ipv6cp_code(session, code, id, data, len, &mut v6).await?,
            PPP_LCP => handle_lcp_echo(session, code, id, data, len).await?,
            _ => {
                debug!(
                    proto = format_args!("{proto:#06x}"),
                    "Ignored packet during IPCP phase"
                );
            }
        }
    }

    finalize_negotiation(&v4, &v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipcp_nak() {
        // IPCP Configure-Nak:
        // 0x80 0x21 (Proto)
        // 0x03 (Code: Nak)
        // 0x01 (ID)
        // 0x00 0x16 (Len: 22)
        // Opt 3 (Len 6): 192.168.100.50
        // Opt 129 (Len 6): 1.1.1.1
        // Opt 131 (Len 6): 1.0.0.1
        let packet = vec![
            0x80, 0x21, // Proto
            0x03, // Code: Nak
            0x01, // ID
            0x00, 0x16, // Len: 22
            0x03, 0x06, 192, 168, 100, 50, // IP
            129, 0x06, 1, 1, 1, 1, // DNS1
            131, 0x06, 1, 0, 0, 1, // DNS2
        ];

        let mut ip = Ipv4Addr::UNSPECIFIED;
        let mut dns1 = Ipv4Addr::UNSPECIFIED;
        let mut dns2 = Ipv4Addr::UNSPECIFIED;

        parse_ipcp_nak(&packet, 22, &mut ip, &mut dns1, &mut dns2);

        assert_eq!(ip, Ipv4Addr::new(192, 168, 100, 50));
        assert_eq!(dns1, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(dns2, Ipv4Addr::new(1, 0, 0, 1));
    }

    #[test]
    fn test_parse_peer_ip() {
        let packet = vec![
            0x80, 0x21, // Proto
            0x01, // Code: Req
            0x01, // ID
            0x00, 0x0a, // Len: 10
            0x03, 0x06, 10, 0, 0, 1, // IP
        ];

        let peer = parse_peer_ip(&packet, 10);
        assert_eq!(peer, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_parse_peer_v6_ifid() {
        let packet = vec![
            0x80, 0x57, // Proto: IPv6CP
            0x01, // Code: Req
            0x01, // ID
            0x00, 0x0e, // Len: 14
            0x01, 0x0a, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // IFID
        ];

        let peer_v6 = parse_peer_v6_ifid(&packet, 14);
        assert!(peer_v6.is_some());
        let addr = peer_v6.unwrap();
        assert_eq!(addr.octets()[0], 0xfe);
        assert_eq!(addr.octets()[1], 0x80);
        assert_eq!(addr.octets()[8], 0x02);
        assert_eq!(addr.octets()[15], 0x77);
    }

    #[test]
    fn test_build_ipcp_req_with_dns() {
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        let dns1 = Ipv4Addr::new(1, 1, 1, 1);
        let dns2 = Ipv4Addr::new(8, 8, 8, 8);
        let pkt = build_ipcp_req(5, ip, dns1, dns2, true);
        assert_eq!(pkt.len(), 24);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), PPP_IPCP);
        assert_eq!(pkt[2], 0x01); // Conf-Req
        assert_eq!(pkt[3], 5); // ID
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 22); // Length
        assert_eq!(pkt[6], IPCP_OPT_IP);
        assert_eq!(pkt[7], 6);
        assert_eq!(&pkt[8..12], &ip.octets());
        assert_eq!(pkt[12], IPCP_OPT_DNS1);
        assert_eq!(pkt[13], 6);
        assert_eq!(&pkt[14..18], &dns1.octets());
        assert_eq!(pkt[18], IPCP_OPT_DNS2);
        assert_eq!(pkt[19], 6);
        assert_eq!(&pkt[20..24], &dns2.octets());
    }

    #[test]
    fn test_build_ipv6cp_req() {
        let ifid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pkt = build_ipv6cp_req(3, ifid);
        assert_eq!(pkt.len(), 16);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), PPP_IPV6CP);
        assert_eq!(pkt[2], 0x01);
        assert_eq!(pkt[3], 3);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 14);
        assert_eq!(pkt[6], IPV6CP_OPT_IFID);
        assert_eq!(pkt[7], 10);
        assert_eq!(&pkt[8..16], &ifid);
    }
}
