use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::error::LabError;
use crate::report::{RaDecodedInfo, RaPrefixReport};

const ICMPV6_TYPE_RS: u8 = 133;
const ICMPV6_TYPE_RA: u8 = 134;

/// Engine for sending IPv6 Router Solicitations and decoding Router Advertisements.
pub struct RaEngine {
    iface: Option<String>,
    timeout_duration: Duration,
}

impl RaEngine {
    #[must_use]
    pub const fn new(iface: Option<String>) -> Self {
        Self {
            iface,
            timeout_duration: Duration::from_secs(4),
        }
    }

    /// Sends a Router Solicitation (RS) and awaits a Router Advertisement (RA).
    ///
    /// Requires `CAP_NET_RAW` (or root). Returns `Err(LabError::Socket)` if unprivileged.
    pub async fn send_rs_and_await_ra(&self) -> Result<RaDecodedInfo, LabError> {
        let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
            .map_err(|e| LabError::Socket(format!("Raw ICMPv6 socket requires CAP_NET_RAW: {e}")))?;

        if let Some(iface) = &self.iface {
            let _ = sock.bind_device(Some(iface.as_bytes()));
        }

        let _ = sock.set_multicast_hops_v6(255);
        let _ = sock.set_nonblocking(true);

        let async_fd = tokio::io::unix::AsyncFd::new(sock)
            .map_err(|e| LabError::Socket(format!("AsyncFd error: {e}")))?;

        // Build RS packet (Type: 133, Code: 0, Checksum: 0 (kernel calculates), Reserved: 0)
        let rs_packet = [ICMPV6_TYPE_RS, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let dst_sa = socket2::SockAddr::from(std::net::SocketAddrV6::new(
            "ff02::2".parse().unwrap(),
            0,
            0,
            0,
        ));

        let start = Instant::now();
        let _ = async_fd.get_ref().send_to(&rs_packet, &dst_sa);

        let mut buf = [0u8; 1500];

        let res = tokio::time::timeout(self.timeout_duration, async {
            loop {
                let mut guard = async_fd.readable().await.map_err(LabError::Io)?;
                let res = guard
                    .get_inner()
                    .recv_from(unsafe { &mut *(&raw mut buf).cast::<[std::mem::MaybeUninit<u8>; 1500]>() });

                match res {
                    Ok((n, src_sa)) => {
                        guard.clear_ready();
                        if n >= 16 && buf[0] == ICMPV6_TYPE_RA {
                            let src_ip = src_sa.as_socket().and_then(|s| match s {
                                std::net::SocketAddr::V6(v6) => Some(*v6.ip()),
                                std::net::SocketAddr::V4(_) => None,
                            }).unwrap_or(Ipv6Addr::UNSPECIFIED);

                            return Ok(Self::parse_ra(&buf[..n], src_ip, start.elapsed().as_secs_f64() * 1000.0));
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        guard.clear_ready();
                    }
                    Err(e) => return Err(LabError::Io(e)),
                }
            }
        }).await;

        res.unwrap_or_else(|_| Err(LabError::Timeout("Router Advertisement (RA)".to_string())))
    }

    fn parse_ra(data: &[u8], router_ip: Ipv6Addr, latency_ms: f64) -> RaDecodedInfo {
        let cur_hop_limit = data[4];
        let flags = data[5];
        let managed_flag = (flags & 0x80) != 0;
        let other_config_flag = (flags & 0x40) != 0;
        let router_lifetime_secs = u16::from_be_bytes([data[6], data[7]]);
        let reachable_time_ms = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let retrans_timer_ms = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        let mut prefixes = Vec::new();
        let mut rdnss_servers = Vec::new();
        let mut dnssl_domains = Vec::new();

        let mut offset = 16;
        while offset + 2 <= data.len() {
            let opt_type = data[offset];
            let opt_len = data[offset + 1] as usize * 8;
            if opt_len == 0 || offset + opt_len > data.len() {
                break;
            }
            let opt_data = &data[offset..offset + opt_len];

            match opt_type {
                // Prefix Information Option (PIO)
                3 if opt_len >= 32 => {
                    let prefix_len = opt_data[2];
                    let p_flags = opt_data[3];
                    let on_link = (p_flags & 0x80) != 0;
                    let auto_config = (p_flags & 0x40) != 0;
                    let valid_lifetime = u32::from_be_bytes([opt_data[4], opt_data[5], opt_data[6], opt_data[7]]);
                    let preferred_lifetime = u32::from_be_bytes([opt_data[8], opt_data[9], opt_data[10], opt_data[11]]);

                    let mut p_bytes = [0u8; 16];
                    p_bytes.copy_from_slice(&opt_data[16..32]);
                    let prefix = Ipv6Addr::from(p_bytes);

                    prefixes.push(RaPrefixReport {
                        prefix,
                        prefix_len,
                        on_link,
                        auto_config,
                        valid_lifetime_secs: valid_lifetime,
                        preferred_lifetime_secs: preferred_lifetime,
                    });
                }
                // RDNSS Option
                25 if opt_len >= 24 => {
                    let mut srv_offset = 8;
                    while srv_offset + 16 <= opt_len {
                        let mut s_bytes = [0u8; 16];
                        s_bytes.copy_from_slice(&opt_data[srv_offset..srv_offset + 16]);
                        rdnss_servers.push(Ipv6Addr::from(s_bytes));
                        srv_offset += 16;
                    }
                }
                // DNSSL Option
                31 if opt_len >= 8 => {
                    if let Ok(s) = std::str::from_utf8(&opt_data[8..]) {
                        for domain in s.split('\0').filter(|d| !d.is_empty()) {
                            dnssl_domains.push(domain.to_string());
                        }
                    }
                }
                _ => {}
            }
            offset += opt_len;
        }

        RaDecodedInfo {
            router_ip,
            cur_hop_limit,
            managed_flag,
            other_config_flag,
            router_lifetime_secs,
            reachable_time_ms,
            retrans_timer_ms,
            prefixes,
            rdnss_servers,
            dnssl_domains,
            latency_ms,
        }
    }
}
