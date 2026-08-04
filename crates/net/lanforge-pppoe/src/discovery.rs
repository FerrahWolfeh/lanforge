use crate::error::PppoeError;
use lanforge_types::identifiers::MacAddr;
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tracing::debug;

pub const ETH_P_PPP_DISC: u16 = 0x8863;

pub const CODE_PADI: u8 = 0x09;
pub const CODE_PADO: u8 = 0x07;
pub const CODE_PADR: u8 = 0x19;
pub const CODE_PADS: u8 = 0x65;
pub const CODE_PADT: u8 = 0xa7;

pub const TAG_SERVICE_NAME: u16 = 0x0101;
pub const TAG_AC_NAME: u16 = 0x0102;
pub const TAG_HOST_UNIQ: u16 = 0x0103;
pub const TAG_AC_COOKIE: u16 = 0x0104;

#[derive(Debug, Clone)]
pub struct Tag {
    pub tag_type: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PppoeDiscoveryFrame {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub code: u8,
    pub session_id: u16,
    pub tags: Vec<Tag>,
}

impl PppoeDiscoveryFrame {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        for tag in &self.tags {
            payload.extend_from_slice(&tag.tag_type.to_be_bytes());
            #[allow(clippy::cast_possible_truncation)]
            let len = tag.value.len() as u16;
            payload.extend_from_slice(&len.to_be_bytes());
            payload.extend_from_slice(&tag.value);
        }

        let mut packet = Vec::with_capacity(14 + 6 + payload.len());
        packet.extend_from_slice(&self.dst_mac.0);
        packet.extend_from_slice(&self.src_mac.0);
        packet.extend_from_slice(&ETH_P_PPP_DISC.to_be_bytes());
        packet.push(0x11); // Ver: 1, Type: 1
        packet.push(self.code);
        packet.extend_from_slice(&self.session_id.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        let payload_len = payload.len() as u16;
        packet.extend_from_slice(&payload_len.to_be_bytes());
        packet.extend_from_slice(&payload);
        packet
    }

    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }

        let dst_mac = MacAddr(bytes[0..6].try_into().ok()?);
        let src_mac = MacAddr(bytes[6..12].try_into().ok()?);

        let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
        if ethertype != ETH_P_PPP_DISC {
            return None;
        }

        let ver_type = bytes[14];
        if ver_type != 0x11 {
            return None;
        }

        let code = bytes[15];
        let session_id = u16::from_be_bytes([bytes[16], bytes[17]]);
        let payload_len = u16::from_be_bytes([bytes[18], bytes[19]]) as usize;

        if bytes.len() < 20 + payload_len {
            return None;
        }

        let mut tags = Vec::new();
        let mut offset = 20;
        let end = 20 + payload_len;

        while offset + 4 <= end {
            let tag_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let tag_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4;

            if offset + tag_len > end {
                break;
            }

            let value = bytes[offset..offset + tag_len].to_vec();
            offset += tag_len;

            tags.push(Tag { tag_type, value });
        }

        Some(Self {
            dst_mac,
            src_mac,
            code,
            session_id,
            tags,
        })
    }
}

#[derive(Debug)]
pub struct DiscoveryResult {
    pub ac_mac: MacAddr,
    pub ac_name: Option<String>,
    pub session_id: u16,
}

pub struct PppoeDiscovery {
    ifindex: u32,
    local_mac: MacAddr,
    padi_retries: u32,
    padi_timeout_secs: u64,
}

impl PppoeDiscovery {
    #[must_use]
    pub const fn new(
        ifindex: u32,
        local_mac: MacAddr,
        padi_retries: u32,
        padi_timeout_secs: u64,
    ) -> Self {
        Self {
            ifindex,
            local_mac,
            padi_retries,
            padi_timeout_secs,
        }
    }

    #[allow(clippy::similar_names)]
    pub async fn run(&self) -> Result<DiscoveryResult, PppoeError> {
        let fd = bind_discovery_socket(self.ifindex)?;
        let async_fd = AsyncFd::new(fd)?;
        let host_uniq: [u8; 4] = rand::random();

        // 1. Send PADI and wait for PADO
        let (ac_mac, ac_name, ac_cookie) = exchange_padi(
            &async_fd,
            self.local_mac,
            &host_uniq,
            self.padi_retries,
            self.padi_timeout_secs,
        )
        .await?;

        // 2. Send PADR and wait for PADS
        let session_id =
            exchange_padr(&async_fd, self.local_mac, ac_mac, ac_cookie, &host_uniq).await?;

        Ok(DiscoveryResult {
            ac_mac,
            ac_name,
            session_id,
        })
    }
}

fn bind_discovery_socket(ifindex: u32) -> Result<OwnedFd, PppoeError> {
    let fd = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::EthAll,
    )?;

    let saddr = libc::sockaddr_ll {
        sll_family: u16::try_from(libc::AF_PACKET).unwrap(),
        sll_protocol: ETH_P_PPP_DISC.to_be(),
        sll_ifindex: ifindex.cast_signed(),
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0; 8],
    };

    let res = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(saddr).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>()).unwrap(),
        )
    };

    if res < 0 {
        return Err(PppoeError::Nix(nix::errno::Errno::last()));
    }

    Ok(fd)
}

async fn exchange_padi(
    async_fd: &AsyncFd<OwnedFd>,
    local_mac: MacAddr,
    host_uniq: &[u8; 4],
    padi_retries: u32,
    padi_timeout_secs: u64,
) -> Result<(MacAddr, Option<String>, Option<Vec<u8>>), PppoeError> {
    let padi_frame = PppoeDiscoveryFrame {
        dst_mac: MacAddr([0xff; 6]),
        src_mac: local_mac,
        code: CODE_PADI,
        session_id: 0,
        tags: vec![
            Tag {
                tag_type: TAG_SERVICE_NAME,
                value: Vec::new(),
            },
            Tag {
                tag_type: TAG_HOST_UNIQ,
                value: host_uniq.to_vec(),
            },
        ],
    };

    let padi_bytes = padi_frame.encode();

    let mut ac_mac = None;
    let mut ac_name = None;
    let mut ac_cookie = None;

    for attempt in 0..padi_retries {
        debug!(attempt, "Sending PPPoE PADI frame...");
        let guard = async_fd.writable().await?;
        let _ = nix::unistd::write(async_fd.get_ref(), &padi_bytes);
        drop(guard);

        // Wait for PADO
        let timeout = Duration::from_secs(padi_timeout_secs);
        let start = tokio::time::Instant::now();

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if let Ok(Ok(mut guard)) = tokio::time::timeout(remaining, async_fd.readable()).await {
                let mut buf = [0u8; 1500];
                if let Ok(n) = nix::unistd::read(async_fd.get_ref(), &mut buf) {
                    guard.clear_ready();
                    if let Some(frame) = PppoeDiscoveryFrame::parse(&buf[..n])
                        && frame.code == CODE_PADO
                    {
                        // Verify host_uniq
                        let matches_uniq = frame
                            .tags
                            .iter()
                            .any(|t| t.tag_type == TAG_HOST_UNIQ && t.value == host_uniq);
                        if matches_uniq {
                            ac_mac = Some(frame.src_mac);
                            for tag in frame.tags {
                                if tag.tag_type == TAG_AC_COOKIE {
                                    ac_cookie = Some(tag.value);
                                } else if tag.tag_type == TAG_AC_NAME {
                                    ac_name = String::from_utf8(tag.value).ok();
                                }
                            }
                            debug!("Received valid PPPoE PADO frame");
                            break;
                        }
                    }
                }
            }
        }

        if ac_mac.is_some() {
            break;
        }
    }

    let ac_mac = ac_mac.ok_or(PppoeError::DiscoveryTimeout)?;
    Ok((ac_mac, ac_name, ac_cookie))
}

async fn exchange_padr(
    async_fd: &AsyncFd<OwnedFd>,
    local_mac: MacAddr,
    ac_mac: MacAddr,
    ac_cookie: Option<Vec<u8>>,
    host_uniq: &[u8; 4],
) -> Result<u16, PppoeError> {
    let mut padr_tags = vec![
        Tag {
            tag_type: TAG_SERVICE_NAME,
            value: Vec::new(),
        },
        Tag {
            tag_type: TAG_HOST_UNIQ,
            value: host_uniq.to_vec(),
        },
    ];
    if let Some(cookie) = ac_cookie {
        padr_tags.push(Tag {
            tag_type: TAG_AC_COOKIE,
            value: cookie,
        });
    }

    let padr_frame = PppoeDiscoveryFrame {
        dst_mac: ac_mac,
        src_mac: local_mac,
        code: CODE_PADR,
        session_id: 0,
        tags: padr_tags,
    };
    let padr_bytes = padr_frame.encode();

    let mut session_id = None;

    for attempt in 0..3 {
        debug!(attempt, "Sending PPPoE PADR frame...");
        let guard = async_fd.writable().await?;
        let _ = nix::unistd::write(async_fd.get_ref(), &padr_bytes);
        drop(guard);

        // Wait for PADS
        let timeout = Duration::from_secs(3);
        let start = tokio::time::Instant::now();

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if let Ok(Ok(mut guard)) = tokio::time::timeout(remaining, async_fd.readable()).await {
                let mut buf = [0u8; 1500];
                if let Ok(n) = nix::unistd::read(async_fd.get_ref(), &mut buf) {
                    guard.clear_ready();
                    if let Some(frame) = PppoeDiscoveryFrame::parse(&buf[..n])
                        && frame.code == CODE_PADS
                    {
                        let matches_uniq = frame
                            .tags
                            .iter()
                            .any(|t| t.tag_type == TAG_HOST_UNIQ && t.value == host_uniq);
                        if matches_uniq {
                            session_id = Some(frame.session_id);
                            debug!(session_id = frame.session_id, "Received PPPoE PADS frame");
                            break;
                        }
                    }
                }
            }
        }

        if session_id.is_some() {
            break;
        }
    }

    session_id.ok_or(PppoeError::DiscoveryTimeout)
}

pub fn send_padt(
    ifname: &str,
    wan_mac: MacAddr,
    ac_mac: MacAddr,
    session_id: u16,
) -> Result<(), PppoeError> {
    let frame = PppoeDiscoveryFrame {
        dst_mac: ac_mac,
        src_mac: wan_mac,
        code: CODE_PADT,
        session_id,
        tags: vec![],
    };

    let raw_fd = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        Some(SockProtocol::EthAll),
    )?;

    let c_ifname = std::ffi::CString::new(ifname)
        .map_err(|_| PppoeError::NegotiationFailed("Invalid interface name for CString".into()))?;
    let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
    if ifindex == 0 {
        return Err(PppoeError::NegotiationFailed("Interface not found".into()));
    }

    let bytes = frame.encode();
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = u16::try_from(libc::AF_PACKET).unwrap();
    sll.sll_ifindex = ifindex.cast_signed();
    sll.sll_protocol = ETH_P_PPP_DISC.to_be();
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&ac_mac.0);

    unsafe {
        libc::sendto(
            raw_fd.as_raw_fd(),
            bytes.as_ptr().cast::<libc::c_void>(),
            bytes.len(),
            0,
            std::ptr::addr_of!(sll).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>()).unwrap(),
        );
    }
    debug!(session_id, "Sent PPPoE PADT frame to server");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_frame_encode_parse() {
        let frame = PppoeDiscoveryFrame {
            dst_mac: MacAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            src_mac: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            code: CODE_PADI,
            session_id: 0,
            tags: vec![
                Tag {
                    tag_type: TAG_SERVICE_NAME,
                    value: vec![],
                },
                Tag {
                    tag_type: TAG_HOST_UNIQ,
                    value: vec![1, 2, 3, 4],
                },
            ],
        };

        let encoded = frame.encode();
        let parsed = PppoeDiscoveryFrame::parse(&encoded).expect("parse frame");

        assert_eq!(parsed.dst_mac, frame.dst_mac);
        assert_eq!(parsed.src_mac, frame.src_mac);
        assert_eq!(parsed.code, CODE_PADI);
        assert_eq!(parsed.session_id, 0);
        assert_eq!(parsed.tags.len(), 2);
        assert_eq!(parsed.tags[1].value, vec![1, 2, 3, 4]);
    }
}
