pub mod frame;

use crate::error::PppoeError;
use frame::{
    CODE_PADI, CODE_PADO, CODE_PADR, CODE_PADS, CODE_PADT, ETH_P_PPP_DISC, PppoeDiscoveryFrame,
    Tag, TAG_AC_COOKIE, TAG_AC_NAME, TAG_HOST_UNIQ, TAG_SERVICE_NAME,
};
use lanforge_types::identifiers::MacAddr;
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

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
    service_name: Option<String>,
    ac_name: Option<String>,
}

impl PppoeDiscovery {
    #[must_use]
    pub const fn new(
        ifindex: u32,
        local_mac: MacAddr,
        padi_retries: u32,
        padi_timeout_secs: u64,
        service_name: Option<String>,
        ac_name: Option<String>,
    ) -> Self {
        Self {
            ifindex,
            local_mac,
            padi_retries,
            padi_timeout_secs,
            service_name,
            ac_name,
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
            self.service_name.as_deref(),
            self.ac_name.as_deref(),
        )
        .await?;

        // 2. Send PADR and wait for PADS
        let session_id = exchange_padr(
            &async_fd,
            self.local_mac,
            ac_mac,
            ac_cookie.as_deref(),
            &host_uniq,
            self.service_name.as_deref(),
        )
        .await?;

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

#[allow(clippy::too_many_arguments)]
async fn exchange_padi(
    async_fd: &AsyncFd<OwnedFd>,
    local_mac: MacAddr,
    host_uniq: &[u8; 4],
    padi_retries: u32,
    padi_timeout_secs: u64,
    service_name: Option<&str>,
    ac_name_filter: Option<&str>,
) -> Result<(MacAddr, Option<String>, Option<Vec<u8>>), PppoeError> {
    let service_name_bytes = service_name.map_or_else(|| &[] as &[u8], str::as_bytes);
    let padi_frame = PppoeDiscoveryFrame {
        dst_mac: MacAddr([0xff; 6]),
        src_mac: local_mac,
        code: CODE_PADI,
        session_id: 0,
        tags: vec![
            Tag {
                tag_type: TAG_SERVICE_NAME,
                value: service_name_bytes,
            },
            Tag {
                tag_type: TAG_HOST_UNIQ,
                value: host_uniq,
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
                let mut buf = [0u8; 2048];
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
                            let mut frame_ac_name = None;
                            let mut frame_ac_cookie = None;
                            for tag in &frame.tags {
                                if tag.tag_type == TAG_AC_COOKIE {
                                    frame_ac_cookie = Some(tag.value.to_vec());
                                } else if tag.tag_type == TAG_AC_NAME {
                                    frame_ac_name = std::str::from_utf8(tag.value)
                                        .ok()
                                        .map(ToString::to_string);
                                }
                            }

                            if let Some(filter) = ac_name_filter
                                && frame_ac_name.as_deref() != Some(filter)
                            {
                                debug!(
                                    expected = filter,
                                    actual = ?frame_ac_name,
                                    "Ignoring PADO from non-matching Access Concentrator"
                                );
                                continue;
                            }

                            ac_mac = Some(frame.src_mac);
                            ac_name = frame_ac_name;
                            ac_cookie = frame_ac_cookie;
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
    ac_cookie: Option<&[u8]>,
    host_uniq: &[u8; 4],
    service_name: Option<&str>,
) -> Result<u16, PppoeError> {
    let service_name_bytes = service_name.map_or_else(|| &[] as &[u8], str::as_bytes);
    let mut padr_tags = vec![
        Tag {
            tag_type: TAG_SERVICE_NAME,
            value: service_name_bytes,
        },
        Tag {
            tag_type: TAG_HOST_UNIQ,
            value: host_uniq,
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
                let mut buf = [0u8; 2048];
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

    let c_ifname = CString::new(ifname)
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

    let bind_res = unsafe {
        libc::bind(
            raw_fd.as_raw_fd(),
            std::ptr::addr_of!(sll).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>()).unwrap(),
        )
    };
    if bind_res < 0 {
        warn!(error = %std::io::Error::last_os_error(), "Failed to bind raw socket for PADT");
    }

    // Transmit PADT frame in burst (3 frames spaced by 10ms) to guarantee BRAS receives termination
    for i in 0..3 {
        let sent = unsafe {
            libc::sendto(
                raw_fd.as_raw_fd(),
                bytes.as_ptr().cast::<libc::c_void>(),
                bytes.len(),
                0,
                std::ptr::addr_of!(sll).cast::<libc::sockaddr>(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>()).unwrap(),
            )
        };
        if sent < 0 {
            warn!(
                attempt = i + 1,
                error = %std::io::Error::last_os_error(),
                "Failed to transmit PPPoE PADT frame"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    info!(
        session_id,
        wan_iface = ifname,
        ac_mac = %ac_mac,
        "Transmitted PPPoE PADT termination frames to BRAS"
    );
    Ok(())
}
