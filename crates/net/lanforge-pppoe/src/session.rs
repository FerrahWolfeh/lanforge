use crate::error::PppoeError;
use lanforge_types::identifiers::MacAddr;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

pub const PX_PROTO_OE: u32 = 0;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PppoeAddr {
    pub sid: u16,
    pub remote: [u8; 6],
    pub dev: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SockAddrPppox {
    pub sa_family: u16,
    pub sa_protocol: u32,
    pub pppoe: PppoeAddr,
}

pub struct PppoeSession {
    async_fd: AsyncFd<OwnedFd>,
}

impl PppoeSession {
    pub fn connect(ifname: &str, ac_mac: MacAddr, session_id: u16) -> Result<Self, PppoeError> {
        let fd = socket(
            AddressFamily::Pppox,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )?;

        let mut dev_bytes = [0u8; 16];
        let c_ifname = CString::new(ifname).map_err(|_| {
            PppoeError::NegotiationFailed("Invalid interface name for CString".into())
        })?;
        let bytes = c_ifname.as_bytes();
        let len = bytes.len().min(15);
        dev_bytes[..len].copy_from_slice(&bytes[..len]);

        let addr = SockAddrPppox {
            sa_family: u16::try_from(libc::AF_PPPOX).unwrap(),
            sa_protocol: PX_PROTO_OE,
            pppoe: PppoeAddr {
                sid: session_id.to_be(),
                remote: ac_mac.0,
                dev: dev_bytes,
            },
        };

        let res = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                libc::socklen_t::try_from(std::mem::size_of::<SockAddrPppox>()).unwrap(),
            )
        };

        if res < 0 {
            return Err(PppoeError::Nix(nix::errno::Errno::last()));
        }

        let async_fd = AsyncFd::new(fd)?;

        Ok(Self { async_fd })
    }

    pub async fn send_ppp_frame(&self, frame: &[u8]) -> Result<(), PppoeError> {
        let mut guard = self.async_fd.writable().await?;
        let n = nix::unistd::write(self.async_fd.get_ref(), frame)?;
        guard.clear_ready();
        if n != frame.len() {
            return Err(PppoeError::NegotiationFailed(
                "Short write on PPPoE session socket".into(),
            ));
        }
        Ok(())
    }

    pub async fn recv_ppp_frame(&self, buf: &mut [u8]) -> Result<usize, PppoeError> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            match nix::unistd::read(self.async_fd.get_ref(), buf) {
                Ok(n) => {
                    guard.clear_ready();
                    return Ok(n);
                }
                Err(nix::errno::Errno::EWOULDBLOCK) => {
                    guard.clear_ready();
                }
                Err(e) => return Err(PppoeError::Nix(e)),
            }
        }
    }

    #[must_use]
    pub fn session_fd(&self) -> &OwnedFd {
        self.async_fd.get_ref()
    }
}
