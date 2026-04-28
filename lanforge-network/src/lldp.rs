//! LLDP (`Link Layer Discovery Protocol`) monitor.
//!
//! Listens for LLDP packets (`EtherType` `0x88cc`) on the target interface
//! to discover infrastructure devices (switches, APs) and their ports.
//!
//! ## Discovery Flow
//!
//! 1. Open raw `AF_PACKET` socket for `EtherType` `0x88cc`.
//! 2. Parse Chassis ID (Parent MAC) and Port ID (Parent Port).
//! 3. Apply `DeviceUpdate::TopologyUpdated` to the central context.

use std::os::unix::io::AsRawFd;
use std::ptr::from_mut;

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::service::AsyncService;
use lanforge_core::state::DeviceUpdate;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tracing::{debug, error, info, warn};

use crate::error::NetworkError;

/// Monitors LLDP advertisements to discover network topology.
#[lanforge_macros::lanforge_service(
    id = "lldp",
    name = "LLDP Monitor",
    critical = false,
    retries = 5,
    base_backoff = 5,
    max_backoff = 60
)]
pub struct LldpMonitor {
    iface: String,
    ifindex: u32,
    ctx: LanforgeContext,
}

impl LldpMonitor {
    /// Creates a new `LldpMonitor` for the given interface.
    #[must_use]
    pub const fn new(iface: String, ifindex: u32, ctx: LanforgeContext) -> Self {
        Self {
            iface,
            ifindex,
            ctx,
        }
    }
}

impl AsyncService for LldpMonitor {
    async fn run(&mut self) -> Result<(), CoreError> {
        let socket = create_lldp_socket(&self.iface).map_err(|e| {
            error!("Failed to create LLDP socket: {e}");
            CoreError::Generic(e.to_string())
        })?;
        socket.set_nonblocking(true).map_err(CoreError::Io)?;
        let async_fd = AsyncFd::new(socket).map_err(CoreError::Io)?;

        info!("LLDP Monitor started on {}", self.iface);

        let mut buf = [0u8; 2048];

        loop {
            if !self.ctx.is_running() {
                break;
            }

            let mut guard = async_fd.readable().await.map_err(CoreError::Io)?;
            let uninit_buf =
                unsafe { &mut *(from_mut(&mut buf).cast::<[std::mem::MaybeUninit<u8>; 2048]>()) };

            match guard.get_inner().recv(uninit_buf) {
                Ok(n) if n > 0 => {
                    guard.clear_ready();
                    if let Some(eth) = EthernetPacket::new(&buf[..n]) {
                        let s = eth.get_source();
                        let src_mac = MacAddr([s.0, s.1, s.2, s.3, s.4, s.5]);
                        if let Some((parent_mac, port)) = parse_lldp_payload(eth.payload()) {
                            debug!(
                                "LLDP: Device {} is behind parent {:?} on port {:?}",
                                src_mac, parent_mac, port
                            );
                            let _ = self.ctx.apply(&DeviceUpdate::TopologyUpdated {
                                mac: src_mac,
                                parent_mac,
                                port,
                                ifindex: self.ifindex,
                            });
                        }
                    }
                }
                Ok(_) => {
                    guard.clear_ready();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                }
                Err(e) => {
                    warn!("LLDP socket recv error: {e}");
                    break;
                }
            }
        }

        Ok(())
    }
}

fn create_lldp_socket(iface: &str) -> Result<Socket, NetworkError> {
    // Protocol 0x88cc in network byte order
    let proto = i32::from(0x88ccu16.to_be());
    let sock = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(proto)))
        .map_err(|e| NetworkError::Socket(format!("PF_PACKET socket: {e}")))?;

    // Bind to specific interface
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = u16::try_from(libc::AF_PACKET).unwrap_or(0);
    addr.sll_protocol = 0x88ccu16.to_be();
    addr.sll_ifindex = unsafe {
        let ifname = std::ffi::CString::new(iface).unwrap();
        libc::if_nametoindex(ifname.as_ptr()).cast_signed()
    };

    let res = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            from_mut(&mut addr).cast_const().cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>()).unwrap(),
        )
    };

    if res != 0 {
        return Err(NetworkError::Socket(format!(
            "bind to {iface}: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(sock)
}

/// Parses an LLDP payload to extract Chassis ID and Port ID.
///
/// Returns `Option<(Parent MAC, Port Name)>`.
fn parse_lldp_payload(data: &[u8]) -> Option<(Option<MacAddr>, Option<String>)> {
    let mut chassis_id = None;
    let mut port_id = None;
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let header = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let tlv_type = (header >> 9) as u8;
        let tlv_len = (header & 0x01FF) as usize;
        pos += 2;

        if pos + tlv_len > data.len() {
            break;
        }

        let value = &data[pos..pos + tlv_len];
        match tlv_type {
            0 => break, // End of LLDPDU
            1
                // Chassis ID
                if value.len() == 7 && value[0] == 4 => {
                    // MAC address
                    chassis_id = Some(MacAddr(value[1..7].try_into().unwrap()));
                }
            2 if value.len() >= 2 => {
                // Port ID
                match value[0] {
                    3 if value.len() == 7 => {
                        // MAC address
                        port_id = Some(MacAddr(value[1..7].try_into().unwrap()).to_string());
                    }
                    5 | 7 => {
                        // Interface name or locally assigned
                        port_id = Some(String::from_utf8_lossy(&value[1..]).to_string());
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        pos += tlv_len;
    }

    if chassis_id.is_some() || port_id.is_some() {
        Some((chassis_id, port_id))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lldp_basic() {
        // Chassis ID TLV: Type 1, Len 7, Subtype 4 (MAC), MAC 00:11:22:33:44:55
        // (1 << 9) | 7 = 0x0207
        // Port ID TLV: Type 2, Len 5, Subtype 5 (Interface Name), Name "eth0"
        // (2 << 9) | 5 = 0x0405
        // End of LLDPDU: Type 0, Len 0
        let data = [
            0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x04, 0x05, 0x05, 0x65, 0x74,
            0x68, 0x30, 0x00, 0x00,
        ];

        let res = parse_lldp_payload(&data);
        assert!(res.is_some());
        let (chassis, port) = res.unwrap();
        assert_eq!(chassis.unwrap().to_string(), "00:11:22:33:44:55");
        assert_eq!(port.unwrap(), "eth0");
    }

    #[test]
    fn test_parse_lldp_empty() {
        let data = [0x00, 0x00];
        let res = parse_lldp_payload(&data);
        assert!(res.is_none());
    }
}
