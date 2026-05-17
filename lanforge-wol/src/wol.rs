//! Wake-on-LAN (`WoL`) magic packet sender.
//!
//! Sends a `WoL` "magic packet" to wake up sleeping devices on the LAN.
//! For redundancy, the packet is sent to three targets:
//!
//! 1. **Directed broadcast** (e.g., `192.168.1.255:9`) — if provided
//! 2. **Unicast fallback** (device's last known IP) — if provided
//! 3. Both use a UDP socket bound to the target interface with `SO_BROADCAST`
//!
//! The magic packet format: 6 bytes of `0xFF` followed by 16 repetitions
//! of the target MAC address (total 102 bytes).

use lanforge_types::identifiers::MacAddr;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

/// Sends a Wake-on-LAN magic packet for the given MAC address.
///
/// # Arguments
///
/// * `mac` — target device's MAC address
/// * `interface` — network interface name (e.g., `"eth0"`) for socket binding
/// * `directed_broadcast` — optional directed broadcast address (e.g., `192.168.1.255`)
/// * `unicast_ip` — optional fallback unicast IP (device's last known address)
///
/// # Example
///
/// ```ignore
/// use lanforge_types::identifiers::MacAddr;
/// use lanforge_wol::wol::send_wol_magic_packet;
///
/// let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
/// send_wol_magic_packet(
///     mac,
///     "eth0",
///     Some("192.168.1.255".parse().unwrap()),
///     Some("192.168.1.100".parse().unwrap()),
/// ).unwrap();
/// ```
pub fn send_wol_magic_packet(
    mac: MacAddr,
    interface: &str,
    directed_broadcast: Option<Ipv4Addr>,
    unicast_ip: Option<Ipv4Addr>,
) -> io::Result<()> {
    let mut packet = [0u8; 102];
    packet[0..6].copy_from_slice(&[0xFF; 6]);
    for i in 0..16 {
        let start = 6 + i * 6;
        packet[start..start + 6].copy_from_slice(mac.as_bytes());
    }

    // Create a UDP socket using socket2 for better control
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_broadcast(true)?;

    // Bind to the specific interface if possible (Linux specific)
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = socket.bind_device(Some(interface.as_bytes())) {
            tracing::warn!("Failed to bind to device {interface}: {e}");
        }
    }

    let addr = SockAddr::from(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
    socket.bind(&addr)?;

    // 1. Directed Broadcast
    if let Some(bc) = directed_broadcast {
        let _ = socket.send_to(&packet, &SockAddr::from(SocketAddr::new(bc.into(), 9)));
    }

    // 2. Unicast Fallback
    if let Some(ip) = unicast_ip {
        let _ = socket.send_to(&packet, &SockAddr::from(SocketAddr::new(ip.into(), 9)));
    }

    Ok(())
}
