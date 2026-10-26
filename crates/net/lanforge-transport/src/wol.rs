//! Wake-on-LAN (`WoL`) magic packet sender.
//!
//! Sends a `WoL` "magic packet" to wake up sleeping devices on the LAN.
//! For redundancy, the packet is sent to three targets:
//!
//! 1. **Limited broadcast** (`255.255.255.255:9`)
//! 2. **Directed broadcast** (e.g., `192.168.1.255:9`) — if provided
//! 3. **Unicast fallback** (device's last known IP) — if provided
//!
//! Both use a UDP socket bound to the target interface with `SO_BROADCAST`.
//!
//! The magic packet format: 6 bytes of `0xFF` followed by 16 repetitions
//! of the target MAC address (total 102 bytes).

use lanforge_types::identifiers::MacAddr;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

/// Builds a 102-byte Wake-on-LAN magic packet payload.
///
/// The payload consists of 6 bytes of `0xFF` synchronization stream followed by
/// 16 repetitions of the target 6-byte MAC address (RFC compliant format).
#[must_use]
pub fn build_magic_packet(mac: MacAddr) -> [u8; 102] {
    let mut packet = [0xFFu8; 102];
    for chunk in packet[6..].as_chunks_mut::<6>().0 {
        *chunk = mac.0;
    }
    packet
}

/// Sends a Wake-on-LAN magic packet for the given MAC address.
///
/// # Arguments
///
/// * `mac` — target device's MAC address
/// * `interface` — network interface name (e.g., `"eth0"`) for socket binding
/// * `directed_broadcast` — optional directed broadcast address (e.g., `192.168.1.255`)
/// * `unicast_ip` — optional fallback unicast IP (device's last known address)
pub fn send_wol_magic_packet(
    mac: MacAddr,
    interface: &str,
    directed_broadcast: Option<Ipv4Addr>,
    unicast_ip: Option<Ipv4Addr>,
) -> io::Result<()> {
    let packet = build_magic_packet(mac);

    // Create a UDP socket using socket2 for better control
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_broadcast(true)?;

    // Bind to the specific interface if possible (Linux specific)
    #[cfg(target_os = "linux")]
    {
        if !interface.is_empty()
            && let Err(e) = socket.bind_device(Some(interface.as_bytes()))
        {
            tracing::warn!("Failed to bind to device {interface}: {e}");
        }
    }

    let addr = SockAddr::from(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
    socket.bind(&addr)?;

    // 1. Limited Broadcast (255.255.255.255:9)
    let _ = socket.send_to(
        &packet,
        &SockAddr::from(SocketAddr::new(Ipv4Addr::BROADCAST.into(), 9)),
    );

    // 2. Directed Broadcast
    if let Some(bc) = directed_broadcast
        && bc != Ipv4Addr::BROADCAST
    {
        let _ = socket.send_to(&packet, &SockAddr::from(SocketAddr::new(bc.into(), 9)));
    }

    // 3. Unicast Fallback
    if let Some(ip) = unicast_ip {
        let _ = socket.send_to(&packet, &SockAddr::from(SocketAddr::new(ip.into(), 9)));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_magic_packet() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let packet = build_magic_packet(mac);

        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[0..6], &[0xFF; 6]);

        for i in 0..16 {
            let start = 6 + i * 6;
            assert_eq!(&packet[start..start + 6], mac.as_bytes());
        }
    }
}
