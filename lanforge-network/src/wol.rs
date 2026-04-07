use lanforge_core::identifiers::MacAddr;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

/// Sends a Wake-on-LAN Magic Packet to multiple targets for redundancy.
///
/// 1. Limited Broadcast: 255.255.255.255:9
/// 2. Directed Broadcast: If provided (e.g. 192.168.1.255:9)
/// 3. Unicast Fallback: If provided (the last known IP of the device)
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
