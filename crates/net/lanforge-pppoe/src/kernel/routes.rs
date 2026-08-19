use crate::error::PppoeError;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use rtnetlink::packet_route::address::{AddressAttribute, AddressHeaderFlags};
use rtnetlink::packet_route::route::RouteScope;
use rtnetlink::RouteMessageBuilder;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use tokio::process::Command;
use tracing::{debug, warn};

nix::ioctl_write_ptr_bad!(siocsifaddr, 0x8916, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifdstaddr, 0x8918, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifnetmask, 0x891c, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifmtu, 0x8922, libc::ifreq);
nix::ioctl_read_bad!(siocgifflags, 0x8913, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifflags, 0x8914, libc::ifreq);

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn setup_interface_ifreq(
    ifname: &str,
    mtu: u16,
    local_ip: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
) -> Result<u32, PppoeError> {
    let c_ifname = CString::new(ifname)
        .map_err(|_| PppoeError::NegotiationFailed("Invalid interface name for CString".into()))?;
    let bytes = c_ifname.as_bytes();
    let len = bytes.len().min(15);

    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;

    // Set MTU:
    // - For virtual ppp interfaces (e.g. ppp0), MTU is the negotiated PPPoE MRU (1492).
    // - For physical/Ethernet interfaces in eBPF mode (e.g. wan0), the physical interface MTU must be 1500
    //   so that the 1492-byte IP packet + 8-byte PPPoE header (1500 bytes total) is transmitted without driver drops.
    let dev_mtu = if ifname.starts_with("ppp") {
        mtu
    } else {
        1500
    };
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, &b) in bytes[..len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_mtu = libc::c_int::from(dev_mtu);
    unsafe {
        siocsifmtu(sock.as_raw_fd(), &raw const ifr)?;
    }

    // Only adjust flags for virtual ppp interfaces (e.g. ppp0), leaving physical/veth WAN links untouched
    if ifname.starts_with("ppp") {
        let mut ifr_flags: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, &b) in bytes[..len].iter().enumerate() {
            ifr_flags.ifr_name[i] = b as libc::c_char;
        }
        unsafe {
            siocgifflags(sock.as_raw_fd(), &raw mut ifr_flags)?;
            ifr_flags.ifr_ifru.ifru_flags |=
                (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_POINTOPOINT) as i16;
            siocsifflags(sock.as_raw_fd(), &raw const ifr_flags)?;
        }
    }

    // Set Local & Peer IPv4 Address
    if let (Some(local), Some(peer)) = (local_ip, peer_ip) {
        let mut ifr_addr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, &b) in bytes[..len].iter().enumerate() {
            ifr_addr.ifr_name[i] = b as libc::c_char;
        }
        let sin = unsafe {
            &mut *std::ptr::addr_of_mut!(ifr_addr.ifr_ifru.ifru_addr).cast::<libc::sockaddr_in>()
        };
        sin.sin_family = libc::AF_INET as u16;
        sin.sin_addr.s_addr = u32::from_ne_bytes(local.octets());
        unsafe {
            siocsifaddr(sock.as_raw_fd(), &raw const ifr_addr)?;
        }

        // Set /32 netmask (255.255.255.255) to prevent default classful subnet assignment
        let mut ifr_mask: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, &b) in bytes[..len].iter().enumerate() {
            ifr_mask.ifr_name[i] = b as libc::c_char;
        }
        let sin_mask = unsafe {
            &mut *std::ptr::addr_of_mut!(ifr_mask.ifr_ifru.ifru_netmask).cast::<libc::sockaddr_in>()
        };
        sin_mask.sin_family = libc::AF_INET as u16;
        sin_mask.sin_addr.s_addr = u32::from_ne_bytes([255, 255, 255, 255]);
        unsafe {
            siocsifnetmask(sock.as_raw_fd(), &raw const ifr_mask)?;
        }

        if ifname.starts_with("ppp") {
            let mut ifr_dst: libc::ifreq = unsafe { std::mem::zeroed() };
            for (i, &b) in bytes[..len].iter().enumerate() {
                ifr_dst.ifr_name[i] = b as libc::c_char;
            }
            let sin_dst = unsafe {
                &mut *std::ptr::addr_of_mut!(ifr_dst.ifr_ifru.ifru_dstaddr)
                    .cast::<libc::sockaddr_in>()
            };
            sin_dst.sin_family = libc::AF_INET as u16;
            sin_dst.sin_addr.s_addr = u32::from_ne_bytes(peer.octets());
            unsafe {
                siocsifdstaddr(sock.as_raw_fd(), &raw const ifr_dst)?;
            }
        }
    }

    let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
    Ok(ifindex)
}

pub async fn add_ipv4_peer_route(
    ifname: &str,
    ifindex: u32,
    peer: Ipv4Addr,
    local: Option<Ipv4Addr>,
) {
    match rtnetlink::new_connection() {
        Err(e) => warn!(error = %e, "Failed to open rtnetlink connection for peer route"),
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(peer, 32)
                .output_interface(ifindex)
                .scope(RouteScope::Link)
                .priority(50);
            if let Some(src) = local {
                builder = builder.source_prefix(src, 32);
            }
            let route = builder.build();
            let result = handle.route().add(route).replace().execute().await;
            if let Err(e) = result
                && !e.to_string().contains("File exists")
            {
                warn!(error = %e, "Failed to install IPv4 on-link peer route");
            }
        }
    }

    let mut cmd = Command::new("ip");
    cmd.args([
        "route",
        "replace",
        &format!("{peer}/32"),
        "dev",
        ifname,
        "scope",
        "link",
        "metric",
        "50",
        "mtu",
        "1492",
        "advmss",
        "1452",
    ]);
    if let Some(src) = local {
        cmd.args(["src", &src.to_string()]);
    }
    let _ = cmd.output().await;
}

pub async fn add_static_neighbour(ifname: &str, peer: Ipv4Addr, mac: [u8; 6]) {
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    let result = Command::new("ip")
        .args([
            "neigh",
            "replace",
            &peer.to_string(),
            "dev",
            ifname,
            "lladdr",
            &mac_str,
            "nud",
            "permanent",
        ])
        .status()
        .await;
    match result {
        Ok(s) if s.success() => {
            debug!(
                ifname,
                peer = %peer,
                mac = %mac_str,
                "Installed static neighbour entry for peer gateway"
            );
        }
        Err(e) => {
            warn!(error = %e, "Failed to run ip neigh replace for peer gateway");
        }
        _ => {}
    }
}

pub async fn add_ipv4_default_route(ifname: &str, ifindex: u32, peer: Ipv4Addr) {
    match rtnetlink::new_connection() {
        Err(e) => warn!(error = %e, "Failed to open rtnetlink connection for route"),
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .gateway(peer)
                .output_interface(ifindex)
                .priority(100)
                .build();
            let result = handle.route().add(route).replace().execute().await;
            if let Err(e) = result
                && !e.to_string().contains("File exists")
            {
                warn!(error = %e, "Failed to install IPv4 default route");
            }
        }
    }

    let _ = Command::new("ip")
        .args([
            "route",
            "replace",
            "default",
            "via",
            &peer.to_string(),
            "dev",
            ifname,
            "metric",
            "100",
            "mtu",
            "1492",
            "advmss",
            "1452",
        ])
        .output()
        .await;
}

#[allow(clippy::too_many_lines)]
pub async fn add_ipv6_link_local(
    ifname: &str,
    ifindex: u32,
    v6_ll: Ipv6Addr,
    peer_v6_ll: Option<Ipv6Addr>,
    peer_mac: Option<[u8; 6]>,
) {
    match rtnetlink::new_connection() {
        Err(e) => warn!(error = %e, "Failed to open rtnetlink connection for IPv6 addr"),
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            let mut req = handle.address().add(ifindex, IpAddr::V6(v6_ll), 64);
            req.message_mut().header.flags |= AddressHeaderFlags::Nodad;
            if let Some(peer) = peer_v6_ll {
                req.message_mut()
                    .attributes
                    .push(AddressAttribute::Address(IpAddr::V6(peer)));
            }
            let result = req.execute().await;
            if let Err(e) = result
                && !e.to_string().contains("File exists")
            {
                warn!(error = %e, "Failed to assign IPv6 link-local address");
            }
        }
    }

    if let Some(peer) = peer_v6_ll {
        let _ = Command::new("ip")
            .args([
                "-6",
                "addr",
                "replace",
                &v6_ll.to_string(),
                "peer",
                &format!("{peer}/128"),
                "dev",
                ifname,
                "scope",
                "link",
                "nodad",
            ])
            .output()
            .await;
    } else {
        let _ = Command::new("ip")
            .args([
                "-6",
                "addr",
                "replace",
                &format!("{v6_ll}/64"),
                "dev",
                ifname,
                "scope",
                "link",
            ])
            .output()
            .await;
    }

    if let (Some(peer), Some(mac)) = (peer_v6_ll, peer_mac) {
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        let _ = Command::new("ip")
            .args([
                "-6",
                "neigh",
                "replace",
                &peer.to_string(),
                "dev",
                ifname,
                "lladdr",
                &mac_str,
                "nud",
                "permanent",
            ])
            .output()
            .await;
    }

    if let Some(peer) = peer_v6_ll {
        let _ = Command::new("ip")
            .args([
                "-6",
                "route",
                "replace",
                "default",
                "via",
                &peer.to_string(),
                "dev",
                ifname,
                "metric",
                "100",
                "mtu",
                "1492",
                "advmss",
                "1432",
            ])
            .output()
            .await;
    } else {
        let _ = Command::new("ip")
            .args([
                "-6",
                "route",
                "replace",
                "default",
                "dev",
                ifname,
                "metric",
                "100",
                "mtu",
                "1492",
                "advmss",
                "1432",
            ])
            .output()
            .await;
    }
}

pub async fn deconfigure_routes_and_addrs(
    ifname: &str,
    is_ebpf: bool,
    peer_ip: Option<Ipv4Addr>,
) {
    if is_ebpf && !ifname.starts_with("ppp") {
        debug!(ifname, "Deconfiguring eBPF physical interface routes and IP addresses");

        // 1. Delete default IPv4 and IPv6 routes via WAN
        let _ = Command::new("ip")
            .args(["route", "del", "default", "dev", ifname])
            .output()
            .await;
        let _ = Command::new("ip")
            .args(["-6", "route", "del", "default", "dev", ifname])
            .output()
            .await;

        // 2. Delete peer route and static neighbour entry
        if let Some(peer) = peer_ip {
            let _ = Command::new("ip")
                .args(["route", "del", &format!("{peer}/32"), "dev", ifname])
                .output()
                .await;
            let _ = Command::new("ip")
                .args(["neigh", "del", &peer.to_string(), "dev", ifname])
                .output()
                .await;
        }

        // 3. Flush assigned IPv4 and IPv6 addresses
        let _ = Command::new("ip")
            .args(["-4", "addr", "flush", "dev", ifname, "scope", "global"])
            .output()
            .await;
        let _ = Command::new("ip")
            .args(["-6", "addr", "flush", "dev", ifname, "scope", "global"])
            .output()
            .await;
    }
}
