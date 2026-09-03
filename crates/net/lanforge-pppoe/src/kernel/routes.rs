use crate::error::PppoeError;
use futures::TryStreamExt;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use rtnetlink::RouteMessageBuilder;
use rtnetlink::packet_route::address::{AddressAttribute, AddressHeaderFlags, AddressScope};
use rtnetlink::packet_route::neighbour::{NeighbourAttribute, NeighbourState};
use rtnetlink::packet_route::route::RouteScope;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
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
    // - For physical/Ethernet interfaces in eBPF mode (e.g. wan0), the physical interface MTU must be 1500.
    let dev_mtu = if ifname.starts_with("ppp") { mtu } else { 1500 };
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

pub async fn assign_ipv4_address(ifindex: u32, local: Ipv4Addr, peer: Option<Ipv4Addr>) {
    match rtnetlink::new_connection() {
        Err(e) => warn!(error = %e, "Failed to open rtnetlink connection for IP addr"),
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            let mut req = handle.address().add(ifindex, IpAddr::V4(local), 32);
            if let Some(peer_ip) = peer {
                req.message_mut()
                    .attributes
                    .push(AddressAttribute::Address(IpAddr::V4(peer_ip)));
                req.message_mut()
                    .attributes
                    .push(AddressAttribute::Local(IpAddr::V4(local)));
            }
            let result = req.replace().execute().await;
            if let Err(e) = result
                && !e.to_string().contains("File exists")
            {
                warn!(error = %e, "Failed to assign IPv4 address via rtnetlink");
            }
        }
    }
}

pub async fn add_ipv4_peer_route(ifindex: u32, peer: Ipv4Addr, local: Option<Ipv4Addr>) {
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
}

pub async fn add_static_neighbour(ifindex: u32, peer: Ipv4Addr, mac: [u8; 6]) {
    match rtnetlink::new_connection() {
        Err(e) => warn!(error = %e, "Failed to open rtnetlink connection for neighbour"),
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            let mut req = handle.neighbours().add(ifindex, IpAddr::V4(peer));
            req.message_mut().header.state = NeighbourState::Permanent;
            req.message_mut()
                .attributes
                .push(NeighbourAttribute::LinkLayerAddress(mac.to_vec()));
            let result = req.replace().execute().await;
            if let Err(e) = result
                && !e.to_string().contains("File exists")
            {
                warn!(error = %e, "Failed to install static neighbour entry");
            } else {
                debug!(ifindex, peer = %peer, "Installed static neighbour entry via rtnetlink");
            }
        }
    }
}

pub async fn add_ipv4_default_route(ifindex: u32, peer: Ipv4Addr) {
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
}

pub async fn add_ipv6_link_local(
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
                req.message_mut()
                    .attributes
                    .push(AddressAttribute::Local(IpAddr::V6(v6_ll)));
            }
            let result = req.execute().await;
            if let Err(e) = result
                && !e.to_string().contains("File exists")
            {
                warn!(error = %e, "Failed to assign IPv6 link-local address");
            }

            if let (Some(peer), Some(mac)) = (peer_v6_ll, peer_mac) {
                let mut neigh_req = handle.neighbours().add(ifindex, IpAddr::V6(peer));
                neigh_req.message_mut().header.state = NeighbourState::Permanent;
                neigh_req
                    .message_mut()
                    .attributes
                    .push(NeighbourAttribute::LinkLayerAddress(mac.to_vec()));
                let _ = neigh_req.replace().execute().await;
            }

            // IPv6 default route
            let mut route_builder = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                .output_interface(ifindex)
                .priority(100);
            if let Some(peer) = peer_v6_ll {
                route_builder = route_builder.gateway(peer);
            }
            let route = route_builder.build();
            let _ = handle.route().add(route).replace().execute().await;
        }
    }
}

pub async fn deconfigure_routes_and_addrs(ifname: &str, is_ebpf: bool, peer_ip: Option<Ipv4Addr>) {
    if is_ebpf && !ifname.starts_with("ppp") {
        debug!(
            ifname,
            "Deconfiguring eBPF physical interface routes and IP addresses via rtnetlink"
        );

        let Ok(c_ifname) = CString::new(ifname) else {
            return;
        };
        let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
        if ifindex == 0 {
            return;
        }

        if let Ok((conn, handle, _)) = rtnetlink::new_connection() {
            tokio::spawn(conn);

            // 1. Delete default IPv4 route
            let default_v4 = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .output_interface(ifindex)
                .build();
            let _ = handle.route().del(default_v4).execute().await;

            // 2. Delete peer route and static neighbour entry
            if let Some(peer) = peer_ip {
                let peer_route = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(peer, 32)
                    .output_interface(ifindex)
                    .build();
                let _ = handle.route().del(peer_route).execute().await;
                let mut neigh_stream = handle
                    .neighbours()
                    .get()
                    .set_address_family(rtnetlink::packet_route::AddressFamily::Inet)
                    .execute();
                while let Ok(Some(msg)) = neigh_stream.try_next().await {
                    if msg.header.ifindex == ifindex {
                        let _ = handle.neighbours().del(msg).execute().await;
                    }
                }
            }

            // 3. Delete default IPv6 route
            let default_v6 = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                .output_interface(ifindex)
                .build();
            let _ = handle.route().del(default_v6).execute().await;

            // 4. Flush global IPv4 / IPv6 addresses
            let mut addr_stream = handle
                .address()
                .get()
                .set_link_index_filter(ifindex)
                .execute();
            while let Ok(Some(addr_msg)) = addr_stream.try_next().await {
                if addr_msg.header.scope == AddressScope::Universe {
                    let _ = handle.address().del(addr_msg).execute().await;
                }
            }
        }
    }
}
