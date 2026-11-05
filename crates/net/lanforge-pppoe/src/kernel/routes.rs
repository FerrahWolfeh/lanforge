use super::{ifreq_named, sockaddr_v4};
use crate::error::PppoeError;
use futures::TryStreamExt;
use lanforge_transport::sys;
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
    let mut ifr = ifreq_named(bytes);
    ifr.ifr_ifru.ifru_mtu = libc::c_int::from(dev_mtu);
    // SAFETY: SIOCSIFMTU reads the `ifreq` we own (name + `ifru_mtu`) for the duration of the call.
    unsafe { siocsifmtu(sock.as_raw_fd(), &raw const ifr) }?;

    // Only adjust flags for virtual ppp interfaces (e.g. ppp0), leaving physical/veth WAN links untouched
    if ifname.starts_with("ppp") {
        let mut ifr_flags = ifreq_named(bytes);
        // SAFETY: SIOCGIFFLAGS reads the name and writes `ifru_flags` inside the `ifreq` we own.
        unsafe { siocgifflags(sock.as_raw_fd(), &raw mut ifr_flags) }?;
        // SAFETY: SIOCGIFFLAGS succeeded, so `ifru_flags` is the field the kernel filled in.
        let flags = unsafe { ifr_flags.ifr_ifru.ifru_flags };
        ifr_flags.ifr_ifru.ifru_flags =
            flags | (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_POINTOPOINT) as i16;
        // SAFETY: SIOCSIFFLAGS reads the `ifreq` we own (name + `ifru_flags`).
        unsafe { siocsifflags(sock.as_raw_fd(), &raw const ifr_flags) }?;
    }

    // Set Local & Peer IPv4 Address
    if let (Some(local), Some(peer)) = (local_ip, peer_ip) {
        let mut ifr_addr = ifreq_named(bytes);
        ifr_addr.ifr_ifru.ifru_addr = sockaddr_v4(local);
        // SAFETY: SIOCSIFADDR reads the `ifreq` we own (name + `ifru_addr`).
        unsafe { siocsifaddr(sock.as_raw_fd(), &raw const ifr_addr) }?;

        // Set /32 netmask (255.255.255.255) to prevent default classful subnet assignment
        let mut ifr_mask = ifreq_named(bytes);
        ifr_mask.ifr_ifru.ifru_netmask = sockaddr_v4(Ipv4Addr::BROADCAST);
        // SAFETY: SIOCSIFNETMASK reads the `ifreq` we own (name + `ifru_netmask`).
        unsafe { siocsifnetmask(sock.as_raw_fd(), &raw const ifr_mask) }?;

        if ifname.starts_with("ppp") {
            let mut ifr_dst = ifreq_named(bytes);
            ifr_dst.ifr_ifru.ifru_dstaddr = sockaddr_v4(peer);
            // SAFETY: SIOCSIFDSTADDR reads the `ifreq` we own (name + `ifru_dstaddr`).
            unsafe { siocsifdstaddr(sock.as_raw_fd(), &raw const ifr_dst) }?;
        }
    }

    let ifindex = sys::if_name_to_index(ifname).unwrap_or(0);
    Ok(ifindex)
}

pub async fn assign_ipv4_address(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    local: Ipv4Addr,
    peer: Option<Ipv4Addr>,
) {
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

pub async fn add_ipv4_peer_route(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    peer: Ipv4Addr,
    local: Option<Ipv4Addr>,
) {
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

pub async fn add_static_neighbour(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    peer: Ipv4Addr,
    mac: [u8; 6],
) {
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

pub async fn add_ipv4_default_route(handle: &rtnetlink::Handle, ifindex: u32, peer: Ipv4Addr) {
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

pub async fn add_ipv6_link_local(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    v6_ll: Ipv6Addr,
    peer_v6_ll: Option<Ipv6Addr>,
    peer_mac: Option<[u8; 6]>,
) {
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

pub async fn deconfigure_routes_and_addrs(ifname: &str, is_ebpf: bool, peer_ip: Option<Ipv4Addr>) {
    if is_ebpf && !ifname.starts_with("ppp") {
        debug!(
            ifname,
            "Deconfiguring eBPF physical interface routes and IP addresses via rtnetlink"
        );

        let Some(ifindex) = sys::if_name_to_index(ifname) else {
            return;
        };

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    #[ignore = "needs CAP_NET_ADMIN (run inside `unshare -rn`)"]
    fn ifreq_setup_assigns_the_local_address() {
        let local = Ipv4Addr::new(10, 99, 0, 1);
        let ifindex =
            setup_interface_ifreq("lo", 1492, Some(local), Some(Ipv4Addr::new(10, 99, 0, 2)))
                .expect("ioctls on lo");
        assert_eq!(Some(ifindex), sys::if_name_to_index("lo"));
        // Binding succeeds only for a local address: proves the sockaddr_in bytes are in order.
        UdpSocket::bind((local, 0)).expect("10.99.0.1 must be assigned to lo");
        assert!(UdpSocket::bind((Ipv4Addr::new(1, 0, 99, 10), 0)).is_err());
    }
}
