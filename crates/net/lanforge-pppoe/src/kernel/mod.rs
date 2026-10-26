pub mod ppp_dev;
pub mod routes;
pub mod sysctl;

use crate::error::PppoeError;
pub use ppp_dev::{KernelSession, handoff_to_kernel};
use routes::{
    add_ipv4_default_route, add_ipv4_peer_route, add_ipv6_link_local, add_static_neighbour,
    assign_ipv4_address, deconfigure_routes_and_addrs, setup_interface_ifreq,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use sysctl::enable_interface_procfs;
use tracing::{info, warn};

pub async fn configure_interface(
    ifname: &str,
    local_ip: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
    peer_mac: Option<[u8; 6]>,
    local_v6_ll: Option<Ipv6Addr>,
    peer_v6_ll: Option<Ipv6Addr>,
    mtu: u16,
) -> Result<(), PppoeError> {
    // 1. Enable IPv6 processing, loose RP filter, and disable TSO/GSO on the interface via procfs and SIOCETHTOOL ioctl.
    enable_interface_procfs(ifname);

    // 2. Set MTU, bring interface UP, and assign IPv4 addresses via ioctl.
    let ifindex = setup_interface_ifreq(ifname, mtu, local_ip, peer_ip)?;

    if ifindex == 0 {
        warn!(
            ifname,
            "if_nametoindex returned 0; skipping rtnetlink operations"
        );
    } else {
        match rtnetlink::new_connection() {
            Err(e) => warn!(error = %e, "Failed to open rtnetlink connection"),
            Ok((conn, handle, _)) => {
                tokio::spawn(conn);

                // 2b. Assign point-to-point IPv4 peer address on the interface via rtnetlink
                if let (Some(local), Some(peer)) = (local_ip, peer_ip) {
                    assign_ipv4_address(&handle, ifindex, local, Some(peer)).await;
                }

                // 3. For Ethernet/veth interfaces in eBPF mode, add static ARP/neighbour mapping and on-link route for peer gateway
                if !ifname.starts_with("ppp")
                    && let (Some(peer), Some(mac)) = (peer_ip, peer_mac)
                {
                    add_static_neighbour(&handle, ifindex, peer, mac).await;
                    add_ipv4_peer_route(&handle, ifindex, peer, local_ip).await;
                }

                // 4. Add IPv4 Default Route via rtnetlink
                if let (Some(_local), Some(peer)) = (local_ip, peer_ip) {
                    add_ipv4_default_route(&handle, ifindex, peer).await;
                }

                // 5. Set IPv6 Link-Local address with peer binding if negotiated via rtnetlink
                if let Some(v6_ll) = local_v6_ll {
                    add_ipv6_link_local(&handle, ifindex, v6_ll, peer_v6_ll, peer_mac).await;
                }
            }
        }
    }

    info!(
        interface = ifname,
        local = ?local_ip,
        peer = ?peer_ip,
        ipv6_ll = ?local_v6_ll,
        peer_v6_ll = ?peer_v6_ll,
        mtu = mtu,
        "Configured ppp network interface, default route, and IPv6 parameters in Linux kernel"
    );

    Ok(())
}

pub async fn deconfigure_interface(ifname: &str, is_ebpf: bool, peer_ip: Option<Ipv4Addr>) {
    deconfigure_routes_and_addrs(ifname, is_ebpf, peer_ip).await;
    if is_ebpf && !ifname.starts_with("ppp") {
        sysctl::restore_interface_offloads(ifname);
    }
}
