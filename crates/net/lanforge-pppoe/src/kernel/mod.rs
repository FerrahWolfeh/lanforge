pub mod ppp_dev;
pub mod routes;
pub mod sysctl;

use crate::error::PppoeError;
pub use ppp_dev::{handoff_to_kernel, KernelSession};
use routes::{
    add_ipv4_default_route, add_ipv4_peer_route, add_ipv6_link_local, add_static_neighbour,
    deconfigure_routes_and_addrs, setup_interface_ifreq,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use sysctl::enable_interface_procfs;
use tokio::process::Command;
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
    // 1. Enable IPv6 processing and loose RP filter on the interface via procfs.
    enable_interface_procfs(ifname);

    // 2. Set MTU, bring interface UP, and assign IPv4 addresses via ioctl.
    let ifindex = setup_interface_ifreq(ifname, mtu, local_ip, peer_ip)?;

    if ifindex == 0 {
        warn!(
            ifname,
            "if_nametoindex returned 0; skipping rtnetlink operations"
        );
    } else {
        // 2b. Assign point-to-point IPv4 peer address on the interface
        if let (Some(local), Some(peer)) = (local_ip, peer_ip) {
            let _ = Command::new("ip")
                .args([
                    "addr",
                    "replace",
                    &local.to_string(),
                    "peer",
                    &format!("{peer}/32"),
                    "dev",
                    ifname,
                    "scope",
                    "global",
                ])
                .output()
                .await;
        }

        // 3. For Ethernet/veth interfaces in eBPF mode, add static ARP/neighbour mapping and on-link route for peer gateway
        if !ifname.starts_with("ppp")
            && let (Some(peer), Some(mac)) = (peer_ip, peer_mac)
        {
            add_static_neighbour(ifname, peer, mac).await;
            add_ipv4_peer_route(ifname, ifindex, peer, local_ip).await;
        }

        // 4. Add IPv4 Default Route via rtnetlink
        if let (Some(_local), Some(peer)) = (local_ip, peer_ip) {
            add_ipv4_default_route(ifname, ifindex, peer).await;
        }

        // 5. Set IPv6 Link-Local address with peer binding if negotiated via rtnetlink
        if let Some(v6_ll) = local_v6_ll {
            add_ipv6_link_local(ifname, ifindex, v6_ll, peer_v6_ll, peer_mac).await;
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

pub async fn deconfigure_interface(
    ifname: &str,
    is_ebpf: bool,
    peer_ip: Option<Ipv4Addr>,
) {
    deconfigure_routes_and_addrs(ifname, is_ebpf, peer_ip).await;
}
