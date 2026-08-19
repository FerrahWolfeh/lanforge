use crate::error::PppoeError;
use nix::fcntl::{OFlag, open};
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
use nix::sys::stat::Mode;
use rtnetlink::RouteMessageBuilder;
use rtnetlink::packet_route::address::{AddressAttribute, AddressHeaderFlags};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use tracing::{debug, info, warn};

nix::ioctl_readwrite!(pppiocnewunit, 't', 62, libc::c_int);
nix::ioctl_read!(pppiocgchan, 't', 55, libc::c_int);
nix::ioctl_write_ptr!(pppiocattchan, 't', 56, libc::c_int);
nix::ioctl_write_ptr!(pppiocconnect, 't', 58, libc::c_int);
nix::ioctl_write_ptr!(pppiocsmru, 't', 82, libc::c_int);
nix::ioctl_write_ptr!(pppiocsflags, 't', 89, libc::c_int);

pub struct KernelSession {
    pub ppp_unit_fd: OwnedFd,
    pub ppp_chan_fd: OwnedFd,
    pub interface_name: String,
    pub unit_id: i32,
}

pub fn handoff_to_kernel(session_fd: &OwnedFd, mru: u16) -> Result<KernelSession, PppoeError> {
    if !Path::new("/dev/ppp").exists() {
        return Err(PppoeError::DevPppUnavailable);
    }

    debug!("Handoff step 1: Opening /dev/ppp for unit creation");
    let ppp_unit_fd = open(
        Path::new("/dev/ppp"),
        OFlag::O_RDWR | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;

    debug!("Handoff step 2: PPPIOCNEWUNIT");
    let mut unit_id: libc::c_int = -1;
    unsafe {
        pppiocnewunit(ppp_unit_fd.as_raw_fd(), &raw mut unit_id)?;
    }

    debug!(unit_id, "Handoff step 3: PPPIOCGCHAN on session_fd");
    let mut chan_num: libc::c_int = 0;
    unsafe {
        pppiocgchan(session_fd.as_raw_fd(), &raw mut chan_num)?;
    }

    debug!(
        chan_num,
        "Handoff step 4: Opening second /dev/ppp for channel"
    );
    let ppp_chan_fd = open(
        Path::new("/dev/ppp"),
        OFlag::O_RDWR | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;

    debug!("Handoff step 5: PPPIOCATTCHAN");
    unsafe {
        pppiocattchan(ppp_chan_fd.as_raw_fd(), &raw const chan_num)?;
    }

    debug!("Handoff step 6: PPPIOCCONNECT");
    unsafe {
        pppiocconnect(ppp_chan_fd.as_raw_fd(), &raw const unit_id)?;
    }

    debug!("Handoff step 7: PPPIOCSMRU");
    let mru_val = libc::c_int::from(mru);
    unsafe {
        pppiocsmru(ppp_unit_fd.as_raw_fd(), &raw const mru_val)?;
    }

    debug!("Handoff step 8: PPPIOCSFLAGS");
    let flags: libc::c_int = 0;
    unsafe {
        pppiocsflags(ppp_unit_fd.as_raw_fd(), &raw const flags)?;
    }

    let interface_name = format!("ppp{unit_id}");
    info!(
        unit = unit_id,
        interface = %interface_name,
        "Successfully handed off PPPoE session to kernel ppp_generic"
    );

    Ok(KernelSession {
        ppp_unit_fd,
        ppp_chan_fd,
        interface_name,
        unit_id,
    })
}

nix::ioctl_write_ptr_bad!(siocsifaddr, 0x8916, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifdstaddr, 0x8918, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifnetmask, 0x891c, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifmtu, 0x8922, libc::ifreq);
nix::ioctl_read_bad!(siocgifflags, 0x8913, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifflags, 0x8914, libc::ifreq);

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
            let _ = tokio::process::Command::new("ip")
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

async fn add_ipv4_peer_route(ifname: &str, ifindex: u32, peer: Ipv4Addr, local: Option<Ipv4Addr>) {
    match rtnetlink::new_connection() {
        Err(e) => warn!(error = %e, "Failed to open rtnetlink connection for peer route"),
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(peer, 32)
                .output_interface(ifindex)
                .scope(rtnetlink::packet_route::route::RouteScope::Link)
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

    let mut cmd = tokio::process::Command::new("ip");
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

async fn add_static_neighbour(ifname: &str, peer: Ipv4Addr, mac: [u8; 6]) {
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    let result = tokio::process::Command::new("ip")
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

fn enable_interface_procfs(ifname: &str) {
    // accept_ra = 2 is MANDATORY on a router (where IPv6 forwarding is enabled).
    // In the Linux kernel, accept_ra = 1 is silently IGNORED if forwarding == 1.
    // Setting accept_ra = 2 forces the kernel/system to accept RAs on ppp0 even when forwarding.
    let disable_ipv6_path = format!("/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6");
    let accept_ra_path = format!("/proc/sys/net/ipv6/conf/{ifname}/accept_ra");
    let accept_ra_defrtr_path = format!("/proc/sys/net/ipv6/conf/{ifname}/accept_ra_defrtr");
    let accept_ra_pinfo_path = format!("/proc/sys/net/ipv6/conf/{ifname}/accept_ra_pinfo");
    let autoconf_path = format!("/proc/sys/net/ipv6/conf/{ifname}/autoconf");
    let rp_filter_path = format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter");
    let accept_local_path = format!("/proc/sys/net/ipv4/conf/{ifname}/accept_local");

    if Path::new(&disable_ipv6_path).exists() {
        let _ = std::fs::write(&disable_ipv6_path, "0");
    }
    if Path::new(&accept_ra_path).exists() {
        let _ = std::fs::write(&accept_ra_path, "2");
    }
    if Path::new(&accept_ra_defrtr_path).exists() {
        let _ = std::fs::write(&accept_ra_defrtr_path, "1");
    }
    if Path::new(&accept_ra_pinfo_path).exists() {
        let _ = std::fs::write(&accept_ra_pinfo_path, "1");
    }
    if Path::new(&autoconf_path).exists() {
        let _ = std::fs::write(&autoconf_path, "1");
    }
    if Path::new(&rp_filter_path).exists() {
        let _ = std::fs::write(&rp_filter_path, "2");
    }
    if Path::new(&accept_local_path).exists() {
        let _ = std::fs::write(&accept_local_path, "1");
    }

    // Clamp GSO segment size to match PPPoE MTU (1492) while preserving hardware TX/RX/GRO offloads
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", ifname, "gso_max_size", "1492", "gso_max_segs", "1"])
        .output();
    let _ = std::process::Command::new("ethtool")
        .args(["-K", ifname, "tso", "off", "gso", "off"])
        .output();

    // For physical interfaces in eBPF mode, disable hardware TX checksum offload so the kernel IP stack
    // calculates L4 (TCP/UDP) checksums in software before TC egress PPPoE encapsulation (mirroring ppp0 behavior).
    if !ifname.starts_with("ppp") {
        let _ = std::process::Command::new("ethtool")
            .args(["-K", ifname, "tx", "off", "tx-checksum-ip-generic", "off"])
            .output();
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn setup_interface_ifreq(
    ifname: &str,
    mtu: u16,
    local_ip: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
) -> Result<u32, PppoeError> {
    let c_ifname = std::ffi::CString::new(ifname)
        .map_err(|_| PppoeError::NegotiationFailed("Invalid interface name for CString".into()))?;
    let bytes = c_ifname.as_bytes();
    let len = bytes.len().min(15);

    let sock = socket::socket(
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

async fn add_ipv4_default_route(ifname: &str, ifindex: u32, peer: Ipv4Addr) {
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

    let _ = tokio::process::Command::new("ip")
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
async fn add_ipv6_link_local(
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
        let _ = tokio::process::Command::new("ip")
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
        let _ = tokio::process::Command::new("ip")
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
        let _ = tokio::process::Command::new("ip")
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
        let _ = tokio::process::Command::new("ip")
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
        let _ = tokio::process::Command::new("ip")
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
