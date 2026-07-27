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
nix::ioctl_write_ptr_bad!(siocsifmtu, 0x8922, libc::ifreq);
nix::ioctl_read_bad!(siocgifflags, 0x8913, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifflags, 0x8914, libc::ifreq);

pub async fn configure_interface(
    ifname: &str,
    local_ip: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
    local_v6_ll: Option<Ipv6Addr>,
    peer_v6_ll: Option<Ipv6Addr>,
    mtu: u16,
) -> Result<(), PppoeError> {
    // 1. Enable IPv6 processing on the interface via procfs.
    enable_ipv6_procfs(ifname);

    // 2. Set MTU, bring interface UP, and assign IPv4 addresses via ioctl.
    let ifindex = setup_interface_ifreq(ifname, mtu, local_ip, peer_ip)?;

    if ifindex == 0 {
        warn!(
            ifname,
            "if_nametoindex returned 0; skipping rtnetlink operations"
        );
    } else {
        // 3. Add IPv4 Default Route via rtnetlink
        if let (Some(_local), Some(peer)) = (local_ip, peer_ip) {
            add_ipv4_default_route(ifindex, peer).await;
        }

        // 4. Set IPv6 Link-Local address with peer binding if negotiated via rtnetlink
        if let Some(v6_ll) = local_v6_ll {
            add_ipv6_link_local(ifindex, v6_ll, peer_v6_ll).await;
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

fn enable_ipv6_procfs(ifname: &str) {
    // accept_ra = 2 is MANDATORY on a router (where IPv6 forwarding is enabled).
    // In the Linux kernel, accept_ra = 1 is silently IGNORED if forwarding == 1.
    // Setting accept_ra = 2 forces the kernel/system to accept RAs on ppp0 even when forwarding.
    let disable_ipv6_path = format!("/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6");
    let accept_ra_path = format!("/proc/sys/net/ipv6/conf/{ifname}/accept_ra");
    let autoconf_path = format!("/proc/sys/net/ipv6/conf/{ifname}/autoconf");
    if Path::new(&disable_ipv6_path).exists() {
        let _ = std::fs::write(&disable_ipv6_path, "0");
    }
    if Path::new(&accept_ra_path).exists() {
        let _ = std::fs::write(&accept_ra_path, "2");
    }
    if Path::new(&autoconf_path).exists() {
        let _ = std::fs::write(&autoconf_path, "1");
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

    // Set MTU
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, &b) in bytes[..len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_mtu = libc::c_int::from(mtu);
    unsafe {
        siocsifmtu(sock.as_raw_fd(), &raw const ifr)?;
    }

    // Bring interface UP with IFF_POINTOPOINT *before* setting addresses.
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

        let mut ifr_dst: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, &b) in bytes[..len].iter().enumerate() {
            ifr_dst.ifr_name[i] = b as libc::c_char;
        }
        let sin_dst = unsafe {
            &mut *std::ptr::addr_of_mut!(ifr_dst.ifr_ifru.ifru_dstaddr).cast::<libc::sockaddr_in>()
        };
        sin_dst.sin_family = libc::AF_INET as u16;
        sin_dst.sin_addr.s_addr = u32::from_ne_bytes(peer.octets());
        unsafe {
            siocsifdstaddr(sock.as_raw_fd(), &raw const ifr_dst)?;
        }
    }

    let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
    Ok(ifindex)
}

async fn add_ipv4_default_route(ifindex: u32, peer: Ipv4Addr) {
    match rtnetlink::new_connection() {
        Err(e) => warn!(error = %e, "Failed to open rtnetlink connection for route"),
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .gateway(peer)
                .output_interface(ifindex)
                .build();
            let result = handle.route().add(route).execute().await;
            if let Err(e) = result
                && !e.to_string().contains("File exists")
            {
                warn!(error = %e, "Failed to install IPv4 default route");
            }
        }
    }
}

async fn add_ipv6_link_local(ifindex: u32, v6_ll: Ipv6Addr, peer_v6_ll: Option<Ipv6Addr>) {
    match rtnetlink::new_connection() {
        Err(e) => warn!(error = %e, "Failed to open rtnetlink connection for IPv6 addr"),
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            let mut req = handle.address().add(ifindex, IpAddr::V6(v6_ll), 128);
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
}
