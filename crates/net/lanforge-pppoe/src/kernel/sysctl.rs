use crate::error::PppoeError;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::path::Path;
use tracing::debug;

const SIOCETHTOOL: libc::c_ulong = 0x8946;

const ETHTOOL_STXCSUM: u32 = 0x0000_0017;
const ETHTOOL_STSO: u32 = 0x0000_001f;
const ETHTOOL_SGSO: u32 = 0x0000_0029;

#[repr(C)]
struct EthtoolValue {
    cmd: u32,
    data: u32,
}

#[allow(clippy::cast_possible_wrap)]
fn set_ethtool_flag(ifname: &str, cmd: u32, val: u32) -> Result<(), PppoeError> {
    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let c_ifname = CString::new(ifname)
        .map_err(|_| PppoeError::NegotiationFailed("Invalid interface name".into()))?;
    let bytes = c_ifname.as_bytes();
    for (i, &b) in bytes[..bytes.len().min(15)].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    let mut ev = EthtoolValue { cmd, data: val };
    ifr.ifr_ifru.ifru_data = std::ptr::addr_of_mut!(ev).cast::<libc::c_char>();

    unsafe {
        let _ = libc::ioctl(sock.as_raw_fd(), SIOCETHTOOL, &raw mut ifr);
    }

    Ok(())
}

pub fn enable_interface_procfs(ifname: &str) {
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

    // Disable TSO/GSO via kernel SIOCETHTOOL ioctl
    let _ = set_ethtool_flag(ifname, ETHTOOL_STSO, 0);
    let _ = set_ethtool_flag(ifname, ETHTOOL_SGSO, 0);

    // For physical interfaces in eBPF mode, disable hardware TX checksum offload via kernel ioctl
    if !ifname.starts_with("ppp") {
        let _ = set_ethtool_flag(ifname, ETHTOOL_STXCSUM, 0);
    }
}

pub fn restore_interface_offloads(ifname: &str) {
    debug!(ifname, "Restoring network interface offloads via kernel ioctl");
    let _ = set_ethtool_flag(ifname, ETHTOOL_STSO, 1);
    let _ = set_ethtool_flag(ifname, ETHTOOL_SGSO, 1);
    let _ = set_ethtool_flag(ifname, ETHTOOL_STXCSUM, 1);
}
