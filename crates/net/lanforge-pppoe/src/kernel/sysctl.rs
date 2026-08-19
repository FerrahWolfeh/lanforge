use std::path::Path;
use std::process::Command;

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

    // Clamp GSO segment size to match PPPoE MTU (1492) while preserving hardware TX/RX/GRO offloads
    let _ = Command::new("ip")
        .args([
            "link",
            "set",
            "dev",
            ifname,
            "gso_max_size",
            "1492",
            "gso_max_segs",
            "1",
        ])
        .output();
    let _ = Command::new("ethtool")
        .args(["-K", ifname, "tso", "off", "gso", "off"])
        .output();

    // For physical interfaces in eBPF mode, disable hardware TX checksum offload so the kernel IP stack
    // calculates L4 (TCP/UDP) checksums in software before TC egress PPPoE encapsulation (mirroring ppp0 behavior).
    if !ifname.starts_with("ppp") {
        let _ = Command::new("ethtool")
            .args(["-K", ifname, "tx", "off", "tx-checksum-ip-generic", "off"])
            .output();
    }
}
