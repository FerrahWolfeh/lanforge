//! Intelligent zero-config auto-detection for router-first clean starts.
//!
//! Provides hardware-aware LAN interface detection (excluding Docker/Podman/WANs),
//! dynamic RFC 4193 IPv6 ULA prefix generation, and subnet-aware DHCP defaults.

use lanforge_types::network::Ipv6Prefix;
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use rand::RngExt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use tracing::{info, warn};

/// Detects the most appropriate physical LAN interface on the system.
///
/// If an interface is explicitly configured and exists on the host, it is returned directly.
/// Otherwise, a heuristic scoring algorithm evaluates candidate interfaces, strictly
/// excluding container bridges (Docker, Podman, LXD, KVM), tunnels, and WAN interfaces.
#[must_use]
pub fn detect_lan_interface(configured: Option<&str>, wan_iface: Option<&str>) -> String {
    let all_interfaces = interfaces();

    // 1. Explicit configuration check
    if let Some(cfg_iface) = configured {
        let trimmed = cfg_iface.trim();
        if !trimmed.is_empty() && trimmed != "end0" {
            if all_interfaces.iter().any(|i| i.name == trimmed) || all_interfaces.is_empty() {
                return trimmed.to_string();
            }
            warn!(
                "Configured interface '{trimmed}' not found on system, falling back to auto-detection"
            );
        }
    }

    // 2. Score candidates
    let mut best_candidate: Option<(String, i32)> = None;

    for iface in &all_interfaces {
        let name = &iface.name;

        if is_excluded_interface(name, wan_iface) {
            continue;
        }

        let score = score_interface(iface);
        match best_candidate {
            Some((_, best_score)) if score > best_score => {
                best_candidate = Some((name.clone(), score));
            }
            None => {
                best_candidate = Some((name.clone(), score));
            }
            _ => {}
        }
    }

    if let Some((selected, score)) = best_candidate {
        info!(
            iface = %selected,
            score = score,
            "Auto-detected primary LAN interface"
        );
        return selected;
    }

    // 3. Absolute fail-safe
    let fallback = all_interfaces
        .into_iter()
        .find(|i| !i.is_loopback() && !is_wan_name(&i.name))
        .map_or_else(|| "eth0".to_string(), |i| i.name);

    warn!(
        iface = %fallback,
        "No optimal LAN interface detected, using fallback"
    );
    fallback
}

/// Checks if an interface should be excluded from LAN candidacy.
#[must_use]
pub fn is_excluded_interface(name: &str, wan_iface: Option<&str>) -> bool {
    let lower = name.to_lowercase();

    // Loopback
    if lower == "lo" {
        return true;
    }

    // Explicit WAN interface match
    if let Some(wan) = wan_iface
        && lower == wan.to_lowercase()
    {
        return true;
    }

    // WAN name patterns
    if is_wan_name(&lower) {
        return true;
    }

    // Container / Virtual interfaces & tunnels
    if is_container_or_virtual_name(&lower) {
        return true;
    }

    // Docker custom bridge hash (e.g. br-4a5c88b90123)
    if is_docker_bridge_hash(&lower) {
        return true;
    }

    // Check if it is a container bridge by inspecting member ports
    if is_container_bridge_topology(name) {
        return true;
    }

    false
}

/// Checks if the interface name represents a WAN or provider port.
#[inline]
#[must_use]
pub fn is_wan_name(lower: &str) -> bool {
    lower.starts_with("wan")
        || lower.starts_with("wwan")
        || lower.starts_with("ppp")
        || lower.starts_with("usbwan")
        || lower.starts_with("usb_wan")
        || lower.starts_with("lte")
        || lower.starts_with("modem")
}

/// Checks if the interface name matches common virtual / container / VPN patterns.
#[inline]
#[must_use]
pub fn is_container_or_virtual_name(lower: &str) -> bool {
    lower.starts_with("docker")
        || lower.starts_with("podman")
        || lower.starts_with("cni")
        || lower.starts_with("flannel")
        || lower.starts_with("calico")
        || lower.starts_with("virbr")
        || lower.starts_with("lxdbr")
        || lower.starts_with("veth")
        || lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
        || lower.starts_with("tailscale")
        || lower.starts_with("dummy")
        || lower.starts_with("macvlan")
        || lower.starts_with("ipvlan")
}

/// Checks if a bridge name matches Docker's user network pattern (`br-[0-9a-f]{12}`).
#[must_use]
pub fn is_docker_bridge_hash(lower: &str) -> bool {
    lower
        .strip_prefix("br-")
        .is_some_and(|suffix| suffix.len() == 12 && suffix.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Inspects `/sys/class/net/<iface>/brif` to check if a bridge is composed solely of virtual veth interfaces.
#[must_use]
pub fn is_container_bridge_topology(name: &str) -> bool {
    let brif_path = Path::new("/sys/class/net").join(name).join("brif");
    if !brif_path.is_dir() {
        return false;
    }

    if let Ok(entries) = std::fs::read_dir(brif_path) {
        let mut has_entries = false;
        let mut all_veth = true;

        for entry in entries.flatten() {
            has_entries = true;
            let member_name = entry.file_name().to_string_lossy().to_string();
            if !member_name.starts_with("veth") {
                all_veth = false;
                break;
            }
        }

        if has_entries && all_veth {
            return true;
        }
    }

    false
}

/// Scores a candidate interface based on physical properties, link status, and IP addressing.
#[must_use]
pub fn score_interface(iface: &pnet::datalink::NetworkInterface) -> i32 {
    let mut score = 0;
    let name = &iface.name;
    let sys_net = Path::new("/sys/class/net").join(name);

    // 1. Dedicated LAN bridge (e.g. br-lan, lan, br0)
    if name == "br-lan" || name == "lan" || name == "br0" {
        score += 40;
    }

    // 2. Physical hardware device check (/sys/class/net/<iface>/device exists)
    let is_physical = sys_net.join("device").exists();
    if is_physical {
        score += 30;
    }

    // 3. Physical link carrier up (/sys/class/net/<iface>/carrier == "1")
    if let Ok(carrier) = std::fs::read_to_string(sys_net.join("carrier")) {
        if carrier.trim() == "1" {
            score += 20;
        }
    } else if iface.is_up() {
        score += 5;
    }

    // 4. IP addressing state
    for ip in &iface.ips {
        if let IpNetwork::V4(v4) = ip {
            let octets = v4.ip().octets();
            // Private IPv4 range
            let is_private = octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168);

            if is_private {
                score += 15;
                if octets[3] == 1 {
                    score += 10; // Extra points for standard gateway .1
                }
            }
        }
    }

    // 5. Demote Wi-Fi interfaces if physical ethernet is available
    let is_wireless = sys_net.join("wireless").exists() || name.starts_with("wl");
    if is_wireless {
        score -= 15;
    }

    score
}

/// Generates an RFC 4193 compliant random IPv6 Unique Local Address (ULA) prefix (`/64`).
///
/// Uses `0xfd00::/8` with a 40-bit cryptographically random Global ID and subnet ID `1`.
#[must_use]
pub fn generate_rfc4193_ula() -> Ipv6Prefix {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd;

    let mut rng = rand::rng();
    let mut global_id = [0u8; 5];
    rng.fill(&mut global_id);

    bytes[1..6].copy_from_slice(&global_id);
    bytes[7] = 1; // Subnet ID = 1

    Ipv6Prefix::from_addr(Ipv6Addr::from(bytes))
}

/// Default network parameters derived for an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedDhcpDefaults {
    pub router: Ipv4Addr,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
}

/// Derives `DHCPv4` pool and router settings from the interface's current IPv4 configuration.
///
/// If an interface already has an assigned private IPv4 (e.g. `192.168.1.1/24`),
/// it calculates a standard `.100`–`.240` pool within that subnet.
/// If unassigned, it defaults to standard `192.168.1.1` gateway and `192.168.1.100`–`.240` pool.
#[must_use]
pub fn derive_dhcp_defaults(iface_name: &str) -> DerivedDhcpDefaults {
    let all_interfaces = interfaces();
    let target = all_interfaces.iter().find(|i| i.name == iface_name);

    if let Some(iface) = target {
        for ip in &iface.ips {
            if let IpNetwork::V4(v4) = ip {
                let addr = v4.ip();
                let mask = v4.mask();
                let octets = addr.octets();

                // If on /24 subnet
                if mask == Ipv4Addr::new(255, 255, 255, 0) {
                    let base0 = octets[0];
                    let base1 = octets[1];
                    let base2 = octets[2];

                    let router = if octets[3] == 1 {
                        addr
                    } else {
                        Ipv4Addr::new(base0, base1, base2, 1)
                    };

                    return DerivedDhcpDefaults {
                        router,
                        range_start: Ipv4Addr::new(base0, base1, base2, 100),
                        range_end: Ipv4Addr::new(base0, base1, base2, 240),
                        subnet_mask: mask,
                    };
                }
            }
        }
    }

    // Default 192.168.1.1/24 router baseline
    DerivedDhcpDefaults {
        router: Ipv4Addr::new(192, 168, 1, 1),
        range_start: Ipv4Addr::new(192, 168, 1, 100),
        range_end: Ipv4Addr::new(192, 168, 1, 240),
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wan_name() {
        assert!(is_wan_name("wan0"));
        assert!(is_wan_name("wan"));
        assert!(is_wan_name("wwan0"));
        assert!(is_wan_name("ppp0"));
        assert!(is_wan_name("usbwan0"));
        assert!(is_wan_name("usb_wan1"));
        assert!(!is_wan_name("eth0"));
        assert!(!is_wan_name("enp3s0"));
        assert!(!is_wan_name("br-lan"));
    }

    #[test]
    fn test_is_container_or_virtual_name() {
        assert!(is_container_or_virtual_name("docker0"));
        assert!(is_container_or_virtual_name("podman0"));
        assert!(is_container_or_virtual_name("cni-podman0"));
        assert!(is_container_or_virtual_name("virbr0"));
        assert!(is_container_or_virtual_name("lxdbr0"));
        assert!(is_container_or_virtual_name("veth12345"));
        assert!(is_container_or_virtual_name("tun0"));
        assert!(is_container_or_virtual_name("wg0"));
        assert!(is_container_or_virtual_name("tailscale0"));
        assert!(!is_container_or_virtual_name("eth0"));
        assert!(!is_container_or_virtual_name("br-lan"));
    }

    #[test]
    fn test_docker_bridge_hash() {
        assert!(is_docker_bridge_hash("br-4a5c88b90123"));
        assert!(is_docker_bridge_hash("br-0123456789ab"));
        assert!(!is_docker_bridge_hash("br-lan"));
        assert!(!is_docker_bridge_hash("br0"));
        assert!(!is_docker_bridge_hash("bridge0"));
    }

    #[test]
    fn test_generate_rfc4193_ula() {
        let prefix = generate_rfc4193_ula();
        let octets = prefix.to_addr().octets();
        assert_eq!(octets[0], 0xfd);
        assert_eq!(octets[7], 1);
    }

    #[test]
    fn test_derive_dhcp_defaults_fallback() {
        let defaults = derive_dhcp_defaults("non_existent_iface_xyz");
        assert_eq!(defaults.router, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(defaults.range_start, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(defaults.range_end, Ipv4Addr::new(192, 168, 1, 240));
        assert_eq!(defaults.subnet_mask, Ipv4Addr::new(255, 255, 255, 0));
    }
}
