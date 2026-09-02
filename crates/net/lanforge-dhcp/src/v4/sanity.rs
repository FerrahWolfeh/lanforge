//! `DHCPv4` sanity checking, subnet containment audit, and self-healing.
//!
//! Enforces RFC 2131 network topology safety:
//! 1. Server Identifier (Option 54) MUST match the DHCP server's actual interface IP.
//! 2. Default Gateway (Option 3 - Router) MUST belong to the interface's active subnet.
//!    If outside, it auto-heals to the local interface IP.
//! 3. Subnet Mask (Option 1) MUST match the interface's actual subnet mask.
//! 4. Dynamic IP Pools MUST reside within the interface's active subnet. If completely
//!    outside, sensible ranges are automatically derived for the active prefix.

use crate::v4::config::Dhcpv4Config;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use pnet::datalink::interfaces;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use std::net::Ipv4Addr;
use tracing::warn;

/// Default network parameters derived for an IPv4 interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedDhcpDefaults {
    pub router: Ipv4Addr,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
}

/// Derives sensible `DHCPv4` pool and router settings from an interface's IPv4 network.
#[must_use]
pub fn derive_dhcp_defaults_from_v4(v4: &Ipv4Network) -> DerivedDhcpDefaults {
    let addr = v4.ip();
    let mask = v4.mask();
    let prefix = v4.prefix();
    let net_u32 = u32::from_be_bytes(v4.network().octets());
    let bcast_u32 = u32::from_be_bytes(v4.broadcast().octets());

    let subnet_mask = mask;

    // For prefix > 30 (/31 or /32), no usable dynamic pool range exists.
    if prefix > 30 {
        return DerivedDhcpDefaults {
            router: Ipv4Addr::new(192, 168, 1, 1),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 240),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        };
    }

    if prefix == 24 {
        // Standard /24: preserve .100 - .240 baseline
        let octets = addr.octets();
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

    let usable_start = net_u32 + 1;
    let usable_end = bcast_u32 - 1;
    let total_usable = usable_end.saturating_sub(usable_start) + 1;

    let (range_start_u32, range_end_u32) = if prefix < 24 {
        // Larger networks (e.g. /22 with 1022 hosts, /16 with 65534 hosts)
        // Reserve lower 50 IPs for routers, switches, infrastructure.
        // End 10 IPs before broadcast.
        let start = usable_start + 50.min(total_usable / 4);
        let end = usable_end - 10.min(total_usable / 20);
        (start, end)
    } else {
        // Smaller networks (/25 to /30)
        let offset = (total_usable / 4).max(1);
        let start = usable_start + offset;
        let end = usable_end.saturating_sub(1).max(start);
        (start, end)
    };

    DerivedDhcpDefaults {
        router: addr,
        range_start: Ipv4Addr::from(range_start_u32),
        range_end: Ipv4Addr::from(range_end_u32),
        subnet_mask,
    }
}

/// Audits a `Dhcpv4Config` against the real network interface named in `cfg.iface`.
/// Returns `true` if any field was auto-healed.
pub fn audit_and_auto_heal_dhcpv4(cfg: &mut Dhcpv4Config) -> bool {
    let iface_v4 = interfaces()
        .into_iter()
        .find(|i| i.name == cfg.iface)
        .and_then(|i| {
            i.ips.into_iter().find_map(|ip| match ip {
                IpNetwork::V4(v4) => Some(v4),
                IpNetwork::V6(_) => None,
            })
        });

    audit_and_auto_heal_dhcpv4_with_network(cfg, iface_v4.as_ref())
}

/// Audits a `Dhcpv4Config` against an optional active IPv4 network.
///
/// If `network` is `Some`:
/// - `cfg.server_id` is assigned to `network.ip()`.
/// - `cfg.router` is validated against `network`. If outside, auto-healed to `network.ip()`.
/// - `cfg.subnet_mask` is aligned with `network.mask()`.
/// - `cfg.pools` is validated against `network`. If all pools are outside, a valid pool is auto-derived.
pub fn audit_and_auto_heal_dhcpv4_with_network(
    cfg: &mut Dhcpv4Config,
    network: Option<&Ipv4Network>,
) -> bool {
    let Some(v4) = network else {
        if cfg.server_id == Ipv4Addr::UNSPECIFIED {
            cfg.server_id = cfg.router;
        }
        return false;
    };

    let iface_ip = v4.ip();
    let iface_mask = v4.mask();
    let mut modified = cfg.server_id != iface_ip;

    // 1. Server Identifier (Option 54) MUST be our local IP on this interface
    if modified {
        cfg.server_id = iface_ip;
    }

    // 2. Gateway (Option 3 - Router)
    if !v4.contains(cfg.router) {
        warn!(
            "DHCPv4 SANITY CHECK: Configured gateway {} is outside interface '{}' subnet ({}/{}). Auto-healing gateway to local interface IP {}",
            cfg.router, cfg.iface, v4.network(), v4.prefix(), iface_ip
        );
        cfg.router = iface_ip;
        modified = true;
    }

    // 3. Subnet Mask (Option 1)
    if cfg.subnet_mask != iface_mask {
        warn!(
            "DHCPv4 SANITY CHECK: Configured subnet mask {} does not match interface '{}' mask {}. Auto-healing subnet mask.",
            cfg.subnet_mask, cfg.iface, iface_mask
        );
        cfg.subnet_mask = iface_mask;
        modified = true;
    }

    // 4. Dynamic Pools Containment
    if !cfg.pools.is_empty() {
        let any_pool_in_subnet = cfg.pools.iter().any(|p| {
            v4.contains(p.range_start) && v4.contains(p.range_end)
        });

        if !any_pool_in_subnet {
            warn!(
                "DHCPv4 SANITY CHECK: All configured DHCPv4 pools are outside interface '{}' subnet ({}). Auto-healing dynamic pool to interface subnet.",
                cfg.iface, v4
            );
            let derived = derive_dhcp_defaults_from_v4(v4);
            cfg.pools = vec![Dhcpv4Pool {
                name: Some("Auto-Healed LAN Scope".to_string()),
                range_start: derived.range_start,
                range_end: derived.range_end,
                lease_time: Some(cfg.lease_time),
                router: Some(cfg.router),
                subnet_mask: Some(cfg.subnet_mask),
                dns_servers: cfg.dns.clone(),
                ..Default::default()
            }];
            cfg.range_start = None;
            cfg.range_end = None;
            modified = true;
        }
    }

    modified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_heals_unreachable_gateway_and_mask() {
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 3, 1), 22).unwrap();
        let mut cfg = Dhcpv4Config {
            iface: "eth0".to_string(),
            router: Ipv4Addr::new(192, 168, 254, 1), // Outside /22!
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0), // /24 instead of /22
            server_id: Ipv4Addr::new(192, 168, 254, 1),
            ..Default::default()
        };

        let modified = audit_and_auto_heal_dhcpv4_with_network(&mut cfg, Some(&net));
        assert!(modified);
        assert_eq!(cfg.router, Ipv4Addr::new(192, 168, 3, 1));
        assert_eq!(cfg.server_id, Ipv4Addr::new(192, 168, 3, 1));
        assert_eq!(cfg.subnet_mask, Ipv4Addr::new(255, 255, 252, 0));
    }

    #[test]
    fn test_audit_preserves_reachable_custom_gateway() {
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 3, 1), 22).unwrap();
        let mut cfg = Dhcpv4Config {
            iface: "eth0".to_string(),
            router: Ipv4Addr::new(192, 168, 3, 254), // Inside /22!
            subnet_mask: Ipv4Addr::new(255, 255, 252, 0),
            server_id: Ipv4Addr::new(192, 168, 3, 1),
            ..Default::default()
        };

        let modified = audit_and_auto_heal_dhcpv4_with_network(&mut cfg, Some(&net));
        assert!(!modified);
        assert_eq!(cfg.router, Ipv4Addr::new(192, 168, 3, 254));
        assert_eq!(cfg.server_id, Ipv4Addr::new(192, 168, 3, 1));
    }

    #[test]
    fn test_audit_heals_foreign_dynamic_pools() {
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 3, 1), 22).unwrap();
        let mut cfg = Dhcpv4Config {
            iface: "eth0".to_string(),
            router: Ipv4Addr::new(192, 168, 3, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 252, 0),
            server_id: Ipv4Addr::new(192, 168, 3, 1),
            pools: vec![Dhcpv4Pool {
                range_start: Ipv4Addr::new(10, 0, 0, 100),
                range_end: Ipv4Addr::new(10, 0, 0, 200),
                ..Default::default()
            }],
            ..Default::default()
        };

        let modified = audit_and_auto_heal_dhcpv4_with_network(&mut cfg, Some(&net));
        assert!(modified);
        assert_eq!(cfg.pools.len(), 1);
        let healed = &cfg.pools[0];
        assert!(net.contains(healed.range_start));
        assert!(net.contains(healed.range_end));
    }

    #[test]
    fn test_derive_defaults_various_subnets() {
        // /24 test
        let net_24 = Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap();
        let def_24 = derive_dhcp_defaults_from_v4(&net_24);
        assert_eq!(def_24.router, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(def_24.range_start, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(def_24.range_end, Ipv4Addr::new(192, 168, 1, 240));
        assert_eq!(def_24.subnet_mask, Ipv4Addr::new(255, 255, 255, 0));

        // /22 test
        let net_22 = Ipv4Network::new(Ipv4Addr::new(192, 168, 3, 1), 22).unwrap();
        let def_22 = derive_dhcp_defaults_from_v4(&net_22);
        assert_eq!(def_22.router, Ipv4Addr::new(192, 168, 3, 1));
        assert_eq!(def_22.subnet_mask, Ipv4Addr::new(255, 255, 252, 0));
        assert!(net_22.contains(def_22.range_start));
        assert!(net_22.contains(def_22.range_end));

        // /16 test
        let net_16 = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), 16).unwrap();
        let def_16 = derive_dhcp_defaults_from_v4(&net_16);
        assert_eq!(def_16.router, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(def_16.subnet_mask, Ipv4Addr::new(255, 255, 0, 0));
        assert!(net_16.contains(def_16.range_start));
        assert!(net_16.contains(def_16.range_end));
    }
}
