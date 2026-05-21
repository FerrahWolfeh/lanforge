use crate::network::dns::upstream::UpstreamTarget;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// A binary representation of an IP network subnet (CIDR block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpSubnet {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpSubnet {
    /// Checks if a given IP address is contained within this subnet.
    #[must_use]
    pub const fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(host)) => {
                if self.prefix_len > 32 {
                    return false;
                }
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 32 - self.prefix_len as u32;
                let mask = if shift == 32 { 0 } else { u32::MAX << shift };
                let net_u32 = u32::from_be_bytes(net.octets());
                let host_u32 = u32::from_be_bytes(host.octets());
                (net_u32 & mask) == (host_u32 & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(host)) => {
                if self.prefix_len > 128 {
                    return false;
                }
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 128 - self.prefix_len as u32;
                let mask = if shift == 128 { 0 } else { u128::MAX << shift };
                let net_u128 = u128::from_be_bytes(net.octets());
                let host_u128 = u128::from_be_bytes(host.octets());
                (net_u128 & mask) == (host_u128 & mask)
            }
            _ => false,
        }
    }
}

impl FromStr for IpSubnet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((ip_str, mask_str)) = s.split_once('/') else {
            return Err("Missing '/' separator for subnet prefix".into());
        };
        let addr = ip_str
            .parse::<IpAddr>()
            .map_err(|e| format!("Invalid IP address: {e}"))?;
        let prefix_len = mask_str
            .parse::<u8>()
            .map_err(|e| format!("Invalid prefix length: {e}"))?;

        match addr {
            IpAddr::V4(_) if prefix_len > 32 => Err("IPv4 prefix length cannot exceed 32".into()),
            IpAddr::V6(_) if prefix_len > 128 => Err("IPv6 prefix length cannot exceed 128".into()),
            _ => Ok(Self { addr, prefix_len }),
        }
    }
}

impl fmt::Display for IpSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// Dynamic PTR resolver routing rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsReverseResolver {
    pub subnet: IpSubnet,
    pub resolver: UpstreamTarget,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_subnet_contains_ipv4() {
        let subnet = IpSubnet::from_str("192.168.1.0/24").unwrap();
        assert!(subnet.contains("192.168.1.5".parse().unwrap()));
        assert!(subnet.contains("192.168.1.254".parse().unwrap()));
        assert!(!subnet.contains("192.168.2.1".parse().unwrap()));

        let subnet_host = IpSubnet::from_str("10.0.0.1/32").unwrap();
        assert!(subnet_host.contains("10.0.0.1".parse().unwrap()));
        assert!(!subnet_host.contains("10.0.0.2".parse().unwrap()));

        let subnet_any = IpSubnet::from_str("0.0.0.0/0").unwrap();
        assert!(subnet_any.contains("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_subnet_contains_ipv6() {
        let subnet = IpSubnet::from_str("fd00::/8").unwrap();
        assert!(subnet.contains("fd00::1".parse().unwrap()));
        assert!(subnet.contains("fd12:3456:789a::abcd".parse().unwrap()));
        assert!(!subnet.contains("fe80::1".parse().unwrap()));

        let subnet_host = IpSubnet::from_str("2001:db8::1/128").unwrap();
        assert!(subnet_host.contains("2001:db8::1".parse().unwrap()));
        assert!(!subnet_host.contains("2001:db8::2".parse().unwrap()));

        let subnet_any = IpSubnet::from_str("::/0").unwrap();
        assert!(subnet_any.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_subnet_parsing_invalid() {
        assert!(IpSubnet::from_str("192.168.1.1").is_err());
        assert!(IpSubnet::from_str("192.168.1.256/24").is_err());
        assert!(IpSubnet::from_str("192.168.1.1/33").is_err());
        assert!(IpSubnet::from_str("2001:db8::/129").is_err());
    }
}
