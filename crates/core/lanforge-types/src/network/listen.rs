use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

/// Configuration for network service listen addresses.
///
/// Can represent either a single socket address or a list of socket addresses,
/// supporting both concise configuration (`listen = "[::]:53"`) and multi-homed
/// explicit configurations (`listen = ["192.168.1.1:53", "[fd00::1]:53"]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenConfig {
    /// Single listen address.
    Single(SocketAddr),
    /// Multiple listen addresses.
    Multiple(Vec<SocketAddr>),
}

impl ListenConfig {
    /// Creates a default dual-stack listen configuration for the specified port (`[::]:port`).
    #[must_use]
    pub const fn dual_stack(port: u16) -> Self {
        Self::Single(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
    }

    /// Returns a list of all configured listen addresses.
    #[must_use]
    pub fn addrs(&self) -> Vec<SocketAddr> {
        match self {
            Self::Single(addr) => vec![*addr],
            Self::Multiple(addrs) => addrs.clone(),
        }
    }

    /// Returns a slice of configured addresses if single, or the underlying slice if multiple.
    #[must_use]
    pub const fn as_slice(&self) -> &[SocketAddr] {
        match self {
            Self::Single(addr) => std::slice::from_ref(addr),
            Self::Multiple(addrs) => addrs.as_slice(),
        }
    }

    /// Returns the primary (first) socket address.
    #[must_use]
    pub fn primary(&self) -> SocketAddr {
        match self {
            Self::Single(addr) => *addr,
            Self::Multiple(addrs) => addrs
                .first()
                .copied()
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
        }
    }

    /// Returns the port of the primary address.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.primary().port()
    }

    /// Returns true if there are no configured addresses.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::Multiple(addrs) => addrs.is_empty(),
        }
    }
}

impl Display for ListenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(addr) => write!(f, "{addr}"),
            Self::Multiple(addrs) => {
                let parts: Vec<String> = addrs.iter().map(ToString::to_string).collect();
                write!(f, "{}", parts.join(", "))
            }
        }
    }
}

impl FromStr for ListenConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.contains(',') {
            let mut addrs = Vec::new();
            for part in s.split(',') {
                let part = part.trim();
                if !part.is_empty() {
                    let addr = part
                        .parse::<SocketAddr>()
                        .map_err(|e| format!("Invalid socket address '{part}': {e}"))?;
                    addrs.push(addr);
                }
            }
            if addrs.is_empty() {
                return Err("No socket addresses provided".to_string());
            }
            Ok(Self::Multiple(addrs))
        } else {
            let addr = s
                .parse::<SocketAddr>()
                .map_err(|e| format!("Invalid socket address '{s}': {e}"))?;
            Ok(Self::Single(addr))
        }
    }
}

impl From<SocketAddr> for ListenConfig {
    fn from(addr: SocketAddr) -> Self {
        Self::Single(addr)
    }
}

impl From<Vec<SocketAddr>> for ListenConfig {
    fn from(addrs: Vec<SocketAddr>) -> Self {
        if addrs.len() == 1 {
            Self::Single(addrs[0])
        } else {
            Self::Multiple(addrs)
        }
    }
}

impl<const N: usize> From<[SocketAddr; N]> for ListenConfig {
    fn from(addrs: [SocketAddr; N]) -> Self {
        Self::from(addrs.to_vec())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum ListenConfigDe {
    Single(SocketAddr),
    Multiple(Vec<SocketAddr>),
}

impl Serialize for ListenConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(addr) => addr.serialize(serializer),
            Self::Multiple(addrs) => addrs.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ListenConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let de = ListenConfigDe::deserialize(deserializer)?;
        match de {
            ListenConfigDe::Single(addr) => Ok(Self::Single(addr)),
            ListenConfigDe::Multiple(addrs) => {
                if addrs.len() == 1 {
                    Ok(Self::Single(addrs[0]))
                } else {
                    Ok(Self::Multiple(addrs))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_single() {
        let json = "\"127.0.0.1:53\"";
        let cfg: ListenConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg, ListenConfig::Single("127.0.0.1:53".parse().unwrap()));
        assert_eq!(cfg.port(), 53);
    }

    #[test]
    fn test_deserialize_multiple() {
        let json = "[\"192.168.1.1:53\", \"[fd00::1]:53\"]";
        let cfg: ListenConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            cfg,
            ListenConfig::Multiple(vec![
                "192.168.1.1:53".parse().unwrap(),
                "[fd00::1]:53".parse().unwrap(),
            ])
        );
        assert_eq!(cfg.port(), 53);
        assert_eq!(cfg.addrs().len(), 2);
    }

    #[test]
    fn test_dual_stack_constructor() {
        let cfg = ListenConfig::dual_stack(53);
        assert_eq!(cfg, ListenConfig::Single("[::]:53".parse().unwrap()));
        assert_eq!(cfg.port(), 53);
    }

    #[test]
    fn test_from_str() {
        let single: ListenConfig = "[::]:8088".parse().unwrap();
        assert_eq!(single, ListenConfig::Single("[::]:8088".parse().unwrap()));

        let multi: ListenConfig = "192.168.1.1:8088, [fd00::1]:8088".parse().unwrap();
        assert_eq!(
            multi,
            ListenConfig::Multiple(vec![
                "192.168.1.1:8088".parse().unwrap(),
                "[fd00::1]:8088".parse().unwrap(),
            ])
        );
    }
}
