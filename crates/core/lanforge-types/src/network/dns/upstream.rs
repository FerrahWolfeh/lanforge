use std::{net::SocketAddr, str::FromStr};

use serde::{Deserialize, Serialize};

/// Supported protocols for upstream DNS forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    /// Standard DNS over UDP (with TCP fallback).
    Udp,
    /// DNS over TLS (`DoT`).
    Tls,
    /// DNS over QUIC (`DoQ`).
    Quic,
    /// DNS over HTTPS (`DoH`).
    Https,
}

impl std::str::FromStr for UpstreamProtocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tls" => Ok(Self::Tls),
            "quic" => Ok(Self::Quic),
            "https" => Ok(Self::Https),
            _ => Err(format!("Invalid upstream protocol: {s}")),
        }
    }
}

impl std::fmt::Display for UpstreamProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "udp"),
            Self::Tls => write!(f, "tls"),
            Self::Quic => write!(f, "quic"),
            Self::Https => write!(f, "https"),
        }
    }
}

impl UpstreamProtocol {
    /// Returns the implicit security tier (lower = more preferred).
    #[must_use]
    pub const fn tier(self) -> u8 {
        match self {
            Self::Tls | Self::Quic => 0,
            Self::Https => 1,
            Self::Udp => 2,
        }
    }
}

/// An upstream resolver target with protocol and optional hostname for verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct UpstreamTarget {
    /// The IP address and port of the upstream resolver.
    pub addr: SocketAddr,
    /// The protocol to use for forwarding.
    pub protocol: UpstreamProtocol,
    /// Optional hostname for TLS SNI and certificate validation (required for `DoT`).
    pub hostname: Option<String>,
    /// Optional domain suffix for conditional split-DNS forwarding.
    pub domain: Option<String>,
}

/// An upstream target resolver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "UpstreamEntryDe", into = "UpstreamEntryDe")]
pub struct UpstreamEntry {
    /// The target resolver.
    pub target: UpstreamTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum UpstreamEntryDe {
    Target { target: UpstreamTarget },
    Detailed {
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        #[serde(default)]
        domain: Option<String>,
    },
}

impl From<UpstreamEntryDe> for UpstreamEntry {
    fn from(de: UpstreamEntryDe) -> Self {
        match de {
            UpstreamEntryDe::Target { target } => Self { target },
            UpstreamEntryDe::Detailed {
                addr,
                protocol,
                domain,
            } => Self {
                target: UpstreamTarget {
                    addr,
                    protocol,
                    hostname: if protocol == UpstreamProtocol::Udp {
                        None
                    } else {
                        domain.clone()
                    },
                    domain,
                },
            },
        }
    }
}

impl From<UpstreamEntry> for UpstreamEntryDe {
    fn from(entry: UpstreamEntry) -> Self {
        Self::Target {
            target: entry.target,
        }
    }
}


fn parse_secure_target(stripped: &str) -> (Option<String>, &str) {
    stripped.find('@').map_or_else(
        || {
            if stripped.starts_with('[') || stripped.parse::<SocketAddr>().is_ok() {
                (None, stripped)
            } else if let Some(pos) = stripped.find(':') {
                let (h, _) = stripped.split_at(pos);
                (Some(h.to_string()), stripped)
            } else {
                (Some(stripped.to_string()), stripped)
            }
        },
        |pos| {
            let (h, rest) = stripped.split_at(pos);
            (Some(h.to_string()), &rest[1..])
        },
    )
}

impl FromStr for UpstreamTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (s, domain) = s
            .find('#')
            .map_or((s, None), |idx| (&s[..idx], Some(s[idx + 1..].to_string())));

        if let Some(stripped) = s.strip_prefix("tls://") {
            let (hostname, addr_str) = parse_secure_target(stripped);

            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid TLS address '{addr_str}': {e}"))?;
            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Tls,
                hostname,
                domain,
            })
        } else if let Some(stripped) = s.strip_prefix("quic://") {
            let (hostname, addr_str) = parse_secure_target(stripped);

            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid QUIC address '{addr_str}': {e}"))?;

            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Quic,
                hostname,
                domain,
            })
        } else if let Some(stripped) = s.strip_prefix("https://") {
            let (hostname, addr_str) = parse_secure_target(stripped);

            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid HTTPS address '{addr_str}': {e}"))?;

            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Https,
                hostname,
                domain,
            })
        } else {
            let addr_str = s.strip_prefix("udp://").unwrap_or(s);
            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid UDP address '{addr_str}': {e}"))?;
            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Udp,
                hostname: None,
                domain,
            })
        }
    }
}

impl std::fmt::Display for UpstreamTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.protocol {
            UpstreamProtocol::Tls => {
                if let Some(ref hn) = self.hostname {
                    write!(f, "tls://{}@{}", hn, self.addr)?;
                } else {
                    write!(f, "tls://{}", self.addr)?;
                }
            }
            UpstreamProtocol::Quic => {
                if let Some(ref hn) = self.hostname {
                    write!(f, "quic://{}@{}", hn, self.addr)?;
                } else {
                    write!(f, "quic://{}", self.addr)?;
                }
            }
            UpstreamProtocol::Https => {
                if let Some(ref hn) = self.hostname {
                    write!(f, "https://{}@{}", hn, self.addr)?;
                } else {
                    write!(f, "https://{}", self.addr)?;
                }
            }
            UpstreamProtocol::Udp => write!(f, "udp://{}", self.addr)?,
        }
        if let Some(ref d) = self.domain {
            write!(f, "#{d}")?;
        }
        Ok(())
    }
}

impl From<UpstreamTarget> for String {
    fn from(target: UpstreamTarget) -> Self {
        target.to_string()
    }
}

impl TryFrom<String> for UpstreamTarget {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}
