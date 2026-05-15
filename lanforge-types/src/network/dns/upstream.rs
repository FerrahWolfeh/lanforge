use std::{net::SocketAddr, str::FromStr};

use serde::{Deserialize, Serialize};

/// Supported protocols for upstream DNS forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UpstreamTarget {
    /// The IP address and port of the upstream resolver.
    pub addr: SocketAddr,
    /// The protocol to use for forwarding.
    pub protocol: UpstreamProtocol,
    /// Optional hostname for TLS SNI and certificate validation (required for `DoT`).
    pub hostname: Option<String>,
}

/// An upstream target resolver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamEntry {
    /// The target resolver.
    pub target: UpstreamTarget,
}

impl FromStr for UpstreamTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("tls://") {
            let (hostname, addr_str) = stripped.find('@').map_or_else(
                || {
                    let (hostname, addr_str) = stripped.find(':').map_or_else(
                        || (Some(stripped.to_string()), stripped),
                        |pos| {
                            let (h, _) = stripped.split_at(pos);
                            (Some(h.to_string()), stripped)
                        },
                    );
                    (hostname, addr_str)
                },
                |pos| {
                    let (h, rest) = stripped.split_at(pos);
                    (Some(h.to_string()), &rest[1..])
                },
            );

            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid TLS address '{addr_str}': {e}"))?;
            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Tls,
                hostname,
            })
        } else if let Some(stripped) = s.strip_prefix("quic://") {
            let (hostname, addr_str) = stripped.find('@').map_or_else(
                || {
                    let (hostname, addr_str) = stripped.find(':').map_or_else(
                        || (Some(stripped.to_string()), stripped),
                        |pos| {
                            let (h, _) = stripped.split_at(pos);
                            (Some(h.to_string()), stripped)
                        },
                    );
                    (hostname, addr_str)
                },
                |pos| {
                    let (h, rest) = stripped.split_at(pos);
                    (Some(h.to_string()), &rest[1..])
                },
            );

            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid QUIC address '{addr_str}': {e}"))?;

            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Quic,
                hostname,
            })
        } else if let Some(stripped) = s.strip_prefix("https://") {
            let (hostname, addr_str) = stripped.find('@').map_or_else(
                || {
                    let (hostname, addr_str) = stripped.find(':').map_or_else(
                        || (Some(stripped.to_string()), stripped),
                        |pos| {
                            let (h, _) = stripped.split_at(pos);
                            (Some(h.to_string()), stripped)
                        },
                    );
                    (hostname, addr_str)
                },
                |pos| {
                    let (h, rest) = stripped.split_at(pos);
                    (Some(h.to_string()), &rest[1..])
                },
            );

            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid HTTPS address '{addr_str}': {e}"))?;

            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Https,
                hostname,
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
            })
        }
    }
}

impl From<UpstreamTarget> for String {
    fn from(target: UpstreamTarget) -> Self {
        match target.protocol {
            UpstreamProtocol::Tls => format!("tls://{}", target.addr),
            UpstreamProtocol::Quic => format!("quic://{}", target.addr),
            UpstreamProtocol::Https => format!("https://{}", target.addr),
            UpstreamProtocol::Udp => format!("udp://{}", target.addr),
        }
    }
}

impl TryFrom<String> for UpstreamTarget {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}
