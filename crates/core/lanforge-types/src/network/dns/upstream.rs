use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

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

impl FromStr for UpstreamProtocol {
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

impl Display for UpstreamProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => write!(f, "udp"),
            Self::Tls => write!(f, "tls"),
            Self::Quic => write!(f, "quic"),
            Self::Https => write!(f, "https"),
        }
    }
}

impl UpstreamProtocol {
    /// The port a target without one uses: 53, 853 (RFC 7858, RFC 9250) or 443.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Udp => 53,
            Self::Tls | Self::Quic => 853,
            Self::Https => 443,
        }
    }

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

/// Upstream resolution strategy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    #[default]
    Sequential,
    Parallel,
    Fastest,
    RoundRobin,
}

impl FromStr for UpstreamMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sequential" => Ok(Self::Sequential),
            "parallel" => Ok(Self::Parallel),
            "fastest" => Ok(Self::Fastest),
            "roundrobin" | "round-robin" | "round_robin" => Ok(Self::RoundRobin),
            _ => Err(format!("Invalid upstream mode: {s}")),
        }
    }
}

impl Display for UpstreamMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequential => write!(f, "sequential"),
            Self::Parallel => write!(f, "parallel"),
            Self::Fastest => write!(f, "fastest"),
            Self::RoundRobin => write!(f, "roundrobin"),
        }
    }
}

/// Where an upstream resolver is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamAddr {
    /// A fixed address.
    Ip(SocketAddr),
    /// The target's `hostname`, resolved through the bootstrap resolvers, on this port.
    Name(u16),
}

impl UpstreamAddr {
    /// The fixed address; `None` for a host name.
    #[must_use]
    pub const fn ip(self) -> Option<SocketAddr> {
        match self {
            Self::Ip(addr) => Some(addr),
            Self::Name(_) => None,
        }
    }

    #[must_use]
    pub const fn port(self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Name(port) => port,
        }
    }
}

/// An upstream resolver: `[udp|tls|quic|https]://[<tls name>@]<ip>[:<port>][#<domain>]`.
///
/// A host name can stand in place of the address (`tls://dns.google`,
/// `https://dns.google/dns-query`): the DNS looks it up through its bootstrap resolvers. Without
/// a port, the protocol's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct UpstreamTarget {
    /// The address, or the port of a host name (`hostname`).
    pub addr: UpstreamAddr,
    /// The protocol to use for forwarding.
    pub protocol: UpstreamProtocol,
    /// TLS SNI and certificate name; for an [`UpstreamAddr::Name`], also the name resolved.
    pub hostname: Option<String>,
    /// `DoH` request path; `None` = `/dns-query`.
    pub path: Option<String>,
    /// Optional domain suffix for conditional split-DNS forwarding.
    pub domain: Option<String>,
}

impl UpstreamTarget {
    /// The `DoH` path when the URL names none (RFC 8484 §3 leaves it to the server; this is the
    /// one public resolvers use).
    pub const DEFAULT_DOH_PATH: &'static str = "/dns-query";

    /// A target at a fixed address, without a TLS name.
    #[must_use]
    pub const fn at(addr: SocketAddr, protocol: UpstreamProtocol, domain: Option<String>) -> Self {
        Self {
            addr: UpstreamAddr::Ip(addr),
            protocol,
            hostname: None,
            path: None,
            domain,
        }
    }

    /// The host name to resolve; `None` for a fixed address.
    #[must_use]
    pub fn host_name(&self) -> Option<&str> {
        match self.addr {
            UpstreamAddr::Ip(_) => None,
            UpstreamAddr::Name(_) => self.hostname.as_deref(),
        }
    }

    /// The `DoH` request path.
    #[must_use]
    pub fn doh_path(&self) -> &str {
        self.path.as_deref().unwrap_or(Self::DEFAULT_DOH_PATH)
    }
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
    Target {
        target: UpstreamTarget,
    },
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
                    addr: UpstreamAddr::Ip(addr),
                    protocol,
                    hostname: if protocol == UpstreamProtocol::Udp {
                        None
                    } else {
                        domain.clone()
                    },
                    path: None,
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

/// A host name an upstream can be reached by: dotted labels of letters, digits and hyphens. The
/// last label is not all digits, so a mistyped address (`1.1.1.300`) is no name.
fn is_host_name(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

impl FromStr for UpstreamTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (body, domain) = s
            .split_once('#')
            .map_or((s, None), |(b, d)| (b, Some(d.to_string())));
        let (scheme, rest) = body.split_once("://").unwrap_or(("udp", body));
        let protocol: UpstreamProtocol = match scheme {
            "udp" | "tls" | "quic" | "https" => scheme.parse()?,
            _ => return Err(format!("\"{scheme}://\" is not udp, tls, quic or https")),
        };
        let (authority, path) = match rest.find('/') {
            Some(at) if protocol == UpstreamProtocol::Https => {
                (&rest[..at], Some(rest[at..].to_string()))
            }
            Some(_) => return Err(format!("\"{s}\": only https:// takes a path")),
            None => (rest, None),
        };
        let (tls_name, host) = authority
            .rsplit_once('@')
            .map_or((None, authority), |(n, h)| (Some(n), h));
        if tls_name.is_some() && protocol == UpstreamProtocol::Udp {
            return Err(format!("\"{s}\": udp has no TLS name"));
        }
        let default_port = protocol.default_port();
        let fixed = host.parse::<SocketAddr>().ok().or_else(|| {
            host.strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host)
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, default_port))
        });
        if let Some(addr) = fixed {
            return Ok(Self {
                addr: UpstreamAddr::Ip(addr),
                protocol,
                hostname: tls_name.map(str::to_string),
                path,
                domain,
            });
        }
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) => (
                name,
                port.parse()
                    .map_err(|_| format!("\"{s}\": invalid port \"{port}\""))?,
            ),
            None => (host, default_port),
        };
        if !is_host_name(name) {
            return Err(format!("\"{s}\" is not an address or a host name"));
        }
        if tls_name.is_some() {
            return Err(format!(
                "\"{s}\": a host name is its own TLS name; drop the \"<name>@\""
            ));
        }
        Ok(Self {
            addr: UpstreamAddr::Name(port),
            protocol,
            hostname: Some(name.to_ascii_lowercase()),
            path,
            domain,
        })
    }
}

impl Display for UpstreamTarget {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.protocol)?;
        match (self.addr, &self.hostname) {
            (UpstreamAddr::Ip(addr), Some(hn)) if self.protocol != UpstreamProtocol::Udp => {
                write!(f, "{hn}@{addr}")?;
            }
            (UpstreamAddr::Ip(addr), _) => write!(f, "{addr}")?,
            (UpstreamAddr::Name(port), name) => {
                write!(f, "{}", name.as_deref().unwrap_or_default())?;
                if port != self.protocol.default_port() {
                    write!(f, ":{port}")?;
                }
            }
        }
        if let Some(ref path) = self.path {
            write!(f, "{path}")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> UpstreamTarget {
        text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn host_names_take_the_protocols_port_and_keep_their_path() {
        let t = parse("tls://dns.google");
        assert_eq!(t.addr, UpstreamAddr::Name(853));
        assert_eq!(t.host_name(), Some("dns.google"));
        assert_eq!(t.to_string(), "tls://dns.google");

        let t = parse("https://Dns.NextDNS.io/abc123#corp");
        assert_eq!(t.addr, UpstreamAddr::Name(443));
        assert_eq!(t.host_name(), Some("dns.nextdns.io"));
        assert_eq!(t.doh_path(), "/abc123");
        assert_eq!(t.domain.as_deref(), Some("corp"));
        assert_eq!(t.to_string(), "https://dns.nextdns.io/abc123#corp");

        assert_eq!(
            parse("quic://dns.adguard-dns.com:8853").addr,
            UpstreamAddr::Name(8853)
        );
        assert_eq!(parse("dns.quad9.net").addr, UpstreamAddr::Name(53));
        assert_eq!(parse("https://dns.google").doh_path(), "/dns-query");
    }

    #[test]
    fn addresses_stay_addresses() {
        let t = parse("tls://one.one.one.one@1.1.1.1");
        assert_eq!(t.addr, UpstreamAddr::Ip("1.1.1.1:853".parse().unwrap()));
        assert_eq!(t.host_name(), None);
        assert_eq!(t.hostname.as_deref(), Some("one.one.one.one"));
        assert_eq!(
            parse("2606:4700:4700::1111").to_string(),
            "udp://[2606:4700:4700::1111]:53"
        );
        assert_eq!(
            parse("https://[::1]:8443/q").to_string(),
            "https://[::1]:8443/q"
        );
    }

    #[test]
    fn what_is_neither_an_address_nor_a_name_is_refused() {
        for bad in [
            "not-an-address",
            "1.1.1.300",
            "ftp://1.1.1.1",
            "tls://dns.google:x",
            "tls://sni.example@dns.google",
            "udp://name@1.1.1.1",
            "tls://dns.google/path",
            "udp://-bad.example",
            "",
        ] {
            assert!(bad.parse::<UpstreamTarget>().is_err(), "{bad} was accepted");
        }
    }
}
