use crate::network::DnsRecordType;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::identifiers::DeviceIdentifier;

/// DNS service protocols (tcp, udp) for SRV records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsServiceProtocol {
    Tcp,
    Udp,
}

impl FromStr for DnsServiceProtocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let cleaned = trimmed.strip_prefix('_').unwrap_or(trimmed);
        match cleaned.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(format!("Invalid DNS service protocol: {s}")),
        }
    }
}

impl Display for DnsServiceProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

impl DnsServiceProtocol {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "_tcp",
            Self::Udp => "_udp",
        }
    }
}

/// Common homelab DNS services for SRV discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsService {
    Http,
    Https,
    Ssh,
    Ftp,
    Minecraft,
    Plex,
    Jellyfin,
    Ldap,
    Custom(String),
}

impl FromStr for DnsService {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let cleaned = trimmed.strip_prefix('_').unwrap_or(trimmed);
        let lower = cleaned.to_ascii_lowercase();
        match lower.as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "ssh" => Ok(Self::Ssh),
            "ftp" => Ok(Self::Ftp),
            "minecraft" => Ok(Self::Minecraft),
            "plex" => Ok(Self::Plex),
            "jellyfin" => Ok(Self::Jellyfin),
            "ldap" => Ok(Self::Ldap),
            _ => {
                if lower.is_empty() {
                    Err("Empty DNS service name".to_string())
                } else if !lower.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    Err("Invalid DNS service name characters".to_string())
                } else {
                    Ok(Self::Custom(lower))
                }
            }
        }
    }
}

impl Display for DnsService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::Ssh => write!(f, "ssh"),
            Self::Ftp => write!(f, "ftp"),
            Self::Minecraft => write!(f, "minecraft"),
            Self::Plex => write!(f, "plex"),
            Self::Jellyfin => write!(f, "jellyfin"),
            Self::Ldap => write!(f, "ldap"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

impl DnsService {
    #[must_use]
    pub fn to_srv_name(&self) -> Cow<'_, str> {
        match self {
            Self::Http => Cow::Borrowed("_http"),
            Self::Https => Cow::Borrowed("_https"),
            Self::Ssh => Cow::Borrowed("_ssh"),
            Self::Ftp => Cow::Borrowed("_ftp"),
            Self::Minecraft => Cow::Borrowed("_minecraft"),
            Self::Plex => Cow::Borrowed("_plex"),
            Self::Jellyfin => Cow::Borrowed("_jellyfin"),
            Self::Ldap => Cow::Borrowed("_ldap"),
            Self::Custom(name) => Cow::Owned(format!("_{name}")),
        }
    }
}

/// Represents a DNS rewrite rule (domain -> IP/Hostname).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct RewriteRule {
    pub id: Option<i64>,
    pub domain: String,
    pub rtype: DnsRecordType,
    pub answer: RewriteAnswer,
}

impl RewriteRule {
    #[must_use]
    pub fn parse_answer(&self) -> RewriteAnswer {
        self.answer.clone()
    }
}

/// Parsed DNS rewrite answer.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RewriteAnswer {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Device {
        identifier: DeviceIdentifier,
        fallback: Option<Box<Self>>,
    },
    Service {
        service: DnsService,
        protocol: DnsServiceProtocol,
        device: DeviceIdentifier,
        port: u16,
    },
}

impl FromStr for RewriteAnswer {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(srv_content) = s.strip_prefix("srv:") {
            let parts: Vec<&str> = srv_content.split(':').collect();
            if parts.len() < 4 {
                return Err("Invalid SRV rewrite answer format, expected srv:<service>:<protocol>:<device>:<port>".to_string());
            }
            let service = parts[0].parse::<DnsService>()?;
            let protocol = parts[1].parse::<DnsServiceProtocol>()?;
            let port_str = parts
                .last()
                .ok_or_else(|| "Missing port in SRV rewrite answer".to_string())?;
            let port = port_str
                .parse::<u16>()
                .map_err(|e| format!("Invalid port in SRV: {e}"))?;
            let device_str = parts[2..parts.len() - 1].join(":");
            let device = device_str.parse::<DeviceIdentifier>()?;
            return Ok(Self::Service {
                service,
                protocol,
                device,
                port,
            });
        }

        s.parse::<Ipv4Addr>().map_or_else(
            |_| {
                s.parse::<Ipv6Addr>().map_or_else(
                    |_| {
                        s.strip_prefix("dev:").map_or_else(
                            || {
                                if s.contains('.') {
                                    Ok(Self::Cname(s.to_string()))
                                } else {
                                    let id = s.parse::<DeviceIdentifier>()?;
                                    Ok(Self::Device {
                                        identifier: id,
                                        fallback: None,
                                    })
                                }
                            },
                            |dev_content| {
                                if let Some((id_str, fallback_str)) = dev_content.split_once('|') {
                                    let id = id_str.parse::<DeviceIdentifier>()?;
                                    let fallback = fallback_str.parse::<Self>()?;
                                    Ok(Self::Device {
                                        identifier: id,
                                        fallback: Some(Box::new(fallback)),
                                    })
                                } else {
                                    let id = dev_content.parse::<DeviceIdentifier>()?;
                                    Ok(Self::Device {
                                        identifier: id,
                                        fallback: None,
                                    })
                                }
                            },
                        )
                    },
                    |ip| Ok(Self::Aaaa(ip)),
                )
            },
            |ip| Ok(Self::A(ip)),
        )
    }
}

impl Display for RewriteAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(ip) => write!(f, "{ip}"),
            Self::Aaaa(ip) => write!(f, "{ip}"),
            Self::Cname(domain) => write!(f, "{domain}"),
            Self::Device {
                identifier,
                fallback,
            } => {
                if let Some(fb) = fallback {
                    write!(f, "dev:{identifier}|{fb}")
                } else {
                    write!(f, "dev:{identifier}")
                }
            }
            Self::Service {
                service,
                protocol,
                device,
                port,
            } => {
                write!(f, "srv:{service}:{protocol}:{device}:{port}")
            }
        }
    }
}

/// DNS blocking modes.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BlockingMode {
    /// Return NXDOMAIN (default).
    #[default]
    #[serde(rename = "nxdomain", alias = "nx_domain")]
    NxDomain,
    /// Return 0.0.0.0 (A) and :: (AAAA).
    NullIp,
    /// Return a custom user-specified IP address.
    CustomIp,
    /// Return REFUSED.
    Refused,
}

impl FromStr for BlockingMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nxdomain" | "nx_domain" => Ok(Self::NxDomain),
            "null_ip" | "nullip" => Ok(Self::NullIp),
            "custom_ip" | "customip" => Ok(Self::CustomIp),
            "refused" => Ok(Self::Refused),
            _ => Err(format!("Invalid blocking mode: {s}")),
        }
    }
}

impl Display for BlockingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NxDomain => write!(f, "nxdomain"),
            Self::NullIp => write!(f, "null_ip"),
            Self::CustomIp => write!(f, "custom_ip"),
            Self::Refused => write!(f, "refused"),
        }
    }
}

/// Adblock configuration as stored in DB.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AdblockDbConfig {
    pub enabled: bool,
    pub blocking_mode: BlockingMode,
    pub blocking_ip_v4: Option<Ipv4Addr>,
    pub blocking_ip_v6: Option<Ipv6Addr>,
    pub refresh_hours: u32,
    pub refresh_at_night: bool,
}

impl Default for AdblockDbConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            blocking_mode: BlockingMode::default(),
            blocking_ip_v4: None,
            blocking_ip_v6: None,
            refresh_hours: 12,
            refresh_at_night: false,
        }
    }
}

/// Adblock source URL kind.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdblockUrlKind {
    #[default]
    Blocklist,
    Allowlist,
}

impl FromStr for AdblockUrlKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "blocklist" => Ok(Self::Blocklist),
            "allowlist" => Ok(Self::Allowlist),
            _ => Err(format!("Invalid adblock URL kind: {s}")),
        }
    }
}

impl Display for AdblockUrlKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocklist => write!(f, "blocklist"),
            Self::Allowlist => write!(f, "allowlist"),
        }
    }
}

/// Format of an adblock source list.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdblockSourceFormat {
    #[default]
    Auto,
    Adblock,
    Hosts,
    Domains,
    WildcardDomains,
}

impl FromStr for AdblockSourceFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "auto" => Ok(Self::Auto),
            "adblock" => Ok(Self::Adblock),
            "hosts" => Ok(Self::Hosts),
            "domains" => Ok(Self::Domains),
            "wildcard_domains" | "wildcard" => Ok(Self::WildcardDomains),
            _ => Err(format!("Invalid adblock source format: {s}")),
        }
    }
}

impl AdblockSourceFormat {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Adblock => "adblock",
            Self::Hosts => "hosts",
            Self::Domains => "domains",
            Self::WildcardDomains => "wildcard_domains",
        }
    }
}

impl Display for AdblockSourceFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Action decided by the filter engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Block,
    Allow,
}

impl FilterAction {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
        }
    }
}

impl Display for FilterAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Origin of a filter rule match.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FilterOrigin {
    UserRule,
    UserAllowlist,
    List { source_id: i64 },
}

/// Detailed filter match attribution for query logging and diagnostic checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterMatch {
    pub action: FilterAction,
    pub origin: FilterOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<Box<str>>,
    #[serde(default)]
    pub important: bool,
}

/// Action associated with a custom adblock user rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AdblockRuleAction {
    #[default]
    Block,
    Allow,
}

impl AdblockRuleAction {
    #[must_use]
    pub const fn is_block(self) -> bool {
        matches!(self, Self::Block)
    }

    #[must_use]
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
        }
    }
}

impl std::fmt::Display for AdblockRuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AdblockRuleAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "allow" => Ok(Self::Allow),
            other => Err(format!("Unknown rule action: '{other}'. Expected 'block' or 'allow'")),
        }
    }
}

/// A custom adblock rule (allowlist or manual blocklist).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AdblockRuleEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub domain: String,
    pub action: AdblockRuleAction,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_true() -> bool {
    true
}

impl AdblockRuleEntry {
    #[must_use]
    pub const fn is_block(&self) -> bool {
        self.action.is_block()
    }

    #[must_use]
    pub const fn is_allow(&self) -> bool {
        self.action.is_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_device_identifier_parsing() {
        // Name
        let name_id = DeviceIdentifier::from_str("nas-box").unwrap();
        assert_eq!(name_id, DeviceIdentifier::Name("nas-box".to_string()));
        assert_eq!(name_id.to_string(), "nas-box");

        // MAC
        let mac_id = DeviceIdentifier::from_str("e0:d5:5e:e2:d4:89").unwrap();
        assert!(matches!(mac_id, DeviceIdentifier::Mac(_)));
        assert_eq!(mac_id.to_string(), "e0:d5:5e:e2:d4:89");

        // Invalid
        assert!(DeviceIdentifier::from_str("").is_err());
        assert!(DeviceIdentifier::from_str("a".repeat(64).as_str()).is_err());
        assert!(DeviceIdentifier::from_str("-invalid").is_err());
        assert!(DeviceIdentifier::from_str("invalid-").is_err());
        assert!(DeviceIdentifier::from_str("invalid_name").is_err());
    }

    #[test]
    fn test_rewrite_answer_parsing_and_display() {
        // A / Aaaa
        let a_ans = RewriteAnswer::from_str("192.168.1.10").unwrap();
        assert!(matches!(a_ans, RewriteAnswer::A(_)));
        assert_eq!(a_ans.to_string(), "192.168.1.10");

        // Device Name
        let dev_name = RewriteAnswer::from_str("dev:nas-box").unwrap();
        if let RewriteAnswer::Device {
            identifier,
            fallback,
        } = &dev_name
        {
            assert_eq!(identifier, &DeviceIdentifier::Name("nas-box".to_string()));
            assert!(fallback.is_none());
        } else {
            panic!("Expected Device answer");
        }
        assert_eq!(dev_name.to_string(), "dev:nas-box");

        // Device MAC
        let dev_mac = RewriteAnswer::from_str("dev:e0:d5:5e:e2:d4:89").unwrap();
        if let RewriteAnswer::Device {
            identifier,
            fallback,
        } = &dev_mac
        {
            assert!(matches!(identifier, DeviceIdentifier::Mac(_)));
            assert!(fallback.is_none());
        } else {
            panic!("Expected Device answer");
        }
        assert_eq!(dev_mac.to_string(), "dev:e0:d5:5e:e2:d4:89");

        // Device with fallback IP
        let dev_fb = RewriteAnswer::from_str("dev:nas-box|192.168.1.1").unwrap();
        if let RewriteAnswer::Device {
            identifier,
            fallback,
        } = &dev_fb
        {
            assert_eq!(identifier, &DeviceIdentifier::Name("nas-box".to_string()));
            assert!(matches!(fallback.as_deref(), Some(RewriteAnswer::A(_))));
        } else {
            panic!("Expected Device answer with fallback");
        }
        assert_eq!(dev_fb.to_string(), "dev:nas-box|192.168.1.1");

        // Service Discovery
        let srv_ans = RewriteAnswer::from_str("srv:http:tcp:nas-box:8096").unwrap();
        if let RewriteAnswer::Service {
            service,
            protocol,
            device,
            port,
        } = &srv_ans
        {
            assert_eq!(service, &DnsService::Http);
            assert_eq!(protocol, &DnsServiceProtocol::Tcp);
            assert_eq!(device, &DeviceIdentifier::Name("nas-box".to_string()));
            assert_eq!(*port, 8096);
        } else {
            panic!("Expected Service answer");
        }
        assert_eq!(srv_ans.to_string(), "srv:http:tcp:nas-box:8096");

        // Service with MAC and Custom Service name
        let srv_mac = RewriteAnswer::from_str("srv:my-app:udp:e0:d5:5e:e2:d4:89:5000").unwrap();
        if let RewriteAnswer::Service {
            service,
            protocol,
            device,
            port,
        } = &srv_mac
        {
            assert_eq!(service, &DnsService::Custom("my-app".to_string()));
            assert_eq!(protocol, &DnsServiceProtocol::Udp);
            assert!(matches!(device, DeviceIdentifier::Mac(_)));
            assert_eq!(*port, 5000);
        } else {
            panic!("Expected Service answer");
        }
        assert_eq!(srv_mac.to_string(), "srv:my-app:udp:e0:d5:5e:e2:d4:89:5000");
    }
}
