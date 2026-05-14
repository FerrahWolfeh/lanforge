use crate::identifiers::MacAddr;
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

/// Supported DNS record types in Lanforge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u16)]
pub enum DnsRecordType {
    #[default]
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    SVCB = 64,
    HTTPS = 65,
    ANY = 255,
    Unknown(u16),
}

impl From<u16> for DnsRecordType {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            13 => Self::HINFO,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            41 => Self::OPT,
            64 => Self::SVCB,
            65 => Self::HTTPS,
            255 => Self::ANY,
            v => Self::Unknown(v),
        }
    }
}

impl From<DnsRecordType> for u16 {
    fn from(val: DnsRecordType) -> Self {
        match val {
            DnsRecordType::A => 1,
            DnsRecordType::NS => 2,
            DnsRecordType::CNAME => 5,
            DnsRecordType::SOA => 6,
            DnsRecordType::PTR => 12,
            DnsRecordType::HINFO => 13,
            DnsRecordType::MX => 15,
            DnsRecordType::TXT => 16,
            DnsRecordType::AAAA => 28,
            DnsRecordType::SRV => 33,
            DnsRecordType::OPT => 41,
            DnsRecordType::SVCB => 64,
            DnsRecordType::HTTPS => 65,
            DnsRecordType::ANY => 255,
            DnsRecordType::Unknown(v) => v,
        }
    }
}

impl std::str::FromStr for DnsRecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::NS),
            "CNAME" => Ok(Self::CNAME),
            "SOA" => Ok(Self::SOA),
            "PTR" => Ok(Self::PTR),
            "HINFO" => Ok(Self::HINFO),
            "MX" => Ok(Self::MX),
            "TXT" => Ok(Self::TXT),
            "AAAA" => Ok(Self::AAAA),
            "SRV" => Ok(Self::SRV),
            "OPT" => Ok(Self::OPT),
            "SVCB" => Ok(Self::SVCB),
            "HTTPS" => Ok(Self::HTTPS),
            "ANY" => Ok(Self::ANY),
            _ => {
                if s.starts_with("TYPE")
                    && let Ok(v) = s[4..].parse::<u16>()
                {
                    return Ok(Self::Unknown(v));
                }
                Err(format!("Unknown DNS record type: {s}"))
            }
        }
    }
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::NS => write!(f, "NS"),
            Self::CNAME => write!(f, "CNAME"),
            Self::SOA => write!(f, "SOA"),
            Self::PTR => write!(f, "PTR"),
            Self::HINFO => write!(f, "HINFO"),
            Self::MX => write!(f, "MX"),
            Self::TXT => write!(f, "TXT"),
            Self::AAAA => write!(f, "AAAA"),
            Self::SRV => write!(f, "SRV"),
            Self::OPT => write!(f, "OPT"),
            Self::SVCB => write!(f, "SVCB"),
            Self::HTTPS => write!(f, "HTTPS"),
            Self::ANY => write!(f, "ANY"),
            Self::Unknown(v) => write!(f, "TYPE{v}"),
        }
    }
}

/// Serializable snapshot of upstream health metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamHealthSnapshot {
    pub target: String,
    pub protocol: String,
    pub rtt_ewma_us: u32,
    pub last_rtt_us: u32,
    pub total_queries: u64,
    pub total_successes: u64,
    pub total_failures: u64,
    pub status: String,
    pub last_success_secs_ago: Option<u64>,
}

/// The result of a DNS query resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum QueryResult {
    /// Answered authoritatively from local state.
    Local = 0,
    /// Forwarded to upstream and got a response.
    Forwarded = 1,
    /// Blocked by the filter engine.
    Blocked = 2,
    /// NXDOMAIN (host not found anywhere).
    NxDomain = 3,
    /// Upstream error or timeout.
    Error = 4,
    /// Answered from the upstream cache.
    Cached = 5,
    /// Answered via a DNS rewrite rule.
    Rewritten = 6,
    /// Answered from the cache as a blocked domain.
    CachedBlock = 7,
}

/// Transport protocols for incoming and outgoing DNS queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Udp,
    Tcp,
    Tls,
    Quic,
    Https,
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Tls => write!(f, "DoT"),
            Self::Quic => write!(f, "DoQ"),
            Self::Https => write!(f, "DoH"),
        }
    }
}

/// A manual DNS rewrite rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewriteRule {
    /// The domain name to match (e.g., "nas.example.com").
    pub domain: String,
    /// The answer to return. Can be an IP, another domain, or a device reference.
    pub answer: String,
}

/// How to respond to queries blocked by the adblocker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockingMode {
    /// Return NXDOMAIN (default).
    #[default]
    NxDomain,
    /// Return 0.0.0.0 (A) and :: (AAAA).
    NullIp,
    /// Return a custom user-specified IP address.
    CustomIp,
    /// Return REFUSED.
    Refused,
}

impl std::str::FromStr for BlockingMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nxdomain" => Ok(Self::NxDomain),
            "null_ip" | "null" | "zero" => Ok(Self::NullIp),
            "custom_ip" | "custom" => Ok(Self::CustomIp),
            "refused" => Ok(Self::Refused),
            _ => Err(format!("Invalid blocking mode: {s}")),
        }
    }
}

/// Adblock source URL kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AdblockUrlKind {
    #[default]
    Block,
    Allow,
}

impl std::fmt::Display for AdblockUrlKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Allow => write!(f, "allow"),
        }
    }
}

impl std::str::FromStr for AdblockUrlKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "allow" => Ok(Self::Allow),
            _ => Err(format!("Invalid adblock URL kind: {s}")),
        }
    }
}

/// Consolidated adblock configuration from the database.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdblockDbConfig {
    pub enabled: bool,
    pub blocking_mode: BlockingMode,
    pub blocking_ip_v4: Option<Ipv4Addr>,
    pub blocking_ip_v6: Option<Ipv6Addr>,
    pub refresh_hours: u32,
    pub refresh_at_night: bool,
}

/// A single DNS query log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    /// Unix epoch seconds.
    pub timestamp: u64,
    /// Client IP address.
    pub src_ip: std::net::IpAddr,
    /// Domain name queried.
    pub domain: Arc<str>,
    /// Time spent in microseconds (0 for local/cached).
    pub upstream_us: u32,
    /// Query type (A, AAAA, PTR, etc.).
    pub qtype: DnsRecordType,
    /// Outcome of the query.
    pub result: QueryResult,
    /// Whether the response came from the upstream cache.
    pub cached: bool,
    /// Client MAC address (if known).
    pub src_mac: Option<MacAddr>,
    /// Summary of the response data (e.g., first IP address).
    pub answer: Option<String>,
    /// Transport protocol used.
    pub protocol: TransportProtocol,
}

/// A single DNS record entry.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DnsRecordEntry {
    pub name: String,
    pub kind: DnsRecordType,
    pub data: String,
    pub ttl: u32,
}

/// DNS Response Codes (RCODE) as defined in RFC 1035 and updated by others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DnsResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    BADVERS = 16, // EDNS
    Unknown(u8),
}

impl From<u8> for DnsResponseCode {
    fn from(val: u8) -> Self {
        match val & 0x0F {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YXDomain,
            7 => Self::YXRRSet,
            8 => Self::NXRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            16 => Self::BADVERS,
            v => Self::Unknown(v),
        }
    }
}

impl From<DnsResponseCode> for u8 {
    fn from(val: DnsResponseCode) -> Self {
        match val {
            DnsResponseCode::NoError => 0,
            DnsResponseCode::FormErr => 1,
            DnsResponseCode::ServFail => 2,
            DnsResponseCode::NXDomain => 3,
            DnsResponseCode::NotImp => 4,
            DnsResponseCode::Refused => 5,
            DnsResponseCode::YXDomain => 6,
            DnsResponseCode::YXRRSet => 7,
            DnsResponseCode::NXRRSet => 8,
            DnsResponseCode::NotAuth => 9,
            DnsResponseCode::NotZone => 10,
            DnsResponseCode::BADVERS => 16,
            DnsResponseCode::Unknown(v) => v,
        }
    }
}

/// DNS Classes as defined in RFC 1035.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum DnsClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255,
    Unknown(u16),
}

impl From<u16> for DnsClass {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            255 => Self::ANY,
            v => Self::Unknown(v),
        }
    }
}

impl From<DnsClass> for u16 {
    fn from(val: DnsClass) -> Self {
        match val {
            DnsClass::IN => 1,
            DnsClass::CS => 2,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
            DnsClass::ANY => 255,
            DnsClass::Unknown(v) => v,
        }
    }
}

/// DNS Message Header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8, // 4 bits
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: bool, // Reserved
    pub ad: bool,
    pub cd: bool,
    pub rcode: DnsResponseCode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: false,
            ad: false,
            cd: false,
            rcode: DnsResponseCode::NoError,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}

/// DNS Question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: Arc<str>,
    pub qtype: DnsRecordType,
    pub qclass: DnsClass,
}

/// DNS Resource Data variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(Arc<str>),
    PTR(Arc<str>),
    MX {
        preference: u16,
        exchange: Arc<str>,
    },
    NS(Arc<str>),
    TXT(Vec<Arc<str>>),
    SOA {
        mname: Arc<str>,
        rname: Arc<str>,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: Arc<str>,
    },
    OPT {
        options: Vec<(u16, Vec<u8>)>,
    },
    Unknown(Vec<u8>),
}

impl std::fmt::Display for DnsRData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(addr) => write!(f, "{}", addr),
            Self::AAAA(addr) => write!(f, "{}", addr),
            Self::CNAME(name) => write!(f, "{}", name),
            Self::PTR(name) => write!(f, "{}", name),
            Self::MX {
                preference,
                exchange,
            } => write!(f, "{} {}", preference, exchange),
            Self::NS(name) => write!(f, "{}", name),
            Self::TXT(txt) => write!(f, "{}", txt.join(" ")),
            Self::SOA { mname, .. } => write!(f, "SOA {}", mname),
            Self::SRV { target, port, .. } => write!(f, "{}:{}", target, port),
            Self::OPT { .. } => write!(f, "EDNS"),
            Self::Unknown(_) => write!(f, "Unknown"),
        }
    }
}

/// DNS Resource Record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: Arc<str>,
    pub rtype: DnsRecordType,
    pub rclass: DnsClass,
    pub ttl: u32,
    pub rdata: DnsRData,
}

/// A complete DNS Message.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::fmt::Display for DnsRecordEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<5} {:<20} -> {}", self.kind, self.name, self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_record_type_parsing() {
        assert_eq!(DnsRecordType::from(64), DnsRecordType::SVCB);
        assert_eq!(DnsRecordType::from(65), DnsRecordType::HTTPS);
        assert_eq!(u16::from(DnsRecordType::SVCB), 64);
        assert_eq!(u16::from(DnsRecordType::HTTPS), 65);

        assert_eq!(
            "SVCB".parse::<DnsRecordType>().unwrap(),
            DnsRecordType::SVCB
        );
        assert_eq!(
            "https".parse::<DnsRecordType>().unwrap(),
            DnsRecordType::HTTPS
        );

        assert_eq!(DnsRecordType::SVCB.to_string(), "SVCB");
        assert_eq!(DnsRecordType::HTTPS.to_string(), "HTTPS");
    }
}
