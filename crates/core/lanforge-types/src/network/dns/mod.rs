use crate::{
    identifiers::MacAddr,
    network::dns::adblock::{AdblockUrlKind, BlockingMode},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

pub mod adblock;
pub use adblock::{AdblockSourceFormat, FilterAction, FilterMatch, FilterOrigin};
pub mod upstream;
pub use upstream::{UpstreamMode, UpstreamProtocol, UpstreamTarget};

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
    #[serde(rename = "DEVICE", alias = "Device", alias = "dev", alias = "A/AAAA")]
    Device = 65534,
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
            65534 => Self::Device,
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
            DnsRecordType::Device => 65534,
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
            "DEVICE" | "DEV" | "A/AAAA" => Ok(Self::Device),
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

impl DnsRecordType {
    /// Returns the numerical wire value for this DNS record type.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::PTR => 12,
            Self::HINFO => 13,
            Self::MX => 15,
            Self::TXT => 16,
            Self::AAAA => 28,
            Self::SRV => 33,
            Self::OPT => 41,
            Self::SVCB => 64,
            Self::HTTPS => 65,
            Self::ANY => 255,
            Self::Device => 65534,
            Self::Unknown(v) => v,
        }
    }

    #[must_use]
    pub const fn as_static_str(&self) -> Option<&'static str> {
        match self {
            Self::A => Some("A"),
            Self::NS => Some("NS"),
            Self::CNAME => Some("CNAME"),
            Self::SOA => Some("SOA"),
            Self::PTR => Some("PTR"),
            Self::HINFO => Some("HINFO"),
            Self::MX => Some("MX"),
            Self::TXT => Some("TXT"),
            Self::AAAA => Some("AAAA"),
            Self::SRV => Some("SRV"),
            Self::OPT => Some("OPT"),
            Self::SVCB => Some("SVCB"),
            Self::HTTPS => Some("HTTPS"),
            Self::ANY => Some("ANY"),
            Self::Device => Some("DEVICE"),
            Self::Unknown(_) => None,
        }
    }
}

impl Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = self.as_static_str() {
            f.write_str(s)
        } else if let Self::Unknown(v) = self {
            write!(f, "TYPE{v}")
        } else {
            Ok(())
        }
    }
}

/// Health status of an upstream DNS resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamStatus {
    #[default]
    Healthy,
    Degraded,
    Disabled,
}

impl UpstreamStatus {
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for UpstreamStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serializable snapshot of upstream health metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamHealthSnapshot {
    pub target: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub rtt_ewma_us: u32,
    pub last_rtt_us: u32,
    pub total_queries: u64,
    pub total_successes: u64,
    pub total_failures: u64,
    pub status: UpstreamStatus,
    pub last_success_secs_ago: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
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
    /// Answered by coalescing with an in-flight upstream query.
    Coalesced = 8,
}

impl std::fmt::Display for QueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "Local"),
            Self::Forwarded => write!(f, "Forwarded"),
            Self::Blocked => write!(f, "Blocked"),
            Self::NxDomain => write!(f, "NxDomain"),
            Self::Error => write!(f, "Error"),
            Self::Cached => write!(f, "Cached"),
            Self::Rewritten => write!(f, "Rewritten"),
            Self::CachedBlock => write!(f, "CachedBlock"),
            Self::Coalesced => write!(f, "Coalesced"),
        }
    }
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

impl Display for TransportProtocol {
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
    /// Adblock / filter match attribution.
    #[serde(default)]
    pub filter: Option<Box<FilterMatch>>,
    /// In-flight batch correlation ID when query was coalesced or was a coalesce leader.
    #[serde(default)]
    pub coalesce_id: Option<u64>,
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
#[allow(clippy::struct_excessive_bools)]
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

/// Detailed SOA (Start of Authority) record fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSoaData {
    pub mname: Arc<str>,
    pub rname: Arc<str>,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

/// Detailed SVCB / HTTPS service binding record fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSvcbData {
    pub svc_priority: u16,
    pub svc_domain: Arc<str>,
    pub params: Vec<(u16, Vec<u8>)>,
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
    SOA(Box<DnsSoaData>),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: Arc<str>,
    },
    OPT {
        options: Vec<(u16, Vec<u8>)>,
    },
    HTTPS(Box<DnsSvcbData>),
    SVCB(Box<DnsSvcbData>),
    Unknown(Vec<u8>),
}

impl Display for DnsRData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(addr) => write!(f, "{addr}"),
            Self::AAAA(addr) => write!(f, "{addr}"),
            Self::CNAME(name) | Self::PTR(name) | Self::NS(name) => write!(f, "{name}"),
            Self::MX {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            Self::TXT(txt) => write!(f, "{}", txt.join(" ")),
            Self::SOA(soa) => write!(f, "SOA {}", soa.mname),
            Self::SRV { target, port, .. } => write!(f, "{target}:{port}"),
            Self::OPT { .. } => write!(f, "EDNS"),
            Self::HTTPS(data) | Self::SVCB(data) => {
                let mut parts = vec![format!("{} {}", data.svc_priority, data.svc_domain)];
                for (key, val) in &data.params {
                    match *key {
                        1 => {
                            // alpn
                            let mut alpns = Vec::new();
                            let mut p = 0;
                            while p < val.len() {
                                let l = val[p] as usize;
                                if p + 1 + l > val.len() {
                                    break;
                                }
                                if let Ok(s) = std::str::from_utf8(&val[p + 1..p + 1 + l]) {
                                    alpns.push(s.to_string());
                                }
                                p += 1 + l;
                            }
                            if !alpns.is_empty() {
                                parts.push(format!("alpn=\"{}\"", alpns.join(",")));
                            }
                        }
                        3 => {
                            // port
                            if val.len() >= 2 {
                                let port = u16::from_be_bytes([val[0], val[1]]);
                                parts.push(format!("port={port}"));
                            }
                        }
                        4 => {
                            // ipv4hint
                            let mut ips = Vec::new();
                            for chunk in val.as_chunks::<4>().0 {
                                let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                                ips.push(ip.to_string());
                            }
                            if !ips.is_empty() {
                                parts.push(format!("ipv4hint={}", ips.join(",")));
                            }
                        }
                        6 => {
                            // ipv6hint
                            let mut ips = Vec::new();
                            for chunk in val.as_chunks::<16>().0 {
                                let mut b = [0u8; 16];
                                b.copy_from_slice(chunk);
                                let ip = Ipv6Addr::from(b);
                                ips.push(ip.to_string());
                            }
                            if !ips.is_empty() {
                                parts.push(format!("ipv6hint={}", ips.join(",")));
                            }
                        }
                        k => {
                            parts.push(format!("param{k}=..."));
                        }
                    }
                }
                write!(f, "{}", parts.join(" "))
            }
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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Display for DnsRecordEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<5} {:<20} -> {}", self.kind, self.name, self.data)
    }
}

use std::collections::HashMap;

/// Persistent lifetime DNS server statistics across daemon restarts (excludes transient cache metrics).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DnsLifetimeStats {
    pub total_requests: u64,
    pub blocked_queries: u64,
    pub resolved_total: u64,
    pub failed_total: u64,
    pub upstream_errors: u64,
    pub auth_queries: u64,
    pub recursions: u64,
    #[serde(default)]
    pub cache_hits: u64,
    #[serde(default)]
    pub cache_misses: u64,
    #[serde(default)]
    pub proto_udp: u64,
    #[serde(default)]
    pub proto_tcp: u64,
    #[serde(default)]
    pub proto_dot: u64,
    #[serde(default)]
    pub proto_doq: u64,
    #[serde(default)]
    pub proto_doh: u64,
}

/// A snapshot of DNS resolver statistics.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsStatsResponse {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub upstream_errors: u64,
    pub auth_queries: u64,
    pub recursions: u64,
    pub blocked_queries: u64,
    pub resolved_total: u64,
    pub failed_total: u64,
    pub cache_entries: u64,
    pub cache_capacity: u64,
}

/// DNS cache dump entry.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsCacheResponse {
    pub entries: Vec<DnsCacheEntry>,
    pub total: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsCacheEntry {
    pub name: String,
    pub kind: DnsRecordType,
    pub data: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsAdblockStatusResponse {
    pub enabled: bool,
    pub disabled_until: Option<u64>,
    pub remaining_secs: Option<u64>,
    pub blocklist_size: usize,
    pub allowlist_size: usize,
    pub blocking_mode: BlockingMode,
    pub blocking_ip_v4: Option<Ipv4Addr>,
    pub blocking_ip_v6: Option<Ipv6Addr>,
    #[serde(default)]
    pub exceptions_size: usize,
    #[serde(default)]
    pub last_update: Option<u64>,
    #[serde(default)]
    pub next_update: Option<u64>,
    #[serde(default)]
    pub sources_ok: usize,
    #[serde(default)]
    pub sources_failing: usize,
}

/// A single adblock source URL entry.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AdblockUrlEntry {
    pub id: Option<i64>,
    #[serde(default)]
    pub name: Option<String>,
    pub url: String,
    pub kind: AdblockUrlKind,
    #[serde(default)]
    pub format: AdblockSourceFormat,
}

impl AdblockUrlEntry {
    /// Returns the database ID or computes a deterministic positive 64-bit ID from the URL.
    ///
    /// When an entry lacks an explicit database ID (e.g. in test suites, transient configurations,
    /// or before database insertion), a deterministic positive `i64` is derived using 64-bit FNV-1a:
    /// - `0xcbf2_9ce4_8422_2325`: Standard 64-bit FNV offset basis seed.
    /// - `0x0100_0000_01b3`: Standard 64-bit FNV prime providing fast bit avalanche.
    /// - `& 0x7FFF_FFFF_FFFF_FFFF`: Masks the sign bit to guarantee a non-negative `i64`.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn source_id(&self) -> i64 {
        self.id.unwrap_or_else(|| {
            // 64-bit FNV-1a offset basis
            let mut h = 0xcbf2_9ce4_8422_2325_u64;
            for &b in self.url.as_bytes() {
                h ^= u64::from(b);
                // 64-bit FNV prime
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            // Clear sign bit to ensure a non-negative i64
            (h & 0x7FFF_FFFF_FFFF_FFFF) as i64
        })
    }
}

/// Status and metrics for an adblock filter list source.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdblockSourceStatus {
    pub id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub url: String,
    pub format: AdblockSourceFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_detected: Option<AdblockSourceFormat>,
    pub blocks: usize,
    pub exceptions: usize,
    pub unsupported: usize,
    pub last_attempt: u64,
    pub last_success: Option<u64>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    #[serde(default)]
    pub sample_unsupported: Vec<String>,
}

/// Response containing status of all compiled adblock filter sources.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsAdblockSourcesResponse {
    pub sources: Vec<AdblockSourceStatus>,
}

/// Attribution for a single source list matching a domain.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdblockSourceMatch {
    pub source_id: i64,
    pub url: String,
    pub action: FilterAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default)]
    pub important: bool,
}

/// Diagnostic check response for a domain against adblock rules and sources.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdblockCheckResponse {
    pub domain: String,
    pub matched: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterMatch>,
    #[serde(default)]
    pub source_matches: Vec<AdblockSourceMatch>,
}

/// In-depth DNS cache statistics.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsCacheStatsExtResponse {
    pub total_entries: u64,
    pub entries_by_type: HashMap<DnsRecordType, u64>,
    pub memory_usage_bytes: u64,
    pub average_ttl_secs: u64,
    pub evictions: u64,
    pub min_ttl: u32,
    pub capacity: u64,
}

/// Request sent over the core DNS handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRequest {
    Query {
        name: String,
        qtype: DnsRecordType,
    },
    CacheDump {
        limit: Option<usize>,
        offset: Option<usize>,
        #[serde(default)]
        q: Option<String>,
        #[serde(default)]
        kind: Option<DnsRecordType>,
    },
    CacheStatsExt,
    Upstreams,
    UpstreamAdd {
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    },
    UpstreamRemove {
        addr: SocketAddr,
        protocol: UpstreamProtocol,
    },
    AdblockStatus,
    AdblockSources,
    AdblockCheck {
        domain: String,
    },
    AdblockSet {
        enabled: bool,
        duration_secs: Option<u64>,
    },
    AdblockReload,
    AdblockUrlList,
    AdblockUrlAdd {
        url: String,
        kind: AdblockUrlKind,
        #[serde(default)]
        format: AdblockSourceFormat,
    },
    AdblockUrlRemove {
        url: String,
    },
    AdblockConfigSet {
        blocking_mode: Option<BlockingMode>,
        blocking_ip_v4: Option<Ipv4Addr>,
        blocking_ip_v6: Option<Ipv6Addr>,
    },
    Stats,
    LifetimeStats,
}

/// Response returned from the core DNS handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsResponse {
    Query(Result<(Vec<DnsRecordEntry>, bool, String), String>),
    CacheDump(DnsCacheResponse),
    CacheStatsExt(DnsCacheStatsExtResponse),
    Upstreams(Vec<UpstreamHealthSnapshot>),
    UpstreamAdd(Result<(), String>),
    UpstreamRemove(Result<(), String>),
    AdblockStatus(DnsAdblockStatusResponse),
    AdblockSources(DnsAdblockSourcesResponse),
    AdblockCheck(AdblockCheckResponse),
    AdblockSet(Result<(), String>),
    AdblockReload(Result<(), String>),
    AdblockUrlList(Vec<AdblockUrlEntry>),
    AdblockUrlAdd(Result<(), String>),
    AdblockUrlRemove(Result<(), String>),
    AdblockConfigSet(Result<(), String>),
    Stats(DnsStatsResponse),
    LifetimeStats(DnsLifetimeStats),
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

        assert_eq!(DnsRecordType::from(65534), DnsRecordType::Device);
        assert_eq!(u16::from(DnsRecordType::Device), 65534);
        assert_eq!(
            "DEVICE".parse::<DnsRecordType>().unwrap(),
            DnsRecordType::Device
        );
        assert_eq!(
            "dev".parse::<DnsRecordType>().unwrap(),
            DnsRecordType::Device
        );
        assert_eq!(
            "A/AAAA".parse::<DnsRecordType>().unwrap(),
            DnsRecordType::Device
        );
        assert_eq!(DnsRecordType::Device.to_string(), "DEVICE");

        let json = serde_json::to_string(&DnsRecordType::Device).unwrap();
        assert_eq!(json, "\"DEVICE\"");
        let deserialized: DnsRecordType = serde_json::from_str("\"DEVICE\"").unwrap();
        assert_eq!(deserialized, DnsRecordType::Device);
        let deserialized_alias: DnsRecordType = serde_json::from_str("\"A/AAAA\"").unwrap();
        assert_eq!(deserialized_alias, DnsRecordType::Device);
    }
}
