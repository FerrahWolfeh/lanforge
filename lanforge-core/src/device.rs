//! Network device data structures.
//!
//! This module defines the core types representing network devices and their state:
//!
//! - **[`Device`]**: The central data structure for a discovered/managed network device.
//! - **[`Origin`]**: Administrative source of a device's configuration.
//! - **[`Hostname`]** / **[`HostnameOrigin`]**: Hostname with discovery source tracking.
//! - **[`IPv4State`]** / **[`IPv6State`]**: IP connectivity state for a device.
//! - **[`V4Lease`]** / **[`V6Lease`]** / **[`V6PrefixLease`]**: DHCP lease representations.
//! - **[`Ipv6AddrOrSuffix`]**: Full IPv6 address or 64-bit Interface ID (for prefix-flexible addresses).
//! - **[`IpClassification`]** / **[`Ipv6Prefix`]**: IPv6 address categorization and prefix handling.
//! - **[`LearningMethod`]**: How a device was discovered or configured.
//!
//! # Device Lifecycle
//!
//! Devices start as [`Device::new`] with just a MAC address. As network events occur
//! (DHCP leases, NDP/ARP observations, mDNS hints), the device accumulates state
//! (IPs, hostnames, DUIDs) via [`DeviceUpdate`](crate::state::DeviceUpdate) applied
//! through [`LanforgeContext`](crate::context::LanforgeContext).
//!
//! A device becomes "worthy" of inclusion in the device table when it has meaningful
//! information (hostname, IP, or static config).

use lanforge_macros::EnumRepr;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bus::DeviceChange;
use crate::context::state::{FieldUpdate, LeaseTarget};
use crate::identifiers::{Duid, MacAddr};

// ---------------------------------------------------------------------------
// Helpers for Serde
// ---------------------------------------------------------------------------

/// Serializes an optional `SystemTime` as a Unix timestamp.
///
/// # Errors
///
/// Returns an error if the serializer fails to serialize the timestamp.
pub fn serialize_time_opt<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match time {
        Some(t) => {
            let elapsed = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
            serializer.serialize_u64(elapsed.as_secs())
        }
        None => serializer.serialize_none(),
    }
}

/// Serializes a `SystemTime` as a Unix timestamp.
///
/// # Errors
///
/// Returns an error if the serializer fails to serialize the timestamp.
pub fn serialize_time<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    serializer.serialize_u64(elapsed.as_secs())
}

/// Serializes a list of observed IPv4 addresses with their timestamps.
///
/// # Errors
///
/// Returns an error if the serializer fails to serialize the sequence or its elements.
pub fn serialize_seen_v4<S>(
    seen: &[(Ipv4Addr, SystemTime)],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(seen.len()))?;
    for (ip, time) in seen {
        let elapsed = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        seq.serialize_element(&(*ip, elapsed.as_secs()))?;
    }
    seq.end()
}

/// Deserializes a `SystemTime` from a Unix timestamp.
///
/// # Errors
///
/// Returns an error if the deserializer fails to parse the timestamp.
pub fn deserialize_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

/// Deserializes an optional `SystemTime` from a Unix timestamp.
///
/// # Errors
///
/// Returns an error if the deserializer fails to parse the timestamp.
pub fn deserialize_time_opt<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt_secs = Option::<u64>::deserialize(deserializer)?;
    Ok(opt_secs.map(|secs| UNIX_EPOCH + Duration::from_secs(secs)))
}

/// Deserializes a list of observed IPv4 addresses with their timestamps.
///
/// # Errors
///
/// Returns an error if the deserializer fails to parse the sequence or its elements.
pub fn deserialize_seen_v4<'de, D>(deserializer: D) -> Result<Vec<(Ipv4Addr, SystemTime)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Vec::<(Ipv4Addr, u64)>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(ip, secs)| (ip, UNIX_EPOCH + Duration::from_secs(secs)))
        .collect())
}

/// The administrative source of a device's configuration.
///
/// This determines the priority and persistence of the device's settings.
/// Higher-priority origins override lower-priority ones during state conflicts.
///
/// # Priority Order (lowest to highest)
///
/// 1. **Dynamic** — Auto-discovered (DHCP, ARP); lowest priority, may be pruned
/// 2. **External** — Configured via HTTP API (pre-registration)
/// 3. **Cli** — Configured or overridden via CLI control interface
/// 4. **Toml** — Manually configured in `lanforge.toml`; highest persistence
///
/// # Symbols
///
/// Each origin has a display symbol for CLI/UI rendering:
/// - `★` = Toml (static)
/// - `·` = Cli (managed)
/// - `ⓔ` = External (API)
/// - `–` = Dynamic (auto)
///
/// # Example
///
/// ```rust
/// use lanforge_core::device::Origin;
///
/// assert!(Origin::Toml.is_static());
/// assert!(!Origin::Dynamic.is_static());
/// assert_eq!(Origin::Cli.symbol(), "·");
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, EnumRepr,
)]
pub enum Origin {
    /// Configured manually via the `lanforge.toml` file.
    #[enum_repr(alias = "static")]
    Toml,
    /// Configured or overridden via the CLI control interface.
    #[enum_repr(alias = "managed_cli")]
    Cli,
    /// Configured via the HTTP API (pre-registration).
    #[enum_repr(alias = "api")]
    External,
    /// Discovered dynamically on the network (e.g., via DHCP or ARP).
    #[default]
    Dynamic,
}

impl Origin {
    #[must_use]
    pub const fn is_static(&self) -> bool {
        !matches!(self, Self::Dynamic)
    }

    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Toml => "★",
            Self::Cli => "·",
            Self::External => "ⓔ",
            Self::Dynamic => "–",
        }
    }
}
// as_str(), FromStr, and Display are now handled by EnumRepr.

// ---------------------------------------------------------------------------
// Device Classification
// ---------------------------------------------------------------------------

/// High-level categorization of a network device based on discovery hints.
///
/// Designed to be memory-efficient (1 byte) for storage in the core state.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
    Hash,
    EnumRepr,
)]
#[repr(u8)]
pub enum DeviceClass {
    /// No specific classification identified yet.
    #[default]
    None = 0,
    /// Desktop, Laptop, or general-purpose Server.
    #[enum_repr(alias = "pc")]
    #[enum_repr(alias = "server")]
    Computer = 1,
    /// Smartphone or Tablet.
    #[enum_repr(alias = "phone")]
    #[enum_repr(alias = "tablet")]
    Mobile = 2,
    /// Printer or Scanner.
    #[enum_repr(alias = "scanner")]
    Printer = 3,
    /// Smart TV, Streaming Stick, or Audio Speaker.
    #[enum_repr(alias = "tv")]
    #[enum_repr(alias = "audio")]
    #[enum_repr(alias = "speaker")]
    Media = 4,
    /// Smart Home device (`IoT`), Sensors, or Hubs.
    #[enum_repr(alias = "smarthome")]
    #[enum_repr(alias = "sensor")]
    IoT = 5,
    /// Network Infrastructure (Switch, Access Point, Router).
    #[enum_repr(alias = "switch")]
    #[enum_repr(alias = "router")]
    #[enum_repr(alias = "ap")]
    Network = 6,
}

// as_str(), FromStr, and Display are now handled by EnumRepr.

// ---------------------------------------------------------------------------
// Hostname Hierarchy
// ---------------------------------------------------------------------------

/// The discovery source of a hostname, defining its precedence.
///
/// Hostnames from higher-priority sources override lower-priority ones.
///
/// # Priority (lowest to highest)
///
/// | Origin    | Value | Source                           |
/// |-----------|-------|----------------------------------|
/// | None      | 0     | No hostname assigned             |
/// | Mdns      | 1     | Multicast DNS discovery          |
/// | Dhcp      | 2     | DHCP Option 12 (v4) or v6 hint   |
/// | Static    | 3     | Manual config (CLI/TOML/API)     |
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, EnumRepr,
)]
pub enum HostnameOrigin {
    /// No hostname discovered or assigned.
    #[default]
    None = 0,
    /// Discovered via mDNS (lowest discovery priority).
    Mdns = 1,
    /// Learned via DHCP (Option 12 for v4, or v6 client hint).
    Dhcp = 2,
    /// Manually configured via Static configuration or CLI.
    Static = 3,
}

/// Represents a device's hostname with its origin for priority resolution.
///
/// This type tracks not just the name itself, but where it came from,
/// allowing the system to prefer DHCP hostnames over mDNS, and static
/// overrides over both.
///
/// # Example
///
/// ```rust
/// use lanforge_core::device::{Hostname, HostnameOrigin};
///
/// let hostname = Hostname::from("my-laptop");
/// assert_eq!(hostname.origin, HostnameOrigin::Static);
/// assert_eq!(hostname.display(), "my-laptop");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Hostname {
    /// The actual name string.
    pub name: String,
    /// The source that provided this name.
    pub origin: HostnameOrigin,
}

impl Hostname {
    /// Returns the name as a string slice, or "?" if empty.
    #[must_use]
    pub fn display(&self) -> &str {
        if self.name.is_empty() {
            "?"
        } else {
            &self.name
        }
    }
}

impl From<String> for Hostname {
    fn from(name: String) -> Self {
        Self {
            name,
            origin: HostnameOrigin::Static, // Default to Static if coming from raw string (config/CLI)
        }
    }
}

impl From<&str> for Hostname {
    fn from(name: &str) -> Self {
        Self {
            name: name.to_string(),
            origin: HostnameOrigin::Static,
        }
    }
}

impl From<Hostname> for String {
    fn from(val: Hostname) -> Self {
        val.name
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Represents an active `DHCPv4` lease.
///
/// Contains the assigned IPv4 address and the precise expiration time.
/// When `expires` passes, the lease is considered invalid and will be
/// removed during the next [`expire_stale`](crate::context::state::State::expire_stale) run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V4Lease {
    /// The assigned IPv4 address.
    pub ip: Ipv4Addr,
    /// The precise moment when this lease will expire.
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub expires: SystemTime,
}

/// Represents an active `DHCPv6` `IA_NA` (Non-temporary Address) lease.
///
/// `IA_NA` leases are the standard IPv6 address assignments in `DHCPv6`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6Lease {
    /// The assigned IPv6 address.
    pub ip: Ipv6Addr,
    /// The Identity Association Identifier from the client.
    /// IAIDs allow a single client to have multiple address assignments.
    pub iaid: u32,
    /// The precise moment when this lease will expire.
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub expires: SystemTime,
}

/// Represents an active `DHCPv6` `IA_PD` (Prefix Delegation) lease.
///
/// `IA_PD` is used to delegate entire prefixes to downstream clients (e.g., routers).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6PrefixLease {
    /// The delegated IPv6 prefix.
    pub prefix: Ipv6Addr,
    /// The prefix length (e.g., 60, 64).
    pub len: u8,
    /// The Identity Association Identifier from the client.
    pub iaid: u32,
    /// The precise moment when this lease will expire.
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub expires: SystemTime,
}

/// Represents the current IPv4 configuration of a device.
///
/// A device can have either a static address, a dynamic DHCP lease, or no address at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IPv4State {
    /// A manually configured static IPv4 address.
    Static(Ipv4Addr),
    /// An address assigned via a dynamic `DHCPv4` lease.
    Dynamic(V4Lease),
    /// No IPv4 address currently assigned or configured.
    None,
}

impl IPv4State {
    #[must_use]
    pub const fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Static(ip) => Some(*ip),
            Self::Dynamic(lease) => Some(lease.ip),
            Self::None => None,
        }
    }

    /// Returns true if the address was assigned via a dynamic DHCP lease.
    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }
}

/// Represents a specific IPv6 address state for a device.
///
/// A single device may have multiple IPv6 states simultaneously:
/// - A SLAAC address (autoconfigured from router advertisements)
/// - A `DHCPv6` lease (explicitly assigned)
/// - A static address (manually configured)
///
/// # Example
///
/// A typical dual-stack device might have:
/// - `IPv6State::Slaac(fd00::aabb:ccff:fedd:eeff)` — ULA via SLAAC
/// - `IPv6State::Slaac(2001:db8::aabb:ccff:fedd:eeff)` — GUA via SLAAC
/// - `IPv6State::Dynamic(...)` — `DHCPv6` lease
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IPv6State {
    /// A manually configured static address or suffix.
    /// Suffixes are resolved against the current global prefix.
    Static(Ipv6AddrOrSuffix),
    /// An address assigned via a dynamic `DHCPv6` lease (`IA_NA`).
    Dynamic(V6Lease),
    /// An address observed being used via SLAAC (Stateless Address Autoconfiguration).
    /// These are learned from NDP/neighbor discovery events.
    Slaac {
        /// The observed IPv6 address.
        ip: Ipv6Addr,
        /// The last time this specific address was observed.
        #[serde(
            serialize_with = "serialize_time",
            deserialize_with = "deserialize_time"
        )]
        last_seen: SystemTime,
    },
}

impl IPv6State {
    /// Returns the IPv6 address for this state.
    ///
    /// If it is a `Suffix`, it is combined with the given `prefix` if provided.
    #[must_use]
    pub fn ip_with_prefix(&self, prefix: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        match self {
            Self::Dynamic(lease) => Some(lease.ip),
            Self::Slaac { ip, .. } | Self::Static(Ipv6AddrOrSuffix::Full(ip)) => Some(*ip),
            Self::Static(suf) => prefix.map(|p| Ipv6Addr::from(suf.as_u128(Some(p)))),
        }
    }

    #[must_use]
    pub fn ip(&self) -> Option<Ipv6Addr> {
        self.ip_with_prefix(None)
    }

    /// Returns true if the address was assigned via a dynamic `DHCPv6` lease.
    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }
}

/// Represents either a complete IPv6 address or a 64-bit Interface ID (suffix).
///
/// Suffixes are useful when the global prefix changes but the device's
/// identifier remains constant. This is common with ULA prefixes where
/// only the lower 64 bits (the Interface ID) are device-specific.
///
/// # Parsing Rules
///
/// - If the string is a valid `Ipv6Addr` and the first 64 bits are zero → `Suffix`
/// - If it's a valid `Ipv6Addr` with non-zero prefix bits → `Full`
/// - If it's a short string (e.g., "1", "beef") that parses as lower bits → `Suffix`
///
/// # Example
///
/// ```rust
/// use lanforge_core::device::Ipv6AddrOrSuffix;
///
/// // Full address
/// let full = Ipv6AddrOrSuffix::parse("fd00::1").unwrap();
/// assert!(matches!(full, Ipv6AddrOrSuffix::Full(_)));
///
/// // Suffix (only interface ID)
/// let suffix = Ipv6AddrOrSuffix::parse("aabb:ccff:fedd:eeff").unwrap();
/// assert!(matches!(suffix, Ipv6AddrOrSuffix::Suffix(_)));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ipv6AddrOrSuffix {
    /// A complete 128-bit IPv6 address.
    Full(Ipv6Addr),
    /// A 64-bit Interface ID (suffix), typically combined with a global prefix.
    Suffix([u8; 8]),
}

impl Ipv6AddrOrSuffix {
    /// Parses a string into either a Full IPv6 address or a Suffix.
    ///
    /// # Rules
    /// - If the string is a valid `Ipv6Addr` and the first 64 bits are zero, it is treated as a `Suffix`.
    /// - If it's a valid `Ipv6Addr` with non-zero prefix bits, it is a `Full` address.
    /// - If it's a short string (e.g., "1", "beef") that can be parsed as the lower bits of an IPv6 address, it's a `Suffix`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            // Se for um endereço completo mas que começa com ::, pode ser um sufixo mal formatado no TOML?
            // "::1" parses as Ipv6Addr. We should decide if it's Full or Suffix.
            // Regra: se tem mais que 4 grupos ou não começa com ::, é Full.
            // Mas Ipv6Addr::parse é guloso.
            // Vamos checar se o endereço tem zero nos primeiros 64 bits.
            let segs = ip.segments();
            if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
                let mut bytes = [0u8; 8];
                bytes[0..2].copy_from_slice(&segs[4].to_be_bytes());
                bytes[2..4].copy_from_slice(&segs[5].to_be_bytes());
                bytes[4..6].copy_from_slice(&segs[6].to_be_bytes());
                bytes[6..8].copy_from_slice(&segs[7].to_be_bytes());
                return Some(Self::Suffix(bytes));
            }
            return Some(Self::Full(ip));
        }

        // Caso "1", "beef", "dead:beef" (sem o ::)

        if s.split(':').count() > 4 {
            return None;
        }

        let full_s = format!("::{s}");
        full_s.parse::<Ipv6Addr>().map_or(None, |ip| {
            let segs = ip.segments();
            let mut bytes = [0u8; 8];
            bytes[0..2].copy_from_slice(&segs[4].to_be_bytes());
            bytes[2..4].copy_from_slice(&segs[5].to_be_bytes());
            bytes[4..6].copy_from_slice(&segs[6].to_be_bytes());
            bytes[6..8].copy_from_slice(&segs[7].to_be_bytes());
            Some(Self::Suffix(bytes))
        })
    }

    /// Returns the 128-bit integer representation of this address or suffix.
    ///
    /// If it is a `Suffix`, it is combined with the given `prefix` if provided.
    /// If no `prefix` is provided, the suffix is returned as the lower 64 bits with zeroes in the upper 64 bits.
    #[must_use]
    pub fn as_u128(&self, prefix: Option<Ipv6Addr>) -> u128 {
        match self {
            Self::Full(ip) => u128::from_be_bytes(ip.octets()),
            Self::Suffix(s) => {
                let mut bytes = [0u8; 16];
                if let Some(p) = prefix {
                    bytes.copy_from_slice(&p.octets());
                }
                bytes[8..16].copy_from_slice(s);
                u128::from_be_bytes(bytes)
            }
        }
    }
}

impl fmt::Display for Ipv6AddrOrSuffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(ip) => ip.fmt(f),
            Self::Suffix(s) => {
                let ip = Ipv6Addr::new(
                    0,
                    0,
                    0,
                    0,
                    u16::from_be_bytes([s[0], s[1]]),
                    u16::from_be_bytes([s[2], s[3]]),
                    u16::from_be_bytes([s[4], s[5]]),
                    u16::from_be_bytes([s[6], s[7]]),
                );
                ip.fmt(f)
            }
        }
    }
}

/// Priority classification for IP addresses and prefixes.
///
/// Lower values have higher priority in sorting and display.
/// ULA (Unique Local Address) has the highest priority for local consistency.
///
/// # Priority Table
///
/// | Classification | Score | Range           | Description                        |
/// |----------------|-------|-----------------|------------------------------------|
/// | `Ula`            | 0     | `fc00::/7`      | Unique Local Address (highest)     |
/// | `Ipv4`           | 1     | —               | Standard IPv4 address              |
/// | `Gua`            | 2     | `2000::/3`      | Global Unicast Address             |
/// | `LinkLocal`      | 3     | `fe80::/10`     | Link-local address                 |
/// | `Loopback`       | 4     | `127.0.0.1`/`::1` | Local loopback                   |
/// | `Other`          | 10    | —               | Unknown or non-categorized (lowest)|
///
/// # Example
///
/// ```rust
/// use std::net::IpAddr;
/// use lanforge_core::device::{classify_ip, IpClassification};
///
/// let ula = "fd00::1".parse::<IpAddr>().unwrap();
/// assert_eq!(classify_ip(&ula), IpClassification::Ula);
///
/// let ipv4 = "192.168.1.1".parse::<IpAddr>().unwrap();
/// assert_eq!(classify_ip(&ipv4), IpClassification::Ipv4);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IpClassification {
    /// IPv6 Unique Local Address (`fc00::/7`).
    Ula = 0,
    /// Standard IPv4 address.
    Ipv4 = 1,
    /// IPv6 Global Unicast Address (`2000::/3`).
    Gua = 2,
    /// IPv6 Link-Local address (`fe80::/10`).
    LinkLocal = 3,
    /// Local loopback (127.0.0.1 or `::1`).
    Loopback = 4,
    /// Unknown or non-categorized address type.
    Other = 10,
}

impl IpClassification {
    /// Returns the sorting score for this classification.
    #[must_use]
    pub const fn score(&self) -> u8 {
        *self as u8
    }
}

/// Classifies an IP address into its priority category.
///
/// # Example
///
/// ```rust
/// use std::net::IpAddr;
/// use lanforge_core::device::{classify_ip, IpClassification};
///
/// let ula = "fd00::1".parse::<IpAddr>().unwrap();
/// assert_eq!(classify_ip(&ula), IpClassification::Ula);
/// ```
#[must_use]
pub const fn classify_ip(addr: &IpAddr) -> IpClassification {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                IpClassification::Loopback
            } else {
                IpClassification::Ipv4
            }
        }
        IpAddr::V6(v6) => classify_ipv6(v6),
    }
}

/// Classifies an IPv6 address.
#[must_use]
pub const fn classify_ipv6(v6: &Ipv6Addr) -> IpClassification {
    if v6.is_loopback() {
        IpClassification::Loopback
    } else if is_ula(v6) {
        IpClassification::Ula
    } else if (v6.segments()[0] & 0xe000) == 0x2000 {
        // GUA: 2000::/3 (RFC 4291)
        IpClassification::Gua
    } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
        // Link-Local: fe80::/10
        IpClassification::LinkLocal
    } else {
        IpClassification::Other
    }
}

/// Represents a formal IPv6 prefix (/64) with its classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Prefix {
    pub segments: [u16; 4],
    pub group: IpClassification,
}

impl Ipv6Prefix {
    /// Creates a prefix from an IPv6 address, automatically classifying it.
    #[must_use]
    pub const fn from_addr(addr: Ipv6Addr) -> Self {
        let segs = addr.segments();
        Self {
            segments: [segs[0], segs[1], segs[2], segs[3]],
            group: classify_ipv6(&addr),
        }
    }

    /// Explicitly creates a prefix with a specific group.
    #[must_use]
    pub const fn new(addr: Ipv6Addr, group: IpClassification) -> Self {
        let segs = addr.segments();
        Self {
            segments: [segs[0], segs[1], segs[2], segs[3]],
            group,
        }
    }

    /// Returns the full `Ipv6Addr` representation of this prefix (with 0 suffix).
    #[must_use]
    pub const fn to_addr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            self.segments[0],
            self.segments[1],
            self.segments[2],
            self.segments[3],
            0,
            0,
            0,
            0,
        )
    }
}

/// Represents a network device discovered and managed by Lanforge.
///
/// This is the central data structure in the [`State`](crate::state::State), containing
/// identity, addressing, and persistence metadata for each network device.
///
/// # Fields
///
/// | Field           | Description                                     |
/// |-----------------|-------------------------------------------------|
/// | `mac`           | Primary identifier (MAC address)                |
/// | `hostname`      | Current hostname with origin tracking           |
/// | `origin`        | Configuration source (static/dynamic/CLI/API)   |
/// | `managed_at`    | When the device was first manually configured   |
/// | `v4`            | Current IPv4 state (static, DHCP, or none)      |
/// | `v6`            | List of IPv6 states (SLAAC, `DHCPv6`, static)     |
/// | `v6_prefixes`   | Delegated IPv6 prefixes (`DHCPv6-PD`)             |
/// | `seen_v4`       | IPv4 addresses observed via ARP/Netlink         |
/// | `last_seen`     | Last time the device was observed on the network|
/// | `duid`          | `DHCPv6` Unique Identifier (if known)             |
/// | `dns_fallback`  | Auto-generated DNS name (e.g., `host-aa11bb`)   |
///
/// # Lifecycle
///
/// 1. **Creation**: Device starts with only a MAC address via [`Device::new`]
/// 2. **Accumulation**: Gains state through network events (leases, NDP, mDNS)
/// 3. **Worthiness**: Becomes "worthy" when it has hostname, IP, or static config
/// 4. **Expiry**: Dynamic devices without activity for 7 days are pruned
///
/// # Example
///
/// ```rust
/// use lanforge_core::device::Device;
/// use lanforge_core::identifiers::MacAddr;
///
/// let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
/// let device = Device::new(mac);
/// assert_eq!(device.mac, mac);
/// assert!(!device.is_worthy()); // Not yet meaningful
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// The primary identifier: MAC address.
    pub mac: MacAddr,
    /// The device's hostname and its discovery origin.
    ///
    /// Defaults to empty string with [`HostnameOrigin::None`](HostnameOrigin::None).
    pub hostname: Hostname,
    /// Where this device's configuration originated.
    ///
    /// See [`Origin`] for priority order.
    pub origin: Origin,

    /// Precise moment when the device was first manually managed, if applicable.
    ///
    /// Only set for devices configured via CLI, TOML, or API.
    /// Dynamic devices have this as `None`.
    #[serde(
        serialize_with = "serialize_time_opt",
        deserialize_with = "deserialize_time_opt"
    )]
    pub managed_at: Option<SystemTime>,

    /// Current IPv4 connectivity state.
    ///
    /// See [`IPv4State`] for possible values.
    pub v4: IPv4State,
    /// List of IPv6 connectivity states (SLAAC, `DHCPv6`, etc.).
    ///
    /// A device may have multiple entries (e.g., SLAAC + `DHCPv6`).
    pub v6: Vec<IPv6State>,
    /// List of delegated IPv6 prefixes assigned to this device.
    ///
    /// These come from `DHCPv6` Prefix Delegation (`IA_PD`).
    pub v6_prefixes: Vec<V6PrefixLease>,

    /// IPv4 addresses observed via network traffic (`ARP`/`Netlink`).
    ///
    /// These are "seen" addresses — the device may not have an active lease
    /// but was observed communicating on the network.
    #[serde(
        serialize_with = "serialize_seen_v4",
        deserialize_with = "deserialize_seen_v4"
    )]
    pub seen_v4: Vec<(Ipv4Addr, SystemTime)>,

    /// Precise moment when the device was last seen on the network.
    ///
    /// Updated on every network event (DHCP, NDP, ARP). Used for expiry
    /// calculations during garbage collection.
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub last_seen: SystemTime,

    /// `DHCPv6` Unique Identifier (DUID), if tracked.
    ///
    /// The DUID is learned during `DHCPv6` interactions and can be used
    /// to correlate devices across different network interfaces.
    pub duid: Option<Duid>,
    /// Pre-calculated DNS fallback name (e.g., "host-abcdef123456").
    ///
    /// Generated from the MAC address to provide a consistent, if not
    /// user-friendly, DNS name for devices without a configured hostname.
    pub dns_fallback: String,
    /// Discovered classification of the device (e.g., Printer, Media).
    pub class: DeviceClass,
    /// Physical or logical network topology information.
    ///
    /// Tracks which infrastructure device or local interface this device
    /// is connected to, learned via LLDP or bridge observation.
    pub topology: Option<TopologyInfo>,
}

/// Represents a device's position in the network hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyInfo {
    /// The MAC address of the parent device (e.g., a switch or AP).
    /// If `None`, the device is directly connected to a local interface.
    pub parent_mac: Option<MacAddr>,
    /// The name or index of the port on the parent device.
    pub port: Option<String>,
    /// The local interface index where the device was observed.
    pub local_ifindex: u32,
    /// The last time this topology information was refreshed.
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub last_updated: SystemTime,
}

impl Device {
    #[must_use]
    pub fn new(mac: MacAddr) -> Self {
        Self {
            mac,
            hostname: Hostname::default(),
            origin: Origin::Dynamic,
            managed_at: None,
            v4: IPv4State::None,
            v6: Vec::new(),
            v6_prefixes: Vec::new(),
            seen_v4: Vec::new(),
            last_seen: SystemTime::now(),
            duid: None,
            dns_fallback: format!("host-{}", mac.to_string().replace(':', "")).to_ascii_lowercase(),
            class: DeviceClass::None,
            topology: None,
        }
    }

    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.origin.is_static()
    }

    /// Returns true if the device has enough "meaningful" information to be officially
    /// registered in the table.
    ///
    /// # Worthiness Criteria
    ///
    /// A device is considered "worthy" if ANY of the following is true:
    /// - Has a non-empty hostname (even if dynamic)
    /// - Has an IPv4 address (Static or DHCP)
    /// - Has a routable IPv6 address (Dynamic lease, or SLAAC/Static that is GUA/ULA)
    /// - Has a static configuration origin (TOML, CLI, API)
    ///
    /// # Purpose
    ///
    /// This prevents the table from filling with "ghost" devices that have only
    /// been briefly observed (e.g., a single NDP probe) but have no real
    /// network presence.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_core::device::Device;
    /// use lanforge_core::identifiers::MacAddr;
    ///
    /// let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    /// let device = Device::new(mac);
    /// assert!(!device.is_worthy()); // Just MAC, nothing else
    /// ```
    #[must_use]
    pub fn is_worthy(&self) -> bool {
        if self.is_static() || !self.hostname.name.is_empty() {
            return true;
        }

        if !matches!(self.v4, IPv4State::None) || !self.seen_v4.is_empty() {
            return true;
        }

        self.v6.iter().any(|s| {
            s.ip_with_prefix(None).map_or(
                matches!(s, IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_))),
                |ip| {
                    let class = classify_ipv6(&ip);
                    matches!(class, IpClassification::Gua | IpClassification::Ula)
                },
            )
        })
    }

    /// Removes a specific IP from the device record.
    /// Returns true if something was actually removed.
    pub fn remove_ip(&mut self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip4) => {
                let initial_seen = self.seen_v4.len();
                self.seen_v4.retain(|(i, _)| i != ip4);
                let changed = self.seen_v4.len() != initial_seen;

                if matches!(&self.v4, IPv4State::Dynamic(lease) if lease.ip == *ip4) {
                    self.v4 = IPv4State::None;
                    return true;
                }
                changed
            }
            IpAddr::V6(ip6) => {
                let initial_v6 = self.v6.len();
                self.v6
                    .retain(|s| !matches!(s, IPv6State::Slaac { ip: a, .. } if a == ip6));
                self.v6.len() != initial_v6
            }
        }
    }

    /// Returns true if the device has any active IP addresses (v4 or v6).
    #[must_use]
    pub const fn has_any_ip(&self) -> bool {
        self.v4.ip().is_some() || !self.seen_v4.is_empty() || !self.v6.is_empty()
    }

    pub fn update_from_fields(
        &mut self,
        hostname: FieldUpdate<String>,
        duid: FieldUpdate<Duid>,
        v4_static: FieldUpdate<Ipv4Addr>,
        v6_suffix: FieldUpdate<Ipv6AddrOrSuffix>,
        origin: Origin,
    ) -> bool {
        let mut changed = false;

        match hostname {
            FieldUpdate::Set(hn) => {
                if self.hostname.name != hn || self.hostname.origin != HostnameOrigin::Static {
                    self.hostname = Hostname {
                        name: hn,
                        origin: HostnameOrigin::Static,
                    };
                    changed = true;
                }
            }
            FieldUpdate::Clear => {
                if !self.hostname.name.is_empty() {
                    self.hostname = Hostname::default();
                    changed = true;
                }
            }
            FieldUpdate::NoChange => {}
        }

        match duid {
            FieldUpdate::Set(d) => {
                if self.duid.as_ref() != Some(&d) {
                    self.duid = Some(d);
                    changed = true;
                }
            }
            FieldUpdate::Clear => {
                if self.duid.is_some() {
                    self.duid = None;
                    changed = true;
                }
            }
            FieldUpdate::NoChange => {}
        }

        match v4_static {
            FieldUpdate::Set(ip) => {
                if self.v4 != IPv4State::Static(ip) {
                    self.v4 = IPv4State::Static(ip);
                    changed = true;
                }
            }
            FieldUpdate::Clear => {
                if self.v4 != IPv4State::None {
                    self.v4 = IPv4State::None;
                    changed = true;
                }
            }
            FieldUpdate::NoChange => {}
        }

        match v6_suffix {
            FieldUpdate::Set(suf) => {
                let new_state = IPv6State::Static(suf);
                let mut found = false;
                for state in &mut self.v6 {
                    if matches!(state, IPv6State::Static(_)) {
                        if *state != new_state {
                            *state = new_state.clone();
                            changed = true;
                        }
                        found = true;
                        break;
                    }
                }
                if !found {
                    self.v6.push(new_state);
                    changed = true;
                }
            }
            FieldUpdate::Clear => {
                let initial_len = self.v6.len();
                self.v6.retain(|s| !matches!(s, IPv6State::Static(_)));
                if self.v6.len() != initial_len {
                    changed = true;
                }
            }
            FieldUpdate::NoChange => {}
        }

        if changed {
            self.origin = origin;
            let now = SystemTime::now();
            self.managed_at = Some(now);
            self.last_seen = now;
        }

        changed
    }

    pub fn expire_stale_inner(
        &mut self,
        now: SystemTime,
        ip_expiry_threshold: std::time::Duration,
    ) -> Vec<DeviceChange> {
        let mut events = Vec::new();

        // V4
        if let IPv4State::Dynamic(lease) = &self.v4
            && lease.expires < now
        {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V4,
            });
            self.v4 = IPv4State::None;
        }

        // V6
        let mut v6_expired_iaids = Vec::new();
        self.v6.retain(|state| match state {
            IPv6State::Dynamic(lease) if lease.expires < now => {
                v6_expired_iaids.push(lease.iaid);
                false
            }
            IPv6State::Slaac { last_seen, .. } => {
                last_seen.elapsed().unwrap_or(std::time::Duration::ZERO) <= ip_expiry_threshold
            }
            _ => true,
        });
        for iaid in v6_expired_iaids {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V6 { iaid },
            });
        }

        // Prefixes
        let mut prefix_expired_iaids = Vec::new();
        self.v6_prefixes.retain(|p| {
            if p.expires < now {
                prefix_expired_iaids.push(p.iaid);
                false
            } else {
                true
            }
        });
        for iaid in prefix_expired_iaids {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V6Prefix { iaid },
            });
        }

        // ARP
        self.seen_v4.retain(|(_, ts)| {
            ts.elapsed().unwrap_or(std::time::Duration::ZERO) <= ip_expiry_threshold
        });

        events
    }

    #[must_use]
    pub fn is_zombie(&self, max_age: std::time::Duration) -> bool {
        if self.is_static() {
            return false;
        }

        if !matches!(self.v4, IPv4State::None)
            || !self.v6.is_empty()
            || !self.v6_prefixes.is_empty()
        {
            return false;
        }

        self.last_seen
            .elapsed()
            .unwrap_or(std::time::Duration::ZERO)
            > max_age
    }
}

// ---------------------------------------------------------------------------
// Formatting and Selection Helpers
// ---------------------------------------------------------------------------

impl Device {
    /// Defines the threshold for a device to be considered "definitely online".
    /// Returns true if the device was seen within the last 5 minutes.
    /// Defines the threshold for a device to be considered "definitely online".
    pub const ONLINE_THRESHOLD_SECS: u64 = 300; // 5 minutes

    /// Returns the device's hostname, or "?" if not available.
    #[must_use]
    pub fn display_hostname(&self) -> &str {
        self.hostname.display()
    }

    /// Returns true if the device was seen within the last 5 minutes.
    #[must_use]
    pub fn is_online(&self) -> bool {
        self.is_online_at(SystemTime::now())
    }

    /// Returns true if the device was seen within the threshold relative to the given time.
    #[must_use]
    pub fn is_online_at(&self, now: SystemTime) -> bool {
        now.duration_since(self.last_seen)
            .is_ok_and(|d| d.as_secs() < Self::ONLINE_THRESHOLD_SECS)
    }

    /// Returns a human-readable primary IPv4 address or "—".
    #[must_use]
    pub fn display_v4(&self) -> String {
        match &self.v4 {
            IPv4State::Static(ip) => ip.to_string(),
            IPv4State::Dynamic(lease) => lease.ip.to_string(),
            IPv4State::None => self
                .seen_v4
                .first()
                .map_or_else(|| "—".to_string(), |(seen, _)| format!("{seen} ?")),
        }
    }

    /// Returns the primary IPv6 address based on the following priority:
    ///
    /// # Priority Order (highest to lowest)
    ///
    /// 1. **ULA (Unique Local Address)**: Static or Dynamic Lease — most stable for local networking
    /// 2. **Custom GUA**: Static or Dynamic Lease — globally routable, but less stable than ULA
    /// 3. **SLAAC ULA**: Observed SLAAC address in ULA range
    /// 4. **SLAAC GUA**: Observed SLAAC address in GUA range
    ///
    /// # Parameters
    ///
    /// - `gua_prefix`: The current Global Unicast prefix (e.g., `2001:db8:1234::/64`)
    ///   used to resolve static suffixes.
    /// - `ula_prefix`: The current Unique Local prefix (e.g., `fd00:dead:beef::/64`)
    ///   used to resolve static suffixes.
    ///
    /// # Returns
    ///
    /// `Some(Ipv6Addr)` if the device has any IPv6 state, `None` otherwise.
    ///
    /// # Example
    ///
    #[must_use]
    pub fn primary_v6(
        &self,
        gua_prefix: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> Option<Ipv6Addr> {
        let mut best: Option<(u8, Ipv6Addr)> = None;

        let mut update_best = |prio: u8, addr: Ipv6Addr| {
            if best.as_ref().is_none_or(|(b_prio, _)| prio < *b_prio) {
                best = Some((prio, addr));
            }
        };

        for state in &self.v6 {
            if let IPv6State::Slaac { ip, .. } = state {
                if is_ula(ip) {
                    update_best(3, *ip);
                } else if matches!(classify_ipv6(ip), IpClassification::Gua) {
                    update_best(4, *ip);
                }
            } else {
                // 1. Check for ULA
                if let Some(ip) = state.ip_with_prefix(ula_prefix)
                    && is_ula(&ip)
                {
                    update_best(1, ip);
                }
                // 2. Check for GUA
                if let Some(ip) = state.ip_with_prefix(gua_prefix)
                    && matches!(classify_ipv6(&ip), IpClassification::Gua)
                {
                    update_best(2, ip);
                }
            }
        }

        best.map(|(_, addr)| addr)
    }

    /// Returns a human-readable primary IPv6 address or "—".
    #[must_use]
    pub fn display_v6(&self, gua_prefix: Option<Ipv6Addr>, ula_prefix: Option<Ipv6Addr>) -> String {
        self.primary_v6(gua_prefix, ula_prefix)
            .map_or_else(|| "—".to_string(), |ip| ip.to_string())
    }

    /// Returns all available IP addresses (v4 and v6) sorted by priority:
    /// ULA (0) > IPv4 (1) > GUA (2) > others.
    ///
    /// Suffixes are resolved using the provided `gua_prefix` and `ula_prefix`.
    #[must_use]
    pub fn all_addresses_sorted(
        &self,
        gua_prefix: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> Vec<IpAddr> {
        let mut addrs = Vec::new();

        // IPv4
        if let Some(ip) = self.v4.ip() {
            addrs.push(IpAddr::V4(ip));
        }
        for (ip, _) in &self.seen_v4 {
            addrs.push(IpAddr::V4(*ip));
        }

        // IPv6
        for state in &self.v6 {
            if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_)) = state {
                // DNS Contract: Static suffixes produce addresses on ALL active prefixes.
                for prefix in [ula_prefix, gua_prefix].into_iter().flatten() {
                    if let Some(ip) = state.ip_with_prefix(Some(prefix)) {
                        addrs.push(IpAddr::V6(ip));
                    }
                }
            } else if let Some(ip) = state.ip() {
                // DNS Contract: Dynamic leases (DHCPv6) and SLAAC addresses are always included.
                addrs.push(IpAddr::V6(ip));
            }
        }

        // De-duplicate while preserving prioritization order
        let mut unique = HashSet::new();
        addrs.retain(|ip| unique.insert(*ip));

        // Sort by classification score
        addrs.sort_by_key(|ip| classify_ip(ip).score());

        addrs
    }

    /// Categorizes how this device was primarily discovered or configured.
    ///
    /// This method inspects the device's state to determine the most likely
    /// discovery method, which is useful for UI display and analytics.
    ///
    /// # Detection Logic
    ///
    /// | Condition                                | Returns          |
    /// |------------------------------------------|------------------|
    /// | `origin == Toml`                         | `Static`         |
    /// | `origin == Cli`                          | `Managed`        |
    /// | Has active DHCPv4 lease                  | `DhcpV4`         |
    /// | Has active DHCPv6 lease                  | `DhcpV6`         |
    /// | Has SLAAC addresses                      | `Slaac`          |
    /// | Has observed IPv4 via ARP/Netlink        | `NdpArp`         |
    /// | None of the above                        | `Unknown`        |
    #[must_use]
    pub fn learning_method(&self) -> LearningMethod {
        if self.origin == Origin::Toml {
            return LearningMethod::Static;
        }
        if self.origin == Origin::Cli {
            return LearningMethod::Managed;
        }

        // Check DHCPv4
        if matches!(self.v4, IPv4State::Dynamic(_)) {
            return LearningMethod::DhcpV4;
        }

        // Check DHCPv6
        if self.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_))) {
            return LearningMethod::DhcpV6;
        }

        // Check SLAAC
        if self.v6.iter().any(|s| matches!(s, IPv6State::Slaac { .. })) {
            return LearningMethod::Slaac;
        }

        // Check ARP/Netlink
        if !self.seen_v4.is_empty() {
            return LearningMethod::NdpArp;
        }

        LearningMethod::Unknown
    }
}

/// The protocol or method by which a device was discovered.
///
/// This enum is used for analytics, UI display, and understanding the
/// network topology.
///
/// # Variants
///
/// | Variant    | Description                                |
/// |------------|--------------------------------------------|
/// | Static     | Manually configured in `lanforge.toml`     |
/// | Managed    | Manually configured or overridden via CLI  |
/// | DhcpV4     | Discovered via DHCPv4 lease                |
/// | DhcpV6     | Discovered via DHCPv6 lease (IA_NA)        |
/// | Slaac      | Observed via SLAAC (Neighbor Discovery)    |
/// | NdpArp     | Observed via ARP/Netlink (no DHCP/SLAAC)   |
/// | Unknown    | Minimal presence, no clear discovery method|
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LearningMethod {
    /// Manually configured in `lanforge.toml`.
    Static,
    /// Manually configured or overridden via CLI.
    Managed,
    /// Discovered via `DHCPv4` lease.
    DhcpV4,
    /// Discovered via `DHCPv6` lease (`IA_NA`).
    DhcpV6,
    /// Discovered via Router Advertisement / SLAAC.
    Slaac,
    /// Discovered via ARP or Neighbor Discovery traffic.
    NdpArp,
    /// Discovery method could not be determined.
    Unknown,
}

impl fmt::Display for LearningMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static => write!(f, "Static"),
            Self::Managed => write!(f, "Managed"),
            Self::DhcpV4 => write!(f, "DHCPv4"),
            Self::DhcpV6 => write!(f, "DHCPv6"),
            Self::Slaac => write!(f, "SLAAC"),
            Self::NdpArp => write!(f, "NDP/ARP"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Checks if an IPv6 address is a Unique Local Address (ULA).
const fn is_ula(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_ip() {
        assert_eq!(
            classify_ip(&"127.0.0.1".parse().unwrap()),
            IpClassification::Loopback
        );
        assert_eq!(
            classify_ip(&"1.1.1.1".parse().unwrap()),
            IpClassification::Ipv4
        );
        assert_eq!(
            classify_ip(&"fd00::1".parse().unwrap()),
            IpClassification::Ula
        );
        assert_eq!(
            classify_ip(&"2001:db8::1".parse().unwrap()),
            IpClassification::Gua
        );
        assert_eq!(
            classify_ip(&"fe80::1".parse().unwrap()),
            IpClassification::LinkLocal
        );
        assert_eq!(
            classify_ip(&"::1".parse().unwrap()),
            IpClassification::Loopback
        );
    }

    #[test]
    fn test_all_addresses_sorted() {
        let dev = Device {
            hostname: Hostname {
                name: "test".to_string(),
                origin: HostnameOrigin::Static,
            },
            mac: MacAddr([1, 2, 3, 4, 5, 6]),
            origin: Origin::Dynamic,
            managed_at: None,
            class: DeviceClass::None,
            duid: None,
            v4: IPv4State::Static("192.168.1.1".parse().unwrap()),
            v6: vec![
                IPv6State::Slaac {
                    ip: "2001:db8::1".parse().unwrap(),
                    last_seen: SystemTime::now(),
                },
                IPv6State::Slaac {
                    ip: "fd00::1".parse().unwrap(),
                    last_seen: SystemTime::now(),
                },
            ],
            v6_prefixes: Vec::new(),
            seen_v4: Vec::new(),
            last_seen: SystemTime::now(),
            dns_fallback: "host-010203040506".to_string(),
            topology: None,
        };

        let sorted = dev.all_addresses_sorted(None, None);
        // Priority: ULA (fd00::1) > IPv4 (192.168.1.1) > GUA (2001:db8::1)
        assert_eq!(sorted[0], "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(sorted[1], "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(sorted[2], "2001:db8::1".parse::<IpAddr>().unwrap());
    }
}
