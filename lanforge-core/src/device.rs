use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::SystemTime;

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

/// The administrative source of a device's configuration.
///
/// This determines the priority and persistence of the device's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Origin {
    /// Configured manually via the `lanforge.toml` file.
    Toml,
    /// Configured or overridden via the CLI control interface.
    Cli,
    /// Configured via the HTTP API (pre-registration).
    External,
    /// Discovered dynamically on the network (e.g., via DHCP or ARP).
    #[default]
    Dynamic,
}

impl Origin {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Cli => "cli",
            Self::External => "external",
            Self::Dynamic => "dynamic",
        }
    }

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

impl FromStr for Origin {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "toml" | "static" => Ok(Self::Toml),
            "cli" | "managed_cli" => Ok(Self::Cli),
            "external" | "api" => Ok(Self::External),
            "dynamic" => Ok(Self::Dynamic),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Hostname Hierarchy
// ---------------------------------------------------------------------------

/// The discovery source of a hostname, defining its precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V4Lease {
    /// The assigned IPv4 address.
    pub ip: Ipv4Addr,
    /// The precise moment when this lease will expire.
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

/// Represents an active `DHCPv6` `IA_NA` (Address) lease.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6Lease {
    /// The assigned IPv6 address.
    pub ip: Ipv6Addr,
    /// The Identity Association Identifier from the client.
    pub iaid: u32,
    /// The precise moment when this lease will expire.
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

/// Represents an active `DHCPv6` `IA_PD` (Prefix Delegation) lease.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6PrefixLease {
    /// The delegated IPv6 prefix.
    pub prefix: Ipv6Addr,
    /// The prefix length (e.g., 60).
    pub len: u8,
    /// The Identity Association Identifier from the client.
    pub iaid: u32,
    /// The precise moment when this lease will expire.
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

/// Represents the current IPv4 configuration of a device.
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
}

/// Represents a specific IPv6 address state for a device.
///
/// A single device may have multiple IPv6 states (e.g., a SLAAC address and a `DHCPv6` lease).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IPv6State {
    /// A manually configured static address or suffix.
    Static(Ipv6AddrOrSuffix),
    /// An address assigned via a dynamic `DHCPv6` lease (`IA_NA`).
    Dynamic(V6Lease),
    /// An address observed being used via SLAAC (Stateless Address Autoconfiguration).
    Slaac(Ipv6Addr),
}

impl IPv6State {
    /// Returns the IPv6 address for this state.
    ///
    /// If it is a `Suffix`, it is combined with the given `prefix` if provided.
    #[must_use]
    pub fn ip_with_prefix(&self, prefix: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        match self {
            Self::Dynamic(lease) => Some(lease.ip),
            Self::Slaac(ip) | Self::Static(Ipv6AddrOrSuffix::Full(ip)) => Some(*ip),
            Self::Static(suf) => prefix.map(|p| Ipv6Addr::from(suf.as_u128(Some(p)))),
        }
    }

    #[must_use]
    pub fn ip(&self) -> Option<Ipv6Addr> {
        self.ip_with_prefix(None)
    }
}

/// Represents either a complete IPv6 address or a 64-bit Interface ID (suffix).
///
/// Suffixes are useful when the global prefix changes but the device's
/// identifier remains constant.
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
/// This is the central data structure in the `DeviceTable`, containing identity,
/// addressing, and persistence metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// The primary identifier: MAC address.
    pub mac: MacAddr,
    /// The device's hostname and its discovery origin.
    pub hostname: Hostname,
    /// Where this device's configuration originated.
    pub origin: Origin,

    /// Precise moment when the device was first manually managed, if applicable.
    #[serde(serialize_with = "serialize_time_opt")]
    pub managed_at: Option<SystemTime>,

    /// Current IPv4 connectivity state.
    pub v4: IPv4State,
    /// List of IPv6 connectivity states (SLAAC, `DHCPv6`, etc.).
    pub v6: Vec<IPv6State>,
    /// List of delegated IPv6 prefixes assigned to this device.
    pub v6_prefixes: Vec<V6PrefixLease>,

    /// IPv4 addresses observed via network traffic (ARP/Netlink).
    pub seen_v4: Vec<Ipv4Addr>,

    /// Precise moment when the device was last seen on the network.
    #[serde(serialize_with = "serialize_time")]
    pub last_seen: SystemTime,

    /// `DHCPv6` Unique Identifier (DUID), if tracked.
    pub duid: Option<Duid>,
    /// IPs that have failed connectivity probes since the last successful activity.
    #[serde(skip)]
    pub failed_ips: HashSet<IpAddr>,
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
            failed_ips: HashSet::new(),
        }
    }

    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.origin.is_static()
    }

    /// Returns true if the device has enough "meaningful" information to be officially
    /// registered in the table.
    ///
    /// Criteria:
    /// - Has a non-empty hostname.
    /// - Has an IPv4 address (Static or DHCP).
    /// - Has a routable IPv6 address (Dynamic lease, or SLAAC/Static that is GUA/ULA).
    /// - Has a static configuration origin.
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
                self.seen_v4.retain(|i| i != ip4);
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
                    .retain(|s| !matches!(s, IPv6State::Slaac(a) if a == ip6));
                self.v6.len() != initial_v6
            }
        }
    }

    /// Marks an IP as failed. This is transient and cleared on the next seen event.
    /// Returns true if it was not already marked.
    pub fn mark_ip_failed(&mut self, ip: IpAddr) -> bool {
        self.failed_ips.insert(ip)
    }

    /// Clears all transient failure tracking. Called when a device is seen active.
    /// Returns true if something was actually cleared.
    pub fn reset_failures(&mut self) -> bool {
        if self.failed_ips.is_empty() {
            return false;
        }
        self.failed_ips.clear();
        true
    }
}

// ---------------------------------------------------------------------------
// Formatting and Selection Helpers
// ---------------------------------------------------------------------------

impl Device {
    /// Returns the device's hostname, or "?" if not available.
    #[must_use]
    pub fn display_hostname(&self) -> &str {
        self.hostname.display()
    }

    /// Returns true if the device was seen within the last 5 minutes.
    #[must_use]
    pub fn is_online(&self) -> bool {
        self.last_seen
            .elapsed()
            .map(|d| d.as_secs() < 300)
            .unwrap_or(false)
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
                .map_or_else(|| "—".to_string(), |seen| format!("{seen} ?")),
        }
    }

    /// Returns the primary IPv6 address based on following priority:
    ///
    /// 1. **ULA** (Unique Local Address): Static or Dynamic Lease.
    /// 2. **Custom GUA**: Static or Dynamic Lease.
    /// 3. **SLAAC ULA**: Observed SLAAC address in ULA range.
    /// 4. **SLAAC GUA**: Observed SLAAC address in GUA range.
    ///
    /// Suffixes are resolved using the provided `gua_prefix` or `ula_prefix`.
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
            if let IPv6State::Slaac(ip) = state {
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
        for ip in &self.seen_v4 {
            addrs.push(IpAddr::V4(*ip));
        }

        // IPv6
        for state in &self.v6 {
            if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_)) = state {
                if let Some(gua) = gua_prefix
                    && let Some(ip) = state.ip_with_prefix(Some(gua))
                {
                    addrs.push(IpAddr::V6(ip));
                }
                if let Some(ula) = ula_prefix
                    && let Some(ip) = state.ip_with_prefix(Some(ula))
                {
                    addrs.push(IpAddr::V6(ip));
                }
            } else if let Some(ip) = state.ip() {
                addrs.push(IpAddr::V6(ip));
            }
        }

        // De-duplicate while preserving prioritization order
        let mut unique = std::collections::HashSet::new();
        addrs.retain(|ip| unique.insert(*ip));

        // Sort by classification score
        addrs.sort_by_key(|ip| classify_ip(ip).score());

        addrs
    }

    /// Categorizes how this device was primarily learned or configured.
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
        if self.v6.iter().any(|s| matches!(s, IPv6State::Slaac(_))) {
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
            duid: None,
            v4: IPv4State::Static("192.168.1.1".parse().unwrap()),
            v6: vec![
                IPv6State::Slaac("2001:db8::1".parse().unwrap()),
                IPv6State::Slaac("fd00::1".parse().unwrap()),
            ],
            v6_prefixes: Vec::new(),
            seen_v4: Vec::new(),
            last_seen: SystemTime::now(),
            failed_ips: HashSet::new(),
        };

        let sorted = dev.all_addresses_sorted(None, None);
        // Priority: ULA (fd00::1) > IPv4 (192.168.1.1) > GUA (2001:db8::1)
        assert_eq!(sorted[0], "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(sorted[1], "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(sorted[2], "2001:db8::1".parse::<IpAddr>().unwrap());
    }
}
