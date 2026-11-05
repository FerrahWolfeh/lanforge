use crate::network::Ipv6Prefix;
use crate::network::subnet::IpSubnet;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::fmt::{self, Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// L3 WAN operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WanState {
    #[default]
    Down,
    Up,
}

/// Zeros out the host bits of an IPv6 address based on the prefix length using a bitwise mask.
#[must_use]
pub const fn mask_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if prefix_len >= 128 {
        return addr;
    }
    if prefix_len == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mask = !0u128 << (128 - prefix_len);
    let ip_u128 = u128::from_be_bytes(addr.octets());
    Ipv6Addr::from_bits(ip_u128 & mask)
}

/// IPv6 network prefix with prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Net {
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
}

impl Ipv6Net {
    #[must_use]
    pub const fn new(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            addr: mask_ipv6(addr, prefix_len),
            prefix_len,
        }
    }
}

impl Display for Ipv6Net {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl From<Ipv6Prefix> for Ipv6Net {
    fn from(prefix: Ipv6Prefix) -> Self {
        Self {
            addr: prefix.to_addr(),
            prefix_len: 64,
        }
    }
}

/// Point-in-time snapshot of the effective WAN L3 connectivity.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WanSnapshot {
    pub state: WanState,
    pub ifindex: Option<u32>,
    pub ifname: Option<String>,
    pub v4: Option<(Ipv4Addr, u8)>,
    pub v6_prefixes: SmallVec<[Ipv6Net; 2]>,
    pub generation: u64,
}

impl WanSnapshot {
    #[must_use]
    pub const fn is_up(&self) -> bool {
        matches!(self.state, WanState::Up)
    }
}

/// Network link physical and address state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkInfo {
    pub ifindex: u32,
    pub name: String,
    pub carrier: bool,
    pub addrs: SmallVec<[IpSubnet; 4]>,
}

/// Point-in-time snapshot of all discovered network interfaces.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InterfaceSnapshot {
    pub links: SmallVec<[LinkInfo; 8]>,
    pub generation: u64,
}

impl InterfaceSnapshot {
    /// Returns `true` if a link with the given interface name exists.
    #[must_use]
    pub fn has_link(&self, name: &str) -> bool {
        self.links.iter().any(|l| l.name == name)
    }

    /// Whether `name` is known to be absent: the links were scanned (generation > 0) and it is
    /// not among them. An unscanned snapshot blocks nothing.
    #[must_use]
    pub fn lacks_link(&self, name: &str) -> bool {
        self.generation > 0 && !name.is_empty() && !self.has_link(name)
    }

    /// Finds link details by interface name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&LinkInfo> {
        self.links.iter().find(|l| l.name == name)
    }

    /// Finds link details by OS ifindex.
    #[must_use]
    pub fn find_by_index(&self, ifindex: u32) -> Option<&LinkInfo> {
        self.links.iter().find(|l| l.ifindex == ifindex)
    }
}

/// Point-in-time snapshot of low-level network transport metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TransportSnapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub dropped: u64,
    pub rate_limited: u64,
    pub errors: u64,
    pub last_error_age_secs: Option<u64>,
}

impl TransportSnapshot {
    /// Adds `other`'s counters (a service with several sockets shows their sum); the most
    /// recent error wins.
    pub fn absorb(&mut self, other: &Self) {
        self.rx_packets += other.rx_packets;
        self.rx_bytes += other.rx_bytes;
        self.tx_packets += other.tx_packets;
        self.tx_bytes += other.tx_bytes;
        self.dropped += other.dropped;
        self.rate_limited += other.rate_limited;
        self.errors += other.errors;
        self.last_error_age_secs = match (self.last_error_age_secs, other.last_error_age_secs) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
}

/// Transparent, lock-free traffic counters for network transports.
#[derive(Debug, Default)]
pub struct TransportMetrics {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    dropped_packets: AtomicU64,
    rate_limited_packets: AtomicU64,
    errors: AtomicU64,
    last_error_timestamp: AtomicU64,
}

impl TransportMetrics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            rate_limited_packets: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_error_timestamp: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_rx(&self, bytes: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_tx(&self, bytes: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_drop(&self) {
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_rate_limited(&self) {
        self.rate_limited_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_error_timestamp.store(now, Ordering::Relaxed);
    }

    #[must_use]
    pub fn rx_packets(&self) -> u64 {
        self.rx_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tx_packets(&self) -> u64 {
        self.tx_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn rate_limited_packets(&self) -> u64 {
        self.rate_limited_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn last_error_age_secs(&self) -> Option<u64> {
        let ts = self.last_error_timestamp.load(Ordering::Relaxed);
        if ts == 0 {
            None
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Some(now.saturating_sub(ts))
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> TransportSnapshot {
        TransportSnapshot {
            rx_packets: self.rx_packets(),
            rx_bytes: self.rx_bytes(),
            tx_packets: self.tx_packets(),
            tx_bytes: self.tx_bytes(),
            dropped: self.dropped_packets(),
            rate_limited: self.rate_limited_packets(),
            errors: self.errors(),
            last_error_age_secs: self.last_error_age_secs(),
        }
    }

    pub fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.dropped_packets.store(0, Ordering::Relaxed);
        self.rate_limited_packets.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.last_error_timestamp.store(0, Ordering::Relaxed);
    }
}
