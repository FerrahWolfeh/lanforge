//! Telemetry counters for `DHCPv4` and `DHCPv6` services.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Telemetry statistics for `DHCPv4`.
#[derive(Debug)]
pub struct Dhcpv4Stats {
    /// Number of DHCPDISCOVER packets received.
    pub discovers: AtomicU64,
    /// Number of DHCPOFFER packets sent.
    pub offers: AtomicU64,
    /// Number of DHCPREQUEST packets received.
    pub requests: AtomicU64,
    /// Number of DHCPACK packets sent.
    pub acks: AtomicU64,
    /// Number of DHCPNAK packets sent.
    pub naks: AtomicU64,
    /// Number of DHCPRELEASE packets received.
    pub releases: AtomicU64,
    /// Number of DHCPDECLINE packets received.
    pub declines: AtomicU64,
    /// Number of DHCPINFORM packets received.
    pub informs: AtomicU64,
}

impl Default for Dhcpv4Stats {
    fn default() -> Self {
        Self {
            discovers: AtomicU64::new(0),
            offers: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            acks: AtomicU64::new(0),
            naks: AtomicU64::new(0),
            releases: AtomicU64::new(0),
            declines: AtomicU64::new(0),
            informs: AtomicU64::new(0),
        }
    }
}

impl Dhcpv4Stats {
    /// Creates a new instance of `DHCPv4` stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures a snapshot of the current atomic counter values.
    #[must_use]
    pub fn snapshot(&self) -> Dhcpv4StatsSnapshot {
        Dhcpv4StatsSnapshot {
            discovers: self.discovers.load(Ordering::Relaxed),
            offers: self.offers.load(Ordering::Relaxed),
            requests: self.requests.load(Ordering::Relaxed),
            acks: self.acks.load(Ordering::Relaxed),
            naks: self.naks.load(Ordering::Relaxed),
            releases: self.releases.load(Ordering::Relaxed),
            declines: self.declines.load(Ordering::Relaxed),
            informs: self.informs.load(Ordering::Relaxed),
        }
    }
}

/// A serializable snapshot of `DHCPv4` stats.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Dhcpv4StatsSnapshot {
    /// Number of DHCPDISCOVER packets received.
    pub discovers: u64,
    /// Number of DHCPOFFER packets sent.
    pub offers: u64,
    /// Number of DHCPREQUEST packets received.
    pub requests: u64,
    /// Number of DHCPACK packets sent.
    pub acks: u64,
    /// Number of DHCPNAK packets sent.
    pub naks: u64,
    /// Number of DHCPRELEASE packets received.
    pub releases: u64,
    /// Number of DHCPDECLINE packets received.
    pub declines: u64,
    /// Number of DHCPINFORM packets received.
    pub informs: u64,
}

/// Telemetry statistics for `DHCPv6`.
#[derive(Debug)]
pub struct Dhcpv6Stats {
    /// Number of `DHCPv6` Solicit messages received.
    pub solicits: AtomicU64,
    /// Number of `DHCPv6` Advertise messages sent.
    pub advertises: AtomicU64,
    /// Number of `DHCPv6` Request messages received.
    pub requests: AtomicU64,
    /// Number of `DHCPv6` Reply messages sent.
    pub replies: AtomicU64,
    /// Number of `DHCPv6` Renew messages received.
    pub renews: AtomicU64,
    /// Number of `DHCPv6` Rebind messages received.
    pub rebinds: AtomicU64,
    /// Number of `DHCPv6` Release messages received.
    pub releases: AtomicU64,
    /// Number of `DHCPv6` Decline messages received.
    pub declines: AtomicU64,
    /// Number of `DHCPv6` Information-Request messages received.
    pub info_requests: AtomicU64,
}

impl Default for Dhcpv6Stats {
    fn default() -> Self {
        Self {
            solicits: AtomicU64::new(0),
            advertises: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            replies: AtomicU64::new(0),
            renews: AtomicU64::new(0),
            rebinds: AtomicU64::new(0),
            releases: AtomicU64::new(0),
            declines: AtomicU64::new(0),
            info_requests: AtomicU64::new(0),
        }
    }
}

impl Dhcpv6Stats {
    /// Creates a new instance of `DHCPv6` stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures a snapshot of the current atomic counter values.
    #[must_use]
    pub fn snapshot(&self) -> Dhcpv6StatsSnapshot {
        Dhcpv6StatsSnapshot {
            solicits: self.solicits.load(Ordering::Relaxed),
            advertises: self.advertises.load(Ordering::Relaxed),
            requests: self.requests.load(Ordering::Relaxed),
            replies: self.replies.load(Ordering::Relaxed),
            renews: self.renews.load(Ordering::Relaxed),
            rebinds: self.rebinds.load(Ordering::Relaxed),
            releases: self.releases.load(Ordering::Relaxed),
            declines: self.declines.load(Ordering::Relaxed),
            info_requests: self.info_requests.load(Ordering::Relaxed),
        }
    }
}

/// A serializable snapshot of `DHCPv6` stats.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Dhcpv6StatsSnapshot {
    /// Number of `DHCPv6` Solicit messages received.
    pub solicits: u64,
    /// Number of `DHCPv6` Advertise messages sent.
    pub advertises: u64,
    /// Number of `DHCPv6` Request messages received.
    pub requests: u64,
    /// Number of `DHCPv6` Reply messages sent.
    pub replies: u64,
    /// Number of `DHCPv6` Renew messages received.
    pub renews: u64,
    /// Number of `DHCPv6` Rebind messages received.
    pub rebinds: u64,
    /// Number of `DHCPv6` Release messages received.
    pub releases: u64,
    /// Number of `DHCPv6` Decline messages received.
    pub declines: u64,
    /// Number of `DHCPv6` Information-Request messages received.
    pub info_requests: u64,
}
