use std::net::IpAddr;

use lanforge_types::identifiers::MacAddr;
use serde::{Deserialize, Serialize};

/// A response containing active DHCP leases.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeasesResponse {
    /// List of lease entries.
    pub leases: Vec<LeaseEntry>,
}

/// A single active DHCP lease entry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeaseEntry {
    /// MAC address of the leased device.
    pub mac: MacAddr,
    /// Hostname of the device.
    pub hostname: String,
    /// Assigned IP address or prefix.
    pub address: IpAddr,
    /// Type of lease (v4, v6, prefix).
    pub kind: LeaseKind,
    /// Expiration timestamp in seconds since epoch.
    pub expires: u64,
    /// Remaining lifetime in seconds.
    pub remaining_secs: u64,
}

/// Supported DHCP lease types.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    /// Standard `DHCPv4` lease.
    V4,
    /// `DHCPv6` `IA_NA` address lease.
    V6,
    /// `DHCPv6` `IA_PD` prefix delegation lease.
    V6Prefix,
}

/// Detailed DHCP pool utilization.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DhcpPoolsResponse {
    pub v4_pools: Vec<DhcpPoolEntry>,
    pub v6_pools: Vec<DhcpPoolEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DhcpPoolEntry {
    pub subnet: String,
    pub total: u32,
    pub used: u32,
    pub available: u32,
    pub utilization_percent: f32,
}
