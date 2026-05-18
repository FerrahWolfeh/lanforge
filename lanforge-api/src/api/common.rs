use serde::{Deserialize, Serialize};
use std::fmt;
pub use lanforge_types::system::{Cap, ServerCapabilities, ServiceBanner};

/// Supported response encodings.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// JSON line-based (standard).
    Json,
    /// Postcard binary (length-prefixed).
    Postcard,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Postcard => write!(f, "postcard"),
        }
    }
}

/// Supported compression algorithms.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// No compression.
    None,
    /// Zstd compression.
    Zstd,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Zstd => write!(f, "zstd"),
        }
    }
}

/// Daemon capabilities payload.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Capabilities {
    /// List of supported response encodings.
    pub encodings: Vec<Encoding>,
    /// List of supported compression algorithms.
    pub compression: Vec<Compression>,
}

/// A simple success result containing a message.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SimpleSuccess {
    /// Informational message about the operation.
    pub message: String,
}

/// Standard top-level wrapper for HTTP success responses containing data.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpDataResponse<T> {
    pub data: T,
}

/// Standard top-level wrapper for HTTP paginated success responses containing data and metadata.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpPaginatedResponse<T, M> {
    pub data: T,
    pub meta: M,
}

/// Metadata for DNS cache dump responses.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CacheMeta {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

/// Metadata for DNS query log responses.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogMeta {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

/// Standard top-level wrapper for HTTP error responses.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpErrorResponse {
    pub error: String,
}

/// Errors that can occur during RPC calls.
#[derive(Debug, Serialize, Deserialize, thiserror::Error, Clone)]
pub enum RpcCallError {
    #[error("Invalid MAC address: {0}")]
    InvalidMac(String),
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Failed to apply update")]
    UpdateFailed,
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Invalid response type")]
    InvalidResponseType,
}

use lanforge_types::events::{DeviceChange, DeviceEvent, DnsEvent, LanforgeEvent, SystemEvent};

/// Event categories used for filtering event streams.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    DeviceOnline,
    DeviceOffline,
    DeviceUpdated,
    DevicePurged,
    DhcpLeaseGranted,
    DhcpLeaseReleased,
    DnsQuery,
    DnsBlocked,
    DnsRewriteUpdated,
    AdblockToggled,
    ScanCompleted,
    ConfigReloaded,
}

impl EventKind {
    #[must_use]
    pub fn matches(&self, event: &LanforgeEvent) -> bool {
        match self {
            Self::DeviceOnline => match event {
                LanforgeEvent::Device(DeviceEvent::Updated { change, .. }) => {
                    matches!(&**change, DeviceChange::StatusChanged { online: true, .. })
                }
                _ => false,
            },
            Self::DeviceOffline => match event {
                LanforgeEvent::Device(DeviceEvent::Updated { change, .. }) => {
                    matches!(
                        &**change,
                        DeviceChange::StatusChanged { online: false, .. }
                            | DeviceChange::HostRemoved
                            | DeviceChange::IpOffline { .. }
                    )
                }
                _ => false,
            },
            Self::DeviceUpdated => {
                matches!(event, LanforgeEvent::Device(DeviceEvent::Updated { .. }))
            }
            Self::DevicePurged => {
                matches!(event, LanforgeEvent::Device(DeviceEvent::Purged { .. }))
            }
            Self::DhcpLeaseGranted => match event {
                LanforgeEvent::Device(DeviceEvent::Updated { change, .. }) => matches!(
                    &**change,
                    DeviceChange::V4Assigned { .. }
                        | DeviceChange::V6Assigned { .. }
                        | DeviceChange::V6PrefixAssigned { .. }
                ),
                LanforgeEvent::Device(DeviceEvent::LeaseRenew { .. }) => true,
                _ => false,
            },
            Self::DhcpLeaseReleased => match event {
                LanforgeEvent::Device(
                    DeviceEvent::LeaseRelease { .. } | DeviceEvent::Expired { .. },
                ) => true,
                LanforgeEvent::Device(DeviceEvent::Updated { change, .. }) => {
                    matches!(&**change, DeviceChange::LeaseExpired { .. })
                }
                _ => false,
            },
            Self::DnsQuery => matches!(event, LanforgeEvent::Dns(DnsEvent::QueryResolved(_))),
            Self::DnsBlocked => match event {
                #[cfg(feature = "adblock")]
                LanforgeEvent::Dns(DnsEvent::QueryBlocked { .. }) => true,
                #[cfg(feature = "adblock")]
                LanforgeEvent::Dns(DnsEvent::AdblockBlock(_)) => true,
                _ => false,
            },
            Self::DnsRewriteUpdated => {
                matches!(event, LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged))
            }
            Self::AdblockToggled => {
                #[cfg(feature = "adblock")]
                {
                    matches!(event, LanforgeEvent::Dns(DnsEvent::AdblockToggle { .. }))
                }
                #[cfg(not(feature = "adblock"))]
                {
                    false
                }
            }
            Self::ScanCompleted => {
                matches!(
                    event,
                    LanforgeEvent::Device(DeviceEvent::NeighborBatchSummary { .. })
                )
            }
            Self::ConfigReloaded => matches!(
                event,
                LanforgeEvent::System(SystemEvent::ReloadConfig | SystemEvent::ConfigUpdate { .. },)
            ),
        }
    }
}
