#[cfg(feature = "adblock")]
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::network::QueryLogEntry;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum DnsEvent {
    #[cfg(feature = "adblock")]
    AdblockToggle {
        enabled: bool,
        duration_secs: Option<u64>,
    },
    #[cfg(feature = "adblock")]
    AdblockReload,
    #[cfg(feature = "adblock")]
    AdblockBlock(String),
    #[cfg(feature = "adblock")]
    AdblockAllow(String),
    #[cfg(feature = "adblock")]
    QueryBlocked { src_addr: IpAddr, domain: String },
    /// A DNS query was resolved.
    QueryResolved(Arc<QueryLogEntry>),
    /// Flush the DNS cache.
    #[default]
    CacheFlush,
}

impl DnsEvent {
    /// Stable variant name for event streams. Lives here so the adblock variants follow this
    /// crate's `adblock` feature: a consumer gating them on its own feature breaks as soon as
    /// feature unification enables them through another crate.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "adblock")]
            Self::AdblockToggle { .. } => "AdblockToggle",
            #[cfg(feature = "adblock")]
            Self::AdblockReload => "AdblockReload",
            #[cfg(feature = "adblock")]
            Self::AdblockBlock(..) => "AdblockBlock",
            #[cfg(feature = "adblock")]
            Self::AdblockAllow(..) => "AdblockAllow",
            #[cfg(feature = "adblock")]
            Self::QueryBlocked { .. } => "QueryBlocked",
            Self::QueryResolved(..) => "QueryResolved",
            Self::CacheFlush => "CacheFlush",
        }
    }
}
