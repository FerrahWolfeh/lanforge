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
    /// DNS rewrite rules changed in the database.
    ConfigRewritesChanged,
    /// DNS allowlist changed in the database.
    ConfigAllowlistChanged,
    /// Adblock configuration changed in the database.
    ConfigAdblockChanged,
    /// Custom adblock rules (blacklist/whitelist) changed in the database.
    ConfigAdblockRulesChanged,
    /// DNS upstreams changed in the database.
    ConfigUpstreamsChanged,
    /// DNS upstream resolution mode changed.
    ConfigUpstreamModeChanged(crate::network::dns::UpstreamMode),
    /// DNS reverse resolvers changed.
    ConfigReverseResolversChanged,
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
            Self::ConfigRewritesChanged => "ConfigRewritesChanged",
            Self::ConfigAllowlistChanged => "ConfigAllowlistChanged",
            Self::ConfigAdblockChanged => "ConfigAdblockChanged",
            Self::ConfigAdblockRulesChanged => "ConfigAdblockRulesChanged",
            Self::ConfigUpstreamsChanged => "ConfigUpstreamsChanged",
            Self::ConfigUpstreamModeChanged(_) => "ConfigUpstreamModeChanged",
            Self::ConfigReverseResolversChanged => "ConfigReverseResolversChanged",
        }
    }
}
