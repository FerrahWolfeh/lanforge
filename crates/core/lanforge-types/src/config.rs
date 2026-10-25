//! Configuration domain classification and section lifecycle abstractions.

use std::net::SocketAddr;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::network::dhcp::{DhcpOptionsConfig, Dhcpv4Options, Dhcpv4Pool, Dhcpv6Options, Dhcpv6Pool, TftpOptions};
use crate::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use crate::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use crate::network::dns::AdblockUrlEntry;
use crate::network::firewall::FirewallConfig;
use crate::network::pppoe::PppoeConfig;
use crate::network::ra::{DnsslConfig, RAPrefix, RaServerConfig, RdnssConfig};
use crate::network::{DnsReverseResolver, ListenConfig, TrafficConfig};

/// Logical configuration domain identifying which subsystem owns a particular configuration section.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDomain {
    Pppoe,
    Firewall,
    Traffic,
    DhcpV4Pools,
    DhcpV6Pools,
    DhcpV4Options,
    DhcpV6Options,
    Tftp,
    RaServer,
    RaPrefixes,
    RaRdnss,
    RaDnssl,
    DnsUpstreams,
    DnsUpstreamMode,
    DnsRewrites,
    DnsAllowlist,
    DnsAdblock,
    DnsAdblockUrls,
    DnsAdblockRules,
    DnsReverse,
    DnsListen,
    Discovery,
    Interfaces,
    Http,
    Auth,
}

impl ConfigDomain {
    /// Returns the corresponding single-flag [`DomainSet`].
    #[must_use]
    pub const fn as_flag(&self) -> DomainSet {
        match self {
            Self::Pppoe => DomainSet::PPPOE,
            Self::Firewall => DomainSet::FIREWALL,
            Self::Traffic => DomainSet::TRAFFIC,
            Self::DhcpV4Pools => DomainSet::DHCP_V4_POOLS,
            Self::DhcpV6Pools => DomainSet::DHCP_V6_POOLS,
            Self::DhcpV4Options => DomainSet::DHCP_V4_OPTIONS,
            Self::DhcpV6Options => DomainSet::DHCP_V6_OPTIONS,
            Self::Tftp => DomainSet::TFTP,
            Self::RaServer => DomainSet::RA_SERVER,
            Self::RaPrefixes => DomainSet::RA_PREFIXES,
            Self::RaRdnss => DomainSet::RA_RDNSS,
            Self::RaDnssl => DomainSet::RA_DNSSL,
            Self::DnsUpstreams => DomainSet::DNS_UPSTREAMS,
            Self::DnsUpstreamMode => DomainSet::DNS_UPSTREAM_MODE,
            Self::DnsRewrites => DomainSet::DNS_REWRITES,
            Self::DnsAllowlist => DomainSet::DNS_ALLOWLIST,
            Self::DnsAdblock => DomainSet::DNS_ADBLOCK,
            Self::DnsAdblockUrls => DomainSet::DNS_ADBLOCK_URLS,
            Self::DnsAdblockRules => DomainSet::DNS_ADBLOCK_RULES,
            Self::DnsReverse => DomainSet::DNS_REVERSE,
            Self::DnsListen => DomainSet::DNS_LISTEN,
            Self::Discovery => DomainSet::DISCOVERY,
            Self::Interfaces => DomainSet::INTERFACES,
            Self::Http => DomainSet::HTTP,
            Self::Auth => DomainSet::AUTH,
        }
    }

    /// Canonical domain name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Pppoe => "pppoe",
            Self::Firewall => "firewall",
            Self::Traffic => "traffic",
            Self::DhcpV4Pools => "dhcp_v4_pools",
            Self::DhcpV6Pools => "dhcp_v6_pools",
            Self::DhcpV4Options => "dhcp_v4_options",
            Self::DhcpV6Options => "dhcp_v6_options",
            Self::Tftp => "tftp",
            Self::RaServer => "ra_server",
            Self::RaPrefixes => "ra_prefixes",
            Self::RaRdnss => "ra_rdnss",
            Self::RaDnssl => "ra_dnssl",
            Self::DnsUpstreams => "dns_upstreams",
            Self::DnsUpstreamMode => "dns_upstream_mode",
            Self::DnsRewrites => "dns_rewrites",
            Self::DnsAllowlist => "dns_allowlist",
            Self::DnsAdblock => "dns_adblock",
            Self::DnsAdblockUrls => "dns_adblock_urls",
            Self::DnsAdblockRules => "dns_adblock_rules",
            Self::DnsReverse => "dns_reverse",
            Self::DnsListen => "dns_listen",
            Self::Discovery => "discovery",
            Self::Interfaces => "interfaces",
            Self::Http => "http",
            Self::Auth => "auth",
        }
    }
}

bitflags! {
    /// Bitset of changed or monitored configuration domains.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct DomainSet: u32 {
        const PPPOE              = 1 << 0;
        const FIREWALL           = 1 << 1;
        const TRAFFIC            = 1 << 2;
        const DHCP_V4_POOLS      = 1 << 3;
        const DHCP_V6_POOLS      = 1 << 4;
        const DHCP_V4_OPTIONS    = 1 << 5;
        const DHCP_V6_OPTIONS    = 1 << 6;
        const TFTP               = 1 << 7;
        const RA_SERVER          = 1 << 8;
        const RA_PREFIXES        = 1 << 9;
        const RA_RDNSS           = 1 << 10;
        const RA_DNSSL           = 1 << 11;
        const DNS_UPSTREAMS      = 1 << 12;
        const DNS_UPSTREAM_MODE  = 1 << 13;
        const DNS_REWRITES       = 1 << 14;
        const DNS_ALLOWLIST      = 1 << 15;
        const DNS_ADBLOCK        = 1 << 16;
        const DNS_ADBLOCK_URLS   = 1 << 17;
        const DNS_ADBLOCK_RULES  = 1 << 18;
        const DNS_REVERSE        = 1 << 19;
        const DNS_LISTEN         = 1 << 20;
        const DISCOVERY          = 1 << 21;
        const INTERFACES         = 1 << 22;
        const HTTP               = 1 << 23;
        const AUTH               = 1 << 24;
    }
}

impl From<ConfigDomain> for DomainSet {
    fn from(domain: ConfigDomain) -> Self {
        domain.as_flag()
    }
}

impl DomainSet {
    /// Iterates over all active [`ConfigDomain`] elements in this set.
    pub fn domains(self) -> impl Iterator<Item = ConfigDomain> {
        const ALL: [(ConfigDomain, DomainSet); 25] = [
            (ConfigDomain::Pppoe, DomainSet::PPPOE),
            (ConfigDomain::Firewall, DomainSet::FIREWALL),
            (ConfigDomain::Traffic, DomainSet::TRAFFIC),
            (ConfigDomain::DhcpV4Pools, DomainSet::DHCP_V4_POOLS),
            (ConfigDomain::DhcpV6Pools, DomainSet::DHCP_V6_POOLS),
            (ConfigDomain::DhcpV4Options, DomainSet::DHCP_V4_OPTIONS),
            (ConfigDomain::DhcpV6Options, DomainSet::DHCP_V6_OPTIONS),
            (ConfigDomain::Tftp, DomainSet::TFTP),
            (ConfigDomain::RaServer, DomainSet::RA_SERVER),
            (ConfigDomain::RaPrefixes, DomainSet::RA_PREFIXES),
            (ConfigDomain::RaRdnss, DomainSet::RA_RDNSS),
            (ConfigDomain::RaDnssl, DomainSet::RA_DNSSL),
            (ConfigDomain::DnsUpstreams, DomainSet::DNS_UPSTREAMS),
            (ConfigDomain::DnsUpstreamMode, DomainSet::DNS_UPSTREAM_MODE),
            (ConfigDomain::DnsRewrites, DomainSet::DNS_REWRITES),
            (ConfigDomain::DnsAllowlist, DomainSet::DNS_ALLOWLIST),
            (ConfigDomain::DnsAdblock, DomainSet::DNS_ADBLOCK),
            (ConfigDomain::DnsAdblockUrls, DomainSet::DNS_ADBLOCK_URLS),
            (ConfigDomain::DnsAdblockRules, DomainSet::DNS_ADBLOCK_RULES),
            (ConfigDomain::DnsReverse, DomainSet::DNS_REVERSE),
            (ConfigDomain::DnsListen, DomainSet::DNS_LISTEN),
            (ConfigDomain::Discovery, DomainSet::DISCOVERY),
            (ConfigDomain::Interfaces, DomainSet::INTERFACES),
            (ConfigDomain::Http, DomainSet::HTTP),
            (ConfigDomain::Auth, DomainSet::AUTH),
        ];
        ALL.into_iter().filter_map(move |(domain, flag)| {
            if self.contains(flag) {
                Some(domain)
            } else {
                None
            }
        })
    }
}

/// Operational impact of a configuration delta on a running service.
///
/// Ordered by increasing disruption severity:
/// `None < Hot < Rebind < Reconnect`
///
/// When multiple changes are applied simultaneously, `std::cmp::max` determines the overall required action.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpact {
    /// No change detected (`old == new`). Service is not woken.
    None,
    /// In-place state swap without recreating sockets or dropping sessions.
    Hot,
    /// Re-bind socket listeners (e.g. interface or listen port/address changed).
    Rebind,
    /// Full session teardown and reconnection (e.g. `PPPoE` credentials or interface changed).
    Reconnect,
}

/// Implemented by each distinct configuration section.
pub trait ConfigSection: Clone + PartialEq + Send + Sync + 'static {
    /// Logical domain corresponding to this section.
    const DOMAIN: ConfigDomain;

    /// Classifies the impact of migrating from `old` to `new`.
    ///
    /// Must return [`ChangeImpact::None`] when `old == new`.
    fn classify(old: &Self, new: &Self) -> ChangeImpact;
}

// ---------------------------------------------------------------------------
// Section types and implementations
// ---------------------------------------------------------------------------

/// DNS listener configuration for UDP/TCP port 53, `DoT`, and `DoQ`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsListenConfig {
    pub listen: ListenConfig,
    pub dot_listen: Option<SocketAddr>,
    pub dot_enabled: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub doq_listen: Option<SocketAddr>,
    pub doq_enabled: bool,
}

impl Default for DnsListenConfig {
    fn default() -> Self {
        Self {
            listen: ListenConfig::dual_stack(53),
            dot_listen: None,
            dot_enabled: false,
            tls_cert: None,
            tls_key: None,
            doq_listen: None,
            doq_enabled: false,
        }
    }
}

/// DNS domain allowlist entries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DnsAllowlist(pub Vec<String>);

impl std::ops::Deref for DnsAllowlist {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for DnsAllowlist {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<String>> for DnsAllowlist {
    fn from(v: Vec<String>) -> Self {
        Self(v)
    }
}

// 1. PPPoE
impl ConfigSection for PppoeConfig {
    const DOMAIN: ConfigDomain = ConfigDomain::Pppoe;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else if old.wan_iface != new.wan_iface {
            ChangeImpact::Rebind
        } else if old.dataplane != new.dataplane
            || old.username != new.username
            || old.password != new.password
            || old.service_name != new.service_name
            || old.ac_name != new.ac_name
            || old.auth != new.auth
            || old.mru != new.mru
        {
            ChangeImpact::Reconnect
        } else {
            ChangeImpact::Hot
        }
    }
}

// 2. RA Server
impl ConfigSection for RaServerConfig {
    const DOMAIN: ConfigDomain = ConfigDomain::RaServer;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else if old.iface != new.iface {
            ChangeImpact::Rebind
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Vec<RAPrefix> {
    const DOMAIN: ConfigDomain = ConfigDomain::RaPrefixes;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Vec<RdnssConfig> {
    const DOMAIN: ConfigDomain = ConfigDomain::RaRdnss;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Vec<DnsslConfig> {
    const DOMAIN: ConfigDomain = ConfigDomain::RaDnssl;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

// 3. DHCP Pools
impl ConfigSection for Vec<Dhcpv4Pool> {
    const DOMAIN: ConfigDomain = ConfigDomain::DhcpV4Pools;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Vec<Dhcpv6Pool> {
    const DOMAIN: ConfigDomain = ConfigDomain::DhcpV6Pools;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

// 4. DHCP & TFTP Options
impl ConfigSection for Dhcpv4Options {
    const DOMAIN: ConfigDomain = ConfigDomain::DhcpV4Options;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Dhcpv6Options {
    const DOMAIN: ConfigDomain = ConfigDomain::DhcpV6Options;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for TftpOptions {
    const DOMAIN: ConfigDomain = ConfigDomain::Tftp;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else if old.listen_addr != new.listen_addr {
            ChangeImpact::Rebind
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for DhcpOptionsConfig {
    const DOMAIN: ConfigDomain = ConfigDomain::DhcpV4Options;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else if old.tftp.listen_addr != new.tftp.listen_addr {
            ChangeImpact::Rebind
        } else {
            ChangeImpact::Hot
        }
    }
}

// 5. Firewall & Traffic
impl ConfigSection for FirewallConfig {
    const DOMAIN: ConfigDomain = ConfigDomain::Firewall;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for TrafficConfig {
    const DOMAIN: ConfigDomain = ConfigDomain::Traffic;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

// 6. DNS Sections
impl ConfigSection for Vec<UpstreamTarget> {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsUpstreams;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for UpstreamMode {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsUpstreamMode;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Vec<RewriteRule> {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsRewrites;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for DnsAllowlist {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsAllowlist;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for AdblockDbConfig {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsAdblock;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Vec<AdblockUrlEntry> {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsAdblockUrls;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Vec<AdblockRuleEntry> {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsAdblockRules;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for Vec<DnsReverseResolver> {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsReverse;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Hot
        }
    }
}

impl ConfigSection for DnsListenConfig {
    const DOMAIN: ConfigDomain = ConfigDomain::DnsListen;

    fn classify(old: &Self, new: &Self) -> ChangeImpact {
        if old == new {
            ChangeImpact::None
        } else {
            ChangeImpact::Rebind
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_change_impact_ordering() {
        assert!(ChangeImpact::None < ChangeImpact::Hot);
        assert!(ChangeImpact::Hot < ChangeImpact::Rebind);
        assert!(ChangeImpact::Rebind < ChangeImpact::Reconnect);
        assert_eq!(ChangeImpact::Hot.max(ChangeImpact::Reconnect), ChangeImpact::Reconnect);
        assert_eq!(ChangeImpact::None.max(ChangeImpact::Hot), ChangeImpact::Hot);
    }

    #[test]
    fn test_domain_set_bits_and_iterator() {
        let mut set = DomainSet::empty();
        set |= ConfigDomain::Pppoe.as_flag();
        set |= ConfigDomain::RaPrefixes.as_flag();

        assert!(set.contains(DomainSet::PPPOE));
        assert!(set.contains(DomainSet::RA_PREFIXES));
        assert!(!set.contains(DomainSet::FIREWALL));

        let domains: Vec<_> = set.domains().collect();
        assert_eq!(domains, vec![ConfigDomain::Pppoe, ConfigDomain::RaPrefixes]);
    }

    #[test]
    fn test_pppoe_classify() {
        let base = PppoeConfig {
            wan_iface: "eth1".into(),
            username: "user".into(),
            password: "pwd".into(),
            lcp_echo_interval_secs: 20,
            reconnect_delay_secs: 10,
            ..Default::default()
        };

        // None
        assert_eq!(PppoeConfig::classify(&base, &base), ChangeImpact::None);

        // Hot: lcp_echo_interval_secs, reconnect_delay_secs, discovery_padi_retries, terminal_probe
        let mut hot = base.clone();
        hot.lcp_echo_interval_secs = 30;
        assert_eq!(PppoeConfig::classify(&base, &hot), ChangeImpact::Hot);

        let mut hot_delay = base.clone();
        hot_delay.reconnect_delay_secs = 15;
        assert_eq!(PppoeConfig::classify(&base, &hot_delay), ChangeImpact::Hot);

        // Rebind: wan_iface
        let mut rec_iface = base.clone();
        rec_iface.wan_iface = "eth2".into();
        assert_eq!(PppoeConfig::classify(&base, &rec_iface), ChangeImpact::Rebind);

        // Reconnect: username, password, dataplane, auth, mru
        let mut rec_user = base.clone();
        rec_user.username = "user2".into();
        assert_eq!(PppoeConfig::classify(&base, &rec_user), ChangeImpact::Reconnect);

        let mut rec_mru = base.clone();
        rec_mru.mru = 1480;
        assert_eq!(PppoeConfig::classify(&base, &rec_mru), ChangeImpact::Reconnect);
    }

    #[test]
    fn test_ra_classify() {
        let base = RaServerConfig {
            iface: Some("eth0".into()),
            hop_limit: 64,
            max_interval_secs: 200,
            ..Default::default()
        };

        // None
        assert_eq!(RaServerConfig::classify(&base, &base), ChangeImpact::None);

        // Hot
        let mut hot = base.clone();
        hot.hop_limit = 128;
        assert_eq!(RaServerConfig::classify(&base, &hot), ChangeImpact::Hot);

        // Rebind on iface change
        let mut rebind = base.clone();
        rebind.iface = Some("eth1".into());
        assert_eq!(RaServerConfig::classify(&base, &rebind), ChangeImpact::Rebind);
    }

    #[test]
    fn test_tftp_classify() {
        let base = TftpOptions {
            listen_addr: "0.0.0.0:69".into(),
            timeout: 5,
            ..Default::default()
        };

        assert_eq!(TftpOptions::classify(&base, &base), ChangeImpact::None);

        let mut hot = base.clone();
        hot.timeout = 10;
        assert_eq!(TftpOptions::classify(&base, &hot), ChangeImpact::Hot);

        let mut rebind = base.clone();
        rebind.listen_addr = "127.0.0.1:69".into();
        assert_eq!(TftpOptions::classify(&base, &rebind), ChangeImpact::Rebind);
    }

    #[test]
    fn test_dhcp_pools_classify() {
        let base = vec![Dhcpv4Pool {
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 200),
            ..Default::default()
        }];

        assert_eq!(<Vec<Dhcpv4Pool>>::classify(&base, &base), ChangeImpact::None);

        let mut hot = base.clone();
        hot[0].range_end = Ipv4Addr::new(192, 168, 1, 250);
        assert_eq!(<Vec<Dhcpv4Pool>>::classify(&base, &hot), ChangeImpact::Hot);
    }

    #[test]
    fn test_dns_listen_classify() {
        let base = DnsListenConfig::default();
        assert_eq!(DnsListenConfig::classify(&base, &base), ChangeImpact::None);

        let mut rebind = base.clone();
        rebind.dot_enabled = true;
        assert_eq!(DnsListenConfig::classify(&base, &rebind), ChangeImpact::Rebind);
    }
}
