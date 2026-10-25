use bitflags::bitflags;
use serde::{Deserialize, Serialize};

/// High-level logical sections of the Lanforge configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    System,
    Database,
    Api,
    Http,
    Monitor,
    Mdns,
    Tftp,
    Dhcp,
    Ra,
    Dns,
    Adblock,
    Firewall,
    Pppoe,
    Traffic,
    Hosts,
}

impl Section {
    /// All defined sections in canonical order.
    pub const ALL: [Self; 15] = [
        Self::System,
        Self::Database,
        Self::Api,
        Self::Http,
        Self::Monitor,
        Self::Mdns,
        Self::Tftp,
        Self::Dhcp,
        Self::Ra,
        Self::Dns,
        Self::Adblock,
        Self::Firewall,
        Self::Pppoe,
        Self::Traffic,
        Self::Hosts,
    ];

    /// Canonical section identifier matching the top-level TOML key.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Database => "database",
            Self::Api => "api",
            Self::Http => "http",
            Self::Monitor => "monitor",
            Self::Mdns => "mdns",
            Self::Tftp => "tftp",
            Self::Dhcp => "dhcp",
            Self::Ra => "ra",
            Self::Dns => "dns",
            Self::Adblock => "adblock",
            Self::Firewall => "firewall",
            Self::Pppoe => "pppoe",
            Self::Traffic => "traffic",
            Self::Hosts => "hosts",
        }
    }

    /// Whether this section is a dynamic section where `config.redb` is the primary source of truth.
    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(
            self,
            Self::Dhcp
                | Self::Ra
                | Self::Dns
                | Self::Adblock
                | Self::Firewall
                | Self::Pppoe
                | Self::Traffic
                | Self::Hosts
        )
    }

    /// Returns the corresponding `SectionSet` bitflag.
    #[must_use]
    pub const fn as_bitflag(&self) -> SectionSet {
        match self {
            Self::System => SectionSet::SYSTEM,
            Self::Database => SectionSet::DATABASE,
            Self::Api => SectionSet::API,
            Self::Http => SectionSet::HTTP,
            Self::Monitor => SectionSet::MONITOR,
            Self::Mdns => SectionSet::MDNS,
            Self::Tftp => SectionSet::TFTP,
            Self::Dhcp => SectionSet::DHCP,
            Self::Ra => SectionSet::RA,
            Self::Dns => SectionSet::DNS,
            Self::Adblock => SectionSet::ADBLOCK,
            Self::Firewall => SectionSet::FIREWALL,
            Self::Pppoe => SectionSet::PPPOE,
            Self::Traffic => SectionSet::TRAFFIC,
            Self::Hosts => SectionSet::HOSTS,
        }
    }
}

impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

bitflags! {
    /// Bitmask set of configuration sections for change tracking and selective patching.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct SectionSet: u32 {
        const SYSTEM   = 1 << 0;
        const DATABASE = 1 << 1;
        const API      = 1 << 2;
        const HTTP     = 1 << 3;
        const MONITOR  = 1 << 4;
        const MDNS     = 1 << 5;
        const TFTP     = 1 << 6;
        const DHCP     = 1 << 7;
        const RA       = 1 << 8;
        const DNS      = 1 << 9;
        const ADBLOCK  = 1 << 10;
        const FIREWALL = 1 << 11;
        const PPPOE    = 1 << 12;
        const TRAFFIC  = 1 << 13;
        const HOSTS    = 1 << 14;

        const STATIC   = Self::SYSTEM.bits() | Self::DATABASE.bits() | Self::API.bits()
                       | Self::HTTP.bits() | Self::MONITOR.bits() | Self::MDNS.bits() | Self::TFTP.bits();

        const DYNAMIC  = Self::DHCP.bits() | Self::RA.bits() | Self::DNS.bits()
                       | Self::ADBLOCK.bits() | Self::FIREWALL.bits() | Self::PPPOE.bits()
                       | Self::TRAFFIC.bits() | Self::HOSTS.bits();
    }
}

impl Serialize for SectionSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.bits().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SectionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Ok(Self::from_bits_truncate(bits))
    }
}

impl From<lanforge_types::config::ConfigDomain> for Section {
    fn from(domain: lanforge_types::config::ConfigDomain) -> Self {
        match domain {
            lanforge_types::config::ConfigDomain::Pppoe => Self::Pppoe,
            lanforge_types::config::ConfigDomain::Firewall => Self::Firewall,
            lanforge_types::config::ConfigDomain::Traffic => Self::Traffic,
            lanforge_types::config::ConfigDomain::DhcpV4Pools
            | lanforge_types::config::ConfigDomain::DhcpV6Pools
            | lanforge_types::config::ConfigDomain::DhcpV4Options
            | lanforge_types::config::ConfigDomain::DhcpV6Options => Self::Dhcp,
            lanforge_types::config::ConfigDomain::Tftp => Self::Tftp,
            lanforge_types::config::ConfigDomain::RaServer
            | lanforge_types::config::ConfigDomain::RaPrefixes
            | lanforge_types::config::ConfigDomain::RaRdnss
            | lanforge_types::config::ConfigDomain::RaDnssl => Self::Ra,
            lanforge_types::config::ConfigDomain::DnsUpstreams
            | lanforge_types::config::ConfigDomain::DnsUpstreamMode
            | lanforge_types::config::ConfigDomain::DnsRewrites
            | lanforge_types::config::ConfigDomain::DnsAllowlist
            | lanforge_types::config::ConfigDomain::DnsReverse
            | lanforge_types::config::ConfigDomain::DnsListen => Self::Dns,
            lanforge_types::config::ConfigDomain::DnsAdblock
            | lanforge_types::config::ConfigDomain::DnsAdblockUrls
            | lanforge_types::config::ConfigDomain::DnsAdblockRules => Self::Adblock,
            lanforge_types::config::ConfigDomain::Discovery => Self::Monitor,
            lanforge_types::config::ConfigDomain::Interfaces => Self::System,
            lanforge_types::config::ConfigDomain::Http => Self::Http,
            lanforge_types::config::ConfigDomain::Auth => Self::System,
        }
    }
}

impl From<lanforge_types::config::DomainSet> for SectionSet {
    fn from(domains: lanforge_types::config::DomainSet) -> Self {
        let mut set = Self::empty();
        for domain in domains.domains() {
            set |= Section::from(domain).as_bitflag();
        }
        set
    }
}

