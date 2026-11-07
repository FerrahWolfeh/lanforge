use bitflags::bitflags;
use lanforge_types::config::{ConfigDomain, DomainSet};
use serde::{Deserialize, Serialize};
use std::fmt;

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

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

        /// The file is their only source, written by the API before the change is applied; a
        /// broken one is set aside (`ConfigFile::parse_lenient`), never read as defaults.
        const FILE_OWNED = Self::PPPOE.bits() | Self::TRAFFIC.bits() | Self::FIREWALL.bits()
                         | Self::DHCP.bits() | Self::RA.bits() | Self::HOSTS.bits()
                         | Self::DNS.bits() | Self::ADBLOCK.bits();
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

impl From<ConfigDomain> for Section {
    fn from(domain: ConfigDomain) -> Self {
        match domain {
            ConfigDomain::Pppoe => Self::Pppoe,
            ConfigDomain::Firewall => Self::Firewall,
            ConfigDomain::Traffic => Self::Traffic,
            ConfigDomain::DhcpV4Pools
            | ConfigDomain::DhcpV6Pools
            | ConfigDomain::DhcpV4Options
            | ConfigDomain::DhcpV6Options => Self::Dhcp,
            ConfigDomain::Tftp => Self::Tftp,
            ConfigDomain::RaServer
            | ConfigDomain::RaPrefixes
            | ConfigDomain::RaRdnss
            | ConfigDomain::RaDnssl => Self::Ra,
            ConfigDomain::DnsUpstreams
            | ConfigDomain::DnsUpstreamMode
            | ConfigDomain::DnsRewrites
            | ConfigDomain::DnsReverse
            | ConfigDomain::DnsListen => Self::Dns,
            // `[system] search_domains`, but DNS is its consumer: file-owned, never synced.
            ConfigDomain::SiteDomains => Self::Dns,
            ConfigDomain::DnsAdblock
            | ConfigDomain::DnsAdblockUrls
            | ConfigDomain::DnsAdblockRules => Self::Adblock,
            ConfigDomain::Discovery => Self::Monitor,
            ConfigDomain::Interfaces => Self::System,
            ConfigDomain::Http => Self::Http,
            ConfigDomain::Auth => Self::System,
        }
    }
}

impl From<DomainSet> for SectionSet {
    fn from(domains: DomainSet) -> Self {
        let mut set = Self::empty();
        for domain in domains.domains() {
            set |= Section::from(domain).as_bitflag();
        }
        set
    }
}
