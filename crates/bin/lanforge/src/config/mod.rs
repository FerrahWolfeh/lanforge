//! Lanforge configuration — Unified management of CLI, TOML, and Environment.
//!
//! The configuration system uses a clean layered pipeline:
//! 1. **Default**: Router-first fail-safe baseline values.
//! 2. **Auto-Detect**: Hardware-aware LAN interface detection & RFC 4193 ULA generation.
//! 3. **TOML**: Declarative settings from `/etc/lanforge/lanforge.toml`.
//! 4. **CLI/Env**: Operational overrides passed via command line or environment variables.

pub mod args;
pub mod auto_detect;
pub mod boot_file;
pub mod toml;

pub use args::CliArgs;
use lanforge_db::config::DatabaseConfig;
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v4::config::Dhcpv4Config;
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v6::config::Dhcpv6Config;
#[cfg(feature = "discovery")]
use lanforge_discovery::{mdns::MdnsConfig, ndp::config::MonitorConfig};
#[cfg(feature = "dns")]
use lanforge_dns::config::DnsConfig;
#[cfg(feature = "http")]
use lanforge_http::config::HttpConfig;
#[cfg(feature = "ra")]
use lanforge_ra::RaConfig;
#[cfg(feature = "tftp")]
use lanforge_tftp::config::TftpConfig;
#[cfg(feature = "dhcp")]
use lanforge_types::device::Ipv6AddrOrSuffix;
#[cfg(all(feature = "ra", any(feature = "dhcp", test)))]
use lanforge_types::network::ra::PrefixSource;
#[cfg(all(feature = "ra", any(feature = "dns", test)))]
use lanforge_types::network::ra::RAPrefix;
#[cfg(feature = "ra")]
use lanforge_types::network::ra::RaServerConfig;
use lanforge_types::system::SystemStatus;
#[cfg(feature = "uds")]
use lanforge_uds::config::ApiConfig;
pub use toml::load_toml;

use clap::Parser;
#[cfg(feature = "http")]
use std::fs;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(test)]
use lanforge_api::config_file::ConfigFile;
#[cfg(feature = "dhcp")]
use lanforge_api::config_file::DhcpSettings;
#[cfg(not(feature = "discovery"))]
use lanforge_api::config_file::MonitorFile;
#[cfg(feature = "dns")]
use lanforge_api::config_file::{AdblockSettings, DnsSettings};
#[cfg(feature = "ra")]
use lanforge_api::config_file::{RaInputs, effective_ra};
#[cfg(feature = "pppoe")]
use lanforge_pppoe::config::PppoeConfig as PppoeTomlConfig;
use lanforge_types::device::StaticHost;
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::{Ipv6Prefix, is_ula};

use crate::config::toml::SystemCfg;

/// Consolidated and final system configuration.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    pub system: SystemCfg,
    pub database: DatabaseConfig,

    // RA
    #[cfg(feature = "ra")]
    pub ra_enabled: bool,
    /// `[ra]` as written; see `effective_ra` for what the daemon runs.
    #[cfg(feature = "ra")]
    pub ra: RaServerConfig,

    // DHCPv4
    #[cfg(feature = "dhcp")]
    pub dhcpv4_enabled: bool,
    #[cfg(feature = "dhcp")]
    pub dhcpv4_toml: Dhcpv4Config,

    // DHCPv6
    #[cfg(feature = "dhcp")]
    pub dhcpv6_enabled: bool,
    #[cfg(feature = "dhcp")]
    pub dhcpv6_toml: Dhcpv6Config,
    /// The DHCP options and pools the daemon runs: `[dhcp]` + `[tftp]`, their only source.
    #[cfg(feature = "dhcp")]
    pub dhcp: DhcpSettings,

    // DNS
    #[cfg(feature = "dns")]
    pub dns_enabled: bool,
    #[cfg(feature = "dns")]
    pub dns_toml: DnsConfig,
    /// `[dns]` as the settings the daemon runs: upstreams (with their names), mode, reverse
    /// resolvers and rewrites. The file is their only source.
    #[cfg(feature = "dns")]
    pub dns: DnsSettings,
    /// `[adblock]` as the settings the daemon runs. The file is their only source.
    #[cfg(feature = "dns")]
    pub adblock: AdblockSettings,
    /// The text of the global adblock rules file (`[adblock] rules`).
    #[cfg(feature = "dns")]
    pub adblock_rules: String,
    pub search_domains: Vec<String>,

    // Monitor & mDNS
    #[cfg(feature = "discovery")]
    pub monitor_toml: MonitorConfig,
    #[cfg(feature = "discovery")]
    pub mdns_toml: MdnsConfig,

    // API, HTTP, TFTP & PPPoE
    #[cfg(feature = "uds")]
    pub api_toml: ApiConfig,
    #[cfg(feature = "http")]
    pub http_toml: HttpConfig,
    #[cfg(feature = "tftp")]
    pub tftp_toml: TftpConfig,
    #[cfg(feature = "pppoe")]
    pub pppoe_enabled: bool,
    #[cfg(feature = "pppoe")]
    pub pppoe_toml: PppoeTomlConfig,
    #[cfg(feature = "nft")]
    pub firewall_enabled: bool,
    #[cfg(feature = "nft")]
    pub firewall_toml: lanforge_nft::FirewallConfig,
    #[cfg(feature = "traffic")]
    pub traffic_enabled: bool,
    #[cfg(feature = "traffic")]
    pub traffic_toml: lanforge_traffic::TrafficConfig,

    pub config_path: String,
    pub config_writable: bool,
    /// Problems found while loading the config file, shown to the admin.
    pub config_issues: Vec<String>,
    /// `[hosts]` (`None`: not read, the table's static hosts stay as they are).
    pub static_hosts: Option<Vec<StaticHost>>,
    /// `[dhcp]` was set aside: the defaults that run are never written over it.
    pub dhcp_set_aside: bool,
}

impl Config {
    /// Load config: parse CLI args, read TOML, run auto-detection, and apply CLI overrides.
    #[must_use]
    pub fn load() -> Self {
        let cli = CliArgs::parse();
        let config_path = cli.resolved_config_path().to_string_lossy().to_string();

        let mut toml_cfg = load_toml(&config_path);

        // 1. Resolve LAN interface with hardware-aware auto-detection
        let wan_iface = {
            #[cfg(feature = "pppoe")]
            {
                Some(toml_cfg.pppoe.wan_iface.as_str())
            }
            #[cfg(not(feature = "pppoe"))]
            {
                None
            }
        };

        let configured_iface = cli
            .iface_lan
            .as_deref()
            .or(Some(toml_cfg.system.iface.as_str()));
        toml_cfg.system.iface = auto_detect::detect_lan_interface(configured_iface, wan_iface);

        // 2. The site ULA is the one the admin put on the LAN interface (lanforge never assigns
        //    addresses): `[system] ula_prefix` names it, or RA finds it on the interface at run
        //    time (`auto_ula`). Never generated here.

        // 3. Resolve DHCP defaults if pools are unconfigured
        #[cfg(feature = "dhcp")]
        {
            let dhcp_defaults = auto_detect::derive_dhcp_defaults(&toml_cfg.system.iface);
            if toml_cfg.dhcp.v4.pools.is_empty() && toml_cfg.dhcp.v4.range_start.is_none() {
                toml_cfg.dhcp.v4.router = dhcp_defaults.router;
                toml_cfg.dhcp.v4.server_id = dhcp_defaults.router;
                toml_cfg.dhcp.v4.subnet_mask = dhcp_defaults.subnet_mask;
                toml_cfg.dhcp.v4.dns = vec![dhcp_defaults.router];
            }
        }

        let search_domains = Self::resolve_search_domains(&toml_cfg);

        Self::apply_cli_overrides(toml_cfg, &cli, search_domains)
    }

    fn resolve_search_domains(toml_cfg: &toml::TomlConfig) -> Vec<String> {
        // Same rule as `ConfigFile::search_domains` (what a reload resolves): `[system]`'s list,
        // then `lan`. It must not depend on which services are compiled in.
        let mut domains: Vec<String> = Vec::with_capacity(4);
        for dom in toml_cfg
            .system
            .search_domains
            .iter()
            .cloned()
            .chain(["lan".to_string()])
        {
            if !domains.contains(&dom) {
                domains.push(dom);
            }
        }
        domains
    }

    fn apply_cli_overrides(
        toml_cfg: toml::TomlConfig,
        cli: &CliArgs,
        search_domains: Vec<String>,
    ) -> Self {
        Self {
            system: Self::apply_system_overrides(toml_cfg.system, cli),
            database: Self::apply_database_overrides(toml_cfg.database, cli),
            #[cfg(feature = "ra")]
            ra_enabled: toml_cfg.ra.enabled,
            #[cfg(feature = "ra")]
            ra: toml_cfg.ra,
            #[cfg(feature = "dhcp")]
            dhcpv4_enabled: toml_cfg.dhcp.v4.enabled,
            #[cfg(feature = "dhcp")]
            dhcpv4_toml: toml_cfg.dhcp.v4,
            #[cfg(feature = "dhcp")]
            dhcpv6_enabled: toml_cfg.dhcp.v6.enabled,
            #[cfg(feature = "dhcp")]
            dhcpv6_toml: toml_cfg.dhcp.v6,
            #[cfg(feature = "dhcp")]
            dhcp: toml_cfg.dhcp.settings,
            #[cfg(feature = "dns")]
            dns_enabled: toml_cfg.dns.enabled,
            #[cfg(feature = "dns")]
            dns_toml: toml_cfg.dns,
            #[cfg(feature = "dns")]
            dns: toml_cfg.dns_settings,
            #[cfg(feature = "dns")]
            adblock: toml_cfg.adblock,
            #[cfg(feature = "dns")]
            adblock_rules: toml_cfg.adblock_rules,
            search_domains,
            #[cfg(feature = "discovery")]
            monitor_toml: toml_cfg.monitor,
            #[cfg(feature = "discovery")]
            mdns_toml: toml_cfg.mdns,
            #[cfg(feature = "uds")]
            api_toml: {
                let mut api = toml_cfg.api;
                if let Some(ref socket) = cli.control_socket {
                    api.socket_path.clone_from(socket);
                }
                api
            },
            #[cfg(feature = "http")]
            http_toml: {
                let mut http = toml_cfg.http;
                if let Some(ref listen_str) = cli.http_listen
                    && let Ok(addr) = listen_str.parse()
                {
                    http.listen = addr;
                }
                http
            },
            #[cfg(feature = "tftp")]
            tftp_toml: toml_cfg.tftp,
            #[cfg(feature = "pppoe")]
            pppoe_enabled: toml_cfg.pppoe.enabled,
            #[cfg(feature = "pppoe")]
            pppoe_toml: toml_cfg.pppoe,
            #[cfg(feature = "nft")]
            firewall_enabled: toml_cfg.firewall.enabled,
            #[cfg(feature = "nft")]
            firewall_toml: toml_cfg.firewall,
            #[cfg(feature = "traffic")]
            traffic_enabled: toml_cfg.traffic.tuning.enabled || toml_cfg.traffic.sqm.enabled,
            #[cfg(feature = "traffic")]
            traffic_toml: toml_cfg.traffic,
            config_issues: toml_cfg.config_issues,
            static_hosts: toml_cfg.static_hosts,
            dhcp_set_aside: toml_cfg.dhcp_set_aside,
            config_path: cli.resolved_config_path().to_string_lossy().to_string(),
            config_writable: if cli.dev {
                false
            } else {
                cli.is_config_dir_writable()
            },
        }
    }

    fn apply_system_overrides(mut system: SystemCfg, cli: &CliArgs) -> SystemCfg {
        if let Some(ref iface) = cli.iface_lan {
            system.iface.clone_from(iface);
        }
        if let Some(ref target_prefix) = cli.target_prefix {
            system.target_prefix.clone_from(target_prefix);
        }
        if let Some(debounce) = cli.debounce_secs {
            system.debounce_secs = debounce;
        }
        system.auto_provision |= cli.auto_provision || cli.dev;
        system.allow_unprivileged |= cli.allow_unprivileged || cli.dev;
        system
    }

    fn apply_database_overrides(mut database: DatabaseConfig, cli: &CliArgs) -> DatabaseConfig {
        if cli.dev
            && cli.config_db_path.is_none()
            && (database.config_path.is_empty()
                || database.config_path == "/var/lib/lanforge/config.redb")
        {
            database.config_path = "memory".to_string();
        }
        if cli.dev
            && cli.runtime_db_path.is_none()
            && (database.runtime_path.is_empty()
                || database.runtime_path == "/run/lanforge/runtime.redb")
        {
            database.runtime_path = "memory".to_string();
        }
        if let Some(ref path) = cli.config_db_path {
            database.config_path.clone_from(path);
        }
        if let Some(ref path) = cli.runtime_db_path {
            database.runtime_path.clone_from(path);
        }
        database
    }

    /// How long an address seen without activity (and a device's online status) stays fresh
    /// before the stale-expiry tick drops or demotes it. `[monitor] stale_timeout_secs` when
    /// discovery is built in; otherwise the file default, since lease expiry runs in every build.
    #[must_use]
    pub const fn stale_timeout(&self) -> Duration {
        #[cfg(feature = "discovery")]
        let secs = self.monitor_toml.stale_timeout_secs;
        #[cfg(not(feature = "discovery"))]
        let secs = MonitorFile::DEFAULT_STALE_TIMEOUT_SECS;
        Duration::from_secs(secs)
    }

    /// Returns the path to the dedicated API password hash file.
    #[must_use]
    pub fn get_password_hash_path(&self) -> PathBuf {
        Path::new(&self.config_path)
            .parent()
            .unwrap_or_else(|| Path::new("/etc/lanforge"))
            .join("api_password.hash")
    }

    /// What `[ra]` falls back on (see `ra::effective_ra`).
    #[cfg(feature = "ra")]
    #[must_use]
    pub fn ra_inputs(&self) -> RaInputs {
        RaInputs {
            lan_iface: self.system.iface.clone(),
            ula: self.resolve_ula_prefix(),
            search_domains: self.search_domains.clone(),
            #[cfg(feature = "dhcp")]
            dhcpv6_dns: self.dhcp.options.v6.dns_servers.clone(),
            #[cfg(not(feature = "dhcp"))]
            dhcpv6_dns: Vec::new(),
        }
    }

    /// The RA configuration the daemon runs: `[ra]` plus what it derives (in memory only).
    #[cfg(feature = "ra")]
    #[must_use]
    pub fn effective_ra(&self) -> RaServerConfig {
        effective_ra(self.ra.clone(), &self.ra_inputs())
    }

    /// Builds an `RaConfig` from the merged configuration.
    #[cfg(feature = "ra")]
    #[must_use]
    pub fn to_ra_config(&self) -> RaConfig {
        RaConfig::from(self.effective_ra())
    }

    /// Builds a `Dhcpv4Config` from the merged configuration.
    #[cfg(feature = "dhcp")]
    #[must_use]
    pub fn to_dhcpv4_config(&self) -> Dhcpv4Config {
        let mut cfg = self.dhcpv4_toml.clone();

        cfg.enabled = self.dhcpv4_enabled;
        if cfg.iface.is_empty() {
            cfg.iface.clone_from(&self.system.iface);
        }
        cfg.server_id = cfg.router;

        if cfg.domain_name.is_none() {
            cfg.domain_name = self.search_domains.first().cloned();
        }
        cfg.search_domains.clone_from(&self.search_domains);

        cfg
    }

    /// Builds a `Dhcpv6Config` from the merged configuration.
    #[cfg(feature = "dhcp")]
    #[must_use]
    pub fn to_dhcpv6_config(&self) -> Dhcpv6Config {
        let mut cfg = self.dhcpv6_toml.clone();

        cfg.enabled = self.dhcpv6_enabled;
        if cfg.iface.is_empty() {
            cfg.iface.clone_from(&self.system.iface);
        }

        #[cfg(feature = "ra")]
        let prefix_detected = self
            .effective_ra()
            .prefixes
            .iter()
            .find(|p| {
                p.source == PrefixSource::AutoGua
                    || p.source == PrefixSource::Static
                    || p.source == PrefixSource::Ula
            })
            .map(|p| (p.resolved_address(), p.prefix_len));
        #[cfg(not(feature = "ra"))]
        let prefix_detected: Option<(Option<Ipv6Addr>, u8)> = None;
        if let Some((addr, len)) = prefix_detected {
            cfg.ula_prefix = addr;
            cfg.ula_prefix_len = len;
        } else {
            cfg.ula_prefix_len = 64;
        }

        // No `dns_servers`: the server announces this router's own LAN address per reply (the
        // interface's live ULA/GUA), never a guessed address nor an upstream.
        // The base the live `[dhcp.v6]` options go over (`Dhcpv6Config::with_options`): the
        // site's search domains, used when the options name none (as DHCPv4 does).
        cfg.search_domains.clone_from(&self.search_domains);

        cfg
    }

    /// Runs `dns` as the DNS settings (`[dns]`); the boot hands them to the context.
    #[cfg(feature = "dns")]
    pub fn set_dns(&mut self, dns: DnsSettings) {
        self.dns = dns;
    }

    /// Builds a `DnsConfig` from the merged configuration.
    #[cfg(feature = "dns")]
    #[must_use]
    pub fn to_dns_config(&self) -> DnsConfig {
        let mut cfg = self.dns_toml.clone();

        cfg.enabled = self.dns_enabled;

        if cfg.tls_cert.is_none() {
            cfg.tls_cert.clone_from(&self.system.tls_cert);
        }
        if cfg.tls_key.is_none() {
            cfg.tls_key.clone_from(&self.system.tls_key);
        }

        // The site's domains: local names, PTR answers and the SOA zone (the first one).
        cfg.search_domains.clone_from(&self.search_domains);

        if cfg.ula_prefix.is_none() {
            #[cfg(feature = "ra")]
            {
                cfg.ula_prefix = self
                    .effective_ra()
                    .prefixes
                    .iter()
                    .find_map(RAPrefix::resolved_address);
            }
        }

        cfg
    }

    /// Builds an `ApiConfig` for the control service.
    #[cfg(feature = "uds")]
    #[must_use]
    pub fn to_api_config(&self) -> ApiConfig {
        self.api_toml.clone()
    }

    /// Builds an `HttpConfig` for the HTTP service.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn to_http_config(&self) -> HttpConfig {
        let mut cfg = self.http_toml.clone();

        cfg.auth_password_hash = fs::read_to_string(self.get_password_hash_path())
            .map(|s| s.trim().to_string())
            .ok()
            .or_else(|| self.http_toml.auth_password_hash.clone());

        if cfg.tls_cert.is_none() {
            cfg.tls_cert.clone_from(&self.system.tls_cert);
        }
        if cfg.tls_key.is_none() {
            cfg.tls_key.clone_from(&self.system.tls_key);
        }

        if cfg.boot_dir.is_none() {
            #[cfg(feature = "tftp")]
            {
                cfg.boot_dir = Some(self.tftp_toml.root_dir.to_string_lossy().to_string());
            }
            #[cfg(not(feature = "tftp"))]
            {
                cfg.boot_dir = Some("/var/lib/tftpboot".to_string());
            }
        }

        cfg
    }

    fn resolve_ula_prefix(&self) -> Option<Ipv6Prefix> {
        parse_ula_prefix(&self.system.target_prefix)
    }

    #[cfg(feature = "dhcp")]
    fn calculate_dhcpv4_range_size(&self) -> u32 {
        self.dhcpv4_toml
            .pools
            .iter()
            .map(|p| {
                let start = u32::from(p.range_start);
                let end = u32::from(p.range_end);
                end.saturating_sub(start).saturating_add(1)
            })
            .sum()
    }

    #[cfg(not(feature = "dhcp"))]
    const fn calculate_dhcpv4_range_size(&self) -> u32 {
        0
    }

    #[cfg(feature = "dhcp")]
    fn calculate_dhcpv6_pool_size(&self) -> Option<u64> {
        self.dhcpv6_toml
            .pools
            .iter()
            .map(|p| match (&p.range_start, &p.range_end) {
                (Some(Ipv6AddrOrSuffix::Full(s)), Some(Ipv6AddrOrSuffix::Full(e))) => {
                    let start = u128::from_be_bytes(s.octets());
                    let end = u128::from_be_bytes(e.octets());
                    u64::try_from(end.saturating_sub(start).saturating_add(1)).ok()
                }
                _ => None,
            })
            .sum()
    }

    #[cfg(not(feature = "dhcp"))]
    const fn calculate_dhcpv6_pool_size(&self) -> Option<u64> {
        None
    }

    #[cfg(feature = "dns")]
    fn resolve_dns_upstream(&self) -> Option<UpstreamTarget> {
        self.dns_toml.upstreams.first().map(|u| u.target.clone())
    }

    #[cfg(not(feature = "dns"))]
    const fn resolve_dns_upstream(&self) -> Option<UpstreamTarget> {
        None
    }

    #[cfg(feature = "dns")]
    fn resolve_dns_port(&self) -> u16 {
        self.dns_toml.listen.port()
    }

    #[cfg(not(feature = "dns"))]
    const fn resolve_dns_port(&self) -> u16 {
        53
    }

    #[cfg(feature = "tftp")]
    #[allow(clippy::unnecessary_wraps)]
    fn resolve_boot_dir(&self) -> Option<String> {
        Some(self.tftp_toml.root_dir.to_string_lossy().to_string())
    }

    #[cfg(not(feature = "tftp"))]
    const fn resolve_boot_dir(&self) -> Option<String> {
        None
    }

    /// Builds a `SystemStatus` snapshot from the current configuration.
    #[must_use]
    pub fn to_system_status(&self) -> SystemStatus {
        SystemStatus {
            db_path: sanitize_db_url(&self.database.config_path),
            log_db_path: sanitize_db_url(&self.database.runtime_path),
            lan_iface: self.system.iface.clone(),
            ula_prefix: self.resolve_ula_prefix(),
            #[cfg(feature = "ra")]
            ra_enabled: self.ra_enabled,
            #[cfg(not(feature = "ra"))]
            ra_enabled: false,
            #[cfg(feature = "dhcp")]
            dhcp_v4_enabled: self.dhcpv4_enabled,
            #[cfg(not(feature = "dhcp"))]
            dhcp_v4_enabled: false,
            dhcp_v4_range_size: self.calculate_dhcpv4_range_size(),
            #[cfg(feature = "dhcp")]
            dhcp_v6_enabled: self.dhcpv6_enabled,
            #[cfg(not(feature = "dhcp"))]
            dhcp_v6_enabled: false,
            dhcp_v6_pool_size: self.calculate_dhcpv6_pool_size(),
            #[cfg(feature = "dns")]
            dns_enabled: self.dns_enabled,
            #[cfg(not(feature = "dns"))]
            dns_enabled: false,
            dns_upstream: self.resolve_dns_upstream(),
            dns_port: self.resolve_dns_port(),
            boot_dir: self.resolve_boot_dir(),
            #[cfg(feature = "http")]
            http_enabled: self.http_toml.enabled,
            #[cfg(not(feature = "http"))]
            http_enabled: false,
            #[cfg(feature = "pppoe")]
            pppoe_enabled: self.pppoe_toml.enabled,
            #[cfg(not(feature = "pppoe"))]
            pppoe_enabled: false,
            #[cfg(feature = "nft")]
            firewall_enabled: self.firewall_enabled,
            #[cfg(not(feature = "nft"))]
            firewall_enabled: false,
            #[cfg(feature = "traffic")]
            traffic_enabled: self.traffic_enabled,
            #[cfg(not(feature = "traffic"))]
            traffic_enabled: false,
        }
    }
}

fn parse_ula_prefix(raw: &str) -> Option<Ipv6Prefix> {
    let raw = raw.split('/').next()?;
    let addr = raw.parse::<Ipv6Addr>().ok()?;
    is_ula(&addr).then(|| Ipv6Prefix::from_addr(addr))
}

/// `lanforge reload` resolves the search domains from the file (`ConfigFile::search_domains`),
/// the boot from its start-up config: both must agree, or a reload changes the DNSSL.
#[cfg(test)]
mod search_domain_tests {
    use super::*;

    #[test]
    fn reload_and_boot_resolve_the_same_search_domains() {
        for text in [
            "",
            "[system]\nsearch_domains = [\"home.arpa\", \"lan\"]\n",
            "[system]\nsearch_domains = [\"home.arpa\"]\n\n[dhcp.v4]\ndomain_name = \"corp\"\n",
            "[dhcp.v4]\ndomain_name = \"lan\"\n",
        ] {
            let file = ConfigFile::parse(text).unwrap();
            let boot = Config::resolve_search_domains(&toml::TomlConfig::from(&file));
            assert_eq!(file.search_domains(), boot, "{text:?}");
        }
    }
}

/// One search-domain rule for every consumer: a section's own list, else the site's
/// (`[system] search_domains`, else `lan`).
#[cfg(all(test, feature = "dns", feature = "dhcp"))]
#[allow(clippy::unwrap_used, reason = "test helper parses literal config")]
mod site_domain_tests {
    use super::*;
    use clap::Parser;

    fn config(text: &str) -> (Config, ConfigFile) {
        let file = ConfigFile::parse(text).unwrap();
        let toml = toml::TomlConfig::from(&file);
        let site = Config::resolve_search_domains(&toml);
        let cli = args::CliArgs::parse_from(["lanforge"]);
        (Config::apply_cli_overrides(toml, &cli, site), file)
    }

    /// PTR answers and the SOA zone are named after the site's first domain, the same names
    /// the local resolver answers (they were always `lan`).
    #[test]
    fn dns_names_its_zone_after_the_site_domain() {
        let (cfg, _) = config("[system]\nsearch_domains = [\"home.arpa\"]\n");
        assert_eq!(cfg.to_dns_config().search_domains, ["home.arpa", "lan"]);
        let (cfg, _) = config("");
        assert_eq!(cfg.to_dns_config().search_domains, ["lan"]);
    }

    /// `[dhcp.v6] search_domains` empty = the site's, at start and after a live options
    /// change; a list of its own wins. (A live change used to send none.)
    #[test]
    fn dhcpv6_search_domains_fall_back_to_the_site() {
        let (cfg, file) = config("[system]\nsearch_domains = [\"home.arpa\"]\n");
        let mut opts = file.dhcp_settings().0.options.v6;
        assert_eq!(opts.search_domains, Vec::<String>::new());
        let base = cfg.to_dhcpv6_config();
        assert_eq!(
            base.with_options(&opts).search_domains,
            ["home.arpa", "lan"]
        );

        opts.search_domains = vec!["v6.example".into()];
        assert_eq!(base.with_options(&opts).search_domains, ["v6.example"]);

        let (cfg, file) = config("[dhcp.v6]\nsearch_domains = [\"v6.example\"]\n");
        let started = cfg
            .to_dhcpv6_config()
            .with_options(&file.dhcp_settings().0.options.v6);
        assert_eq!(started.search_domains, ["v6.example"], "own list at start");
    }

    /// `[dhcp.v4] domain_name` is option 15 only: it does not add a site domain.
    #[test]
    fn dhcpv4_domain_name_is_not_a_site_domain() {
        let (cfg, _) = config("[dhcp.v4]\ndomain_name = \"corp\"\n");
        assert_eq!(cfg.search_domains, ["lan"]);
    }
}

#[cfg(all(test, feature = "ra"))]
mod config_default_tests {
    use super::*;
    use lanforge_api::config_file::add_default_ra_prefixes;

    #[test]
    fn default_ra_announces_valid_ula_and_dynamic_gua() {
        let ula = parse_ula_prefix("fd12:3456:789a::/64");
        let mut prefixes = Vec::new();
        add_default_ra_prefixes(&mut prefixes, ula);

        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].source, PrefixSource::Ula);
        assert_eq!(
            prefixes[0].resolved_address(),
            Some("fd12:3456:789a::".parse().unwrap())
        );
        assert_eq!(prefixes[1].source, PrefixSource::AutoGua);
    }

    #[test]
    fn default_ra_uses_auto_ula_and_dynamic_gua_without_explicit_ula() {
        for raw in ["", "2001:db8::1/64", "fe80::1/64", "not-an-ip"] {
            let mut prefixes = Vec::new();
            add_default_ra_prefixes(&mut prefixes, parse_ula_prefix(raw));
            assert_eq!(prefixes.len(), 2, "input {raw:?}");
            assert_eq!(prefixes[0].source, PrefixSource::AutoUla, "input {raw:?}");
            assert_eq!(prefixes[1].source, PrefixSource::AutoGua, "input {raw:?}");
        }
    }

    #[test]
    fn explicit_ra_prefixes_are_not_replaced_by_defaults() {
        let mut prefixes = vec![RAPrefix::gua_dynamic()];
        add_default_ra_prefixes(&mut prefixes, parse_ula_prefix("fd12::/64"));
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].source, PrefixSource::AutoGua);
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            system: SystemCfg::default(),
            database: DatabaseConfig::default(),
            #[cfg(feature = "ra")]
            ra_enabled: true,
            #[cfg(feature = "ra")]
            ra: RaServerConfig::default(),
            #[cfg(feature = "dhcp")]
            dhcpv4_enabled: true,
            #[cfg(feature = "dhcp")]
            dhcpv4_toml: Dhcpv4Config::default(),
            #[cfg(feature = "dhcp")]
            dhcpv6_enabled: true,
            #[cfg(feature = "dhcp")]
            dhcpv6_toml: Dhcpv6Config::default(),
            #[cfg(feature = "dhcp")]
            dhcp: DhcpSettings::default(),
            #[cfg(feature = "dns")]
            dns_enabled: true,
            #[cfg(feature = "dns")]
            dns_toml: DnsConfig::default(),
            #[cfg(feature = "dns")]
            dns: DnsSettings::default(),
            #[cfg(feature = "dns")]
            adblock: AdblockSettings::default(),
            #[cfg(feature = "dns")]
            adblock_rules: String::new(),
            search_domains: vec!["lan".to_string()],
            #[cfg(feature = "discovery")]
            monitor_toml: MonitorConfig::default(),
            #[cfg(feature = "discovery")]
            mdns_toml: MdnsConfig::default(),
            #[cfg(feature = "uds")]
            api_toml: ApiConfig::default(),
            #[cfg(feature = "http")]
            http_toml: HttpConfig::default(),
            #[cfg(feature = "tftp")]
            tftp_toml: TftpConfig::default(),
            #[cfg(feature = "pppoe")]
            pppoe_enabled: false,
            #[cfg(feature = "pppoe")]
            pppoe_toml: PppoeTomlConfig::default(),
            #[cfg(feature = "nft")]
            firewall_enabled: true,
            #[cfg(feature = "nft")]
            firewall_toml: lanforge_nft::FirewallConfig::default(),
            #[cfg(feature = "traffic")]
            traffic_enabled: true,
            #[cfg(feature = "traffic")]
            traffic_toml: lanforge_traffic::TrafficConfig::default(),
            config_path: "/etc/lanforge/lanforge.toml".to_string(),
            config_writable: true,
            config_issues: Vec::new(),
            static_hosts: None,
            dhcp_set_aside: false,
        }
    }
}

pub use lanforge_db::sanitize_db_url;
