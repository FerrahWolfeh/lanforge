use anyhow::Result;
use bytesize::ByteSize;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_core::context::{ConfigPatch, LanforgeContext};
use lanforge_db::{LanforgeDb, LogDb, LogStore, PrefixStore, UserStore};
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v4::sanity::derive_dhcp_defaults_from_v4;
use lanforge_discovery::refresh_interface;
use lanforge_types::DnsListenConfig;
#[cfg(feature = "dns")]
use lanforge_types::build::BuildInfo;
use lanforge_types::config::SiteDomains;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
#[cfg(feature = "dhcp")]
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::network::ra::PreviousLanPrefixes;
use lanforge_types::network::{
    IpClassification, Ipv6AddrOrSuffix, Ipv6Prefix, classify_ipv6, is_ula,
};
use lanforge_types::update::InterfaceState;
use netlink_sys::SocketAddr;
use pnet::datalink::interfaces;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use rtnetlink::new_connection;
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_route::RouteNetlinkMessage;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::config::Config;

macro_rules! feat_flag {
    ($feat:ident, $val:expr) => {
        feat_flag!($feat, $val, false)
    };
    (ra, $val:expr, $default:expr) => {{
        #[cfg(feature = "ra")]
        {
            $val
        }
        #[cfg(not(feature = "ra"))]
        {
            $default
        }
    }};
    (dhcp, $val:expr, $default:expr) => {{
        #[cfg(feature = "dhcp")]
        {
            $val
        }
        #[cfg(not(feature = "dhcp"))]
        {
            $default
        }
    }};
    (dns, $val:expr, $default:expr) => {{
        #[cfg(feature = "dns")]
        {
            $val
        }
        #[cfg(not(feature = "dns"))]
        {
            $default
        }
    }};
    (pppoe, $val:expr, $default:expr) => {{
        #[cfg(feature = "pppoe")]
        {
            $val
        }
        #[cfg(not(feature = "pppoe"))]
        {
            $default
        }
    }};
    (http, $val:expr, $default:expr) => {{
        #[cfg(feature = "http")]
        {
            $val
        }
        #[cfg(not(feature = "http"))]
        {
            $default
        }
    }};
    (tftp, $val:expr, $default:expr) => {{
        #[cfg(feature = "tftp")]
        {
            $val
        }
        #[cfg(not(feature = "tftp"))]
        {
            $default
        }
    }};
    (nft, $val:expr, $default:expr) => {{
        #[cfg(feature = "nft")]
        {
            $val
        }
        #[cfg(not(feature = "nft"))]
        {
            $default
        }
    }};
    (traffic, $val:expr, $default:expr) => {{
        #[cfg(feature = "traffic")]
        {
            $val
        }
        #[cfg(not(feature = "traffic"))]
        {
            $default
        }
    }};
}

const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_NEIGH: u32 = 3;
const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV6_IFADDR: u32 = 9;

pub type NetlinkRawMessage = (NetlinkMessage<RouteNetlinkMessage>, SocketAddr);
type NetlinkMessages = broadcast::Sender<NetlinkRawMessage>;
type NetlinkRawReceiver = UnboundedReceiver<NetlinkRawMessage>;

const NETLINK_BROADCAST_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct BootstrapResult {
    pub cfg: Arc<Config>,
    pub rt_handle: rtnetlink::Handle,
    pub messages: NetlinkMessages,
    pub target_ifindex: u32,
    pub db: Arc<LanforgeDb>,
    pub log_db: Arc<LogDb>,
}

/// Orchestrates the initial state of the Lanforge daemon.
pub struct Bootstrapper;

impl Bootstrapper {
    /// Executes the full bootstrap sequence.
    pub async fn run() -> Result<(BootstrapResult, LanforgeContext)> {
        // --- PHASE 1: Initialization ---
        let mut cfg = Config::load();

        Self::check_privileges(&cfg)?;

        info!(
            "Starting Lanforge {} (RA: {}, DHCPv4: {}, DHCPv6: {}, DNS: {})",
            env!("LANFORGE_BUILD"),
            feat_flag!(ra, cfg.ra_enabled),
            feat_flag!(dhcp, cfg.dhcpv4_enabled),
            feat_flag!(dhcp, cfg.dhcpv6_enabled),
            feat_flag!(dns, cfg.dns_enabled)
        );

        let bus = Arc::new(EventBus::new());
        let host_ifaces = interfaces();
        let target_ifindex = Self::find_target_interface(&mut cfg, &host_ifaces)?;
        let (initial_table, db, log_db) = Self::init_device_table(&mut cfg, &host_ifaces)?;
        // Logged once, after the start-up configs are derived.
        cfg.config_issues =
            lanforge_api::config_file::log_issues(std::mem::take(&mut cfg.config_issues));
        let db = Arc::new(db);
        let log_db = Arc::new(log_db);
        let cfg = Arc::new(cfg);

        let ctx = LanforgeContext::new(bus.clone(), initial_table, Some(target_ifindex));
        if let Some(build) = BuildInfo::parse(env!("LANFORGE_BUILD")) {
            ctx.set_build(build);
        }
        Self::populate_context(&ctx, &cfg, &db);
        // `[hosts]` is the static hosts' only source: the table follows it.
        if let Some(hosts) = cfg.static_hosts.as_ref() {
            let issues = lanforge_api::config_file::log_issues(ctx.apply_static_hosts(hosts));
            if !issues.is_empty() {
                let mut all = ctx.config_issues();
                all.extend(issues);
                ctx.set_config_issues(all);
            }
        }

        #[cfg(feature = "dns")]
        {
            let dns_lifetime = log_db.load_dns_lifetime_stats().unwrap_or_default();
            ctx.provide_shared(Arc::new(dns_lifetime));
        }

        #[cfg(feature = "traffic")]
        {
            let traffic_history = log_db.load_traffic_history().unwrap_or_default();
            lanforge_traffic::restore_traffic_history(traffic_history);
        }

        // --- PHASE 2: Netlink Setup ---
        let (handle, messages) = Self::start_netlink_dispatcher()?;

        // --- PHASE 3: Initial Scan ---
        // Crucial: updates ctx with current GUA/ULA/Link-Local before services start.
        let if_state = Self::perform_initial_scan(&handle, &messages, target_ifindex, &ctx).await?;
        Self::log_welcome_banner(&cfg, &if_state);

        // The live LAN prefix comes from the scan above (the OS owns the interface, D-12). The
        // stored one is only history and must never override the scanned state. Both are handed
        // to RA, which deprecates whichever is gone from the LAN by the time it starts: the
        // delegated prefix can change while we are down, or be withdrawn right after this scan.
        let scanned = if_state
            .gua
            .map(lanforge_types::network::Ipv6Prefix::from_addr);
        let stored = db.load_last_gua_prefix().ok().flatten();
        if let Some(stored) = stored
            && scanned != Some(stored)
        {
            info!(previous = %stored, current = ?scanned, "LAN GUA prefix changed since last run; RA will deprecate the previous one");
        }
        let mut previous: Vec<_> = stored.into_iter().collect();
        previous.extend(scanned.filter(|p| Some(*p) != stored));
        if !previous.is_empty() {
            ctx.provide_shared(Arc::new(PreviousLanPrefixes(previous)));
        }

        // --- PHASE 4/5: Handover to Daemon ---
        Ok((
            BootstrapResult {
                cfg,
                rt_handle: handle,
                messages,
                target_ifindex,
                db,
                log_db,
            },
            ctx,
        ))
    }

    fn build_compiled_caps() -> smallvec::SmallVec<[lanforge_types::system::Cap; 32]> {
        let mut compiled = smallvec::SmallVec::new();
        #[cfg(feature = "dns")]
        compiled.push(lanforge_types::system::Cap::Dns);
        #[cfg(feature = "dns")]
        compiled.push(lanforge_types::system::Cap::UpstreamUdpTcp);
        #[cfg(feature = "dns-dot")]
        compiled.push(lanforge_types::system::Cap::UpstreamDoT);
        #[cfg(feature = "dns-doq")]
        compiled.push(lanforge_types::system::Cap::UpstreamDoQ);
        #[cfg(feature = "dns-doh")]
        compiled.push(lanforge_types::system::Cap::UpstreamDoH);
        #[cfg(feature = "doh-server")]
        compiled.push(lanforge_types::system::Cap::DohDownstream);
        #[cfg(feature = "dhcp")]
        {
            compiled.push(lanforge_types::system::Cap::DhcpV4);
            compiled.push(lanforge_types::system::Cap::DhcpV6);
        }
        #[cfg(feature = "ra")]
        compiled.push(lanforge_types::system::Cap::Ra);
        #[cfg(feature = "discovery")]
        {
            compiled.push(lanforge_types::system::Cap::NdpDiscovery);
            compiled.push(lanforge_types::system::Cap::MdnsProbe);
        }
        #[cfg(feature = "uds")]
        compiled.push(lanforge_types::system::Cap::Uds);
        #[cfg(feature = "http")]
        compiled.push(lanforge_types::system::Cap::Http);
        compiled.push(lanforge_types::system::Cap::Zstd);
        compiled.push(lanforge_types::system::Cap::Storage);
        #[cfg(feature = "pppoe")]
        compiled.push(lanforge_types::system::Cap::Pppoe);
        #[cfg(feature = "ebpf")]
        compiled.push(lanforge_types::system::Cap::Ebpf);
        #[cfg(feature = "tftp")]
        compiled.push(lanforge_types::system::Cap::Tftp);
        #[cfg(feature = "nft")]
        compiled.push(lanforge_types::system::Cap::Firewall);
        #[cfg(feature = "traffic")]
        compiled.push(lanforge_types::system::Cap::Traffic);
        #[cfg(feature = "adblock")]
        compiled.push(lanforge_types::system::Cap::Adblock);
        #[cfg(feature = "webui")]
        compiled.push(lanforge_types::system::Cap::Webui);
        compiled
    }

    fn populate_context(ctx: &LanforgeContext, cfg: &Config, db: &LanforgeDb) {
        if !cfg.system.iface.is_empty() {
            ctx.set_target_interface_name(cfg.system.iface.clone());
        }
        if Self::is_recovery(cfg, db) {
            ctx.set_recovery_mode(true);
        }
        ctx.set_config_path(&cfg.config_path);
        ctx.set_config_writable(cfg.config_writable);
        ctx.set_config_issues(cfg.config_issues.clone());

        let mut patch = ConfigPatch::new();

        #[cfg(feature = "dhcp")]
        {
            patch = patch
                .with_dhcp_v4_pools(cfg.dhcp.v4_pools.clone())
                .with_dhcp_v6_pools(cfg.dhcp.v6_pools.clone())
                .with_dhcp_options(cfg.dhcp.options.clone());
        }
        #[cfg(feature = "ra")]
        {
            patch = patch.with_ra_server(cfg.effective_ra());
        }

        #[cfg(feature = "dns")]
        {
            patch = patch
                .with_dns_upstreams(cfg.dns.upstreams.iter().map(|u| u.target.clone()).collect())
                .with_dns_upstream_mode(cfg.dns.upstream_mode)
                .with_dns_rewrites(cfg.dns.rewrites.clone())
                .with_dns_reverse(cfg.dns.reverse.clone());
            patch = patch
                .with_dns_adblock(cfg.adblock.config.clone())
                .with_dns_adblock_urls(cfg.adblock.global_sources().cloned().collect())
                .with_dns_adblock_rules(cfg.adblock_rules.clone());
            // The DNS service binds from the live listeners; the file is their source.
            let dns = cfg.to_dns_config();
            patch = patch.with_dns_listen(DnsListenConfig {
                enabled: dns.enabled,
                listen: dns.listen,
                dot_listen: dns.dot_listen,
                dot_enabled: dns.dot_listen.is_some(),
                tls_cert: dns.tls_cert,
                tls_key: dns.tls_key,
                doq_listen: dns.doq_listen,
                doq_enabled: dns.doq_listen.is_some(),
            });
        }

        #[cfg(feature = "pppoe")]
        {
            patch = patch.with_pppoe(cfg.pppoe_toml.clone());
        }

        #[cfg(feature = "nft")]
        {
            patch = patch.with_firewall(cfg.firewall_toml.clone());
        }

        #[cfg(feature = "traffic")]
        {
            patch = patch.with_traffic(cfg.traffic_toml.clone());
        }

        // The site's domains are live: a reload of `[system] search_domains` reaches DNS.
        patch = patch.with_site_domains(SiteDomains(cfg.search_domains.clone()));

        ctx.hydrate_config(patch);

        ctx.set_status(cfg.to_system_status());
        ctx.set_compiled_caps(Self::build_compiled_caps());
    }

    fn start_netlink_dispatcher() -> Result<(rtnetlink::Handle, NetlinkMessages)> {
        let (handle, messages_rx) = Self::init_netlink()?;
        let (tx, _rx) = broadcast::channel(NETLINK_BROADCAST_CAPACITY);
        let messages = tx.clone();

        let dispatcher_tx = tx;
        tokio::spawn(async move {
            let mut rx = messages_rx;
            while let Some(msg) = rx.next().await {
                if dispatcher_tx.send(msg).is_err() {
                    debug!("Netlink dispatcher: zero active subscribers");
                }
            }
        });

        Ok((handle, messages))
    }

    fn init_device_table(
        cfg: &mut Config,
        host_ifaces: &[pnet::datalink::NetworkInterface],
    ) -> Result<(State, LanforgeDb, LogDb)> {
        let (db, log_db) = Self::open_databases(cfg)?;
        let user_count = db.count_users().unwrap_or(0);
        let is_provisioned = Self::check_provisioning_mode(cfg, &db);

        if is_provisioned {
            let config_path = PathBuf::from(&cfg.config_path);
            crate::config::boot_file::ensure_boot_config(&config_path, cfg.config_writable)?;
            Self::prepare_provisioned_configs(&db, cfg);
        }

        let mut table = db.load_table().unwrap_or_else(|e| {
            warn!("Falha ao carregar DB ({e}), iniciando do zero");
            State::new()
        });

        match log_db.load_runtime_devices() {
            Ok(runtime_devices) => {
                for mut runtime in runtime_devices {
                    if let Some(persisted) = table.devices.get(&runtime.mac) {
                        let persistent = persisted.as_ref();
                        runtime.identity = persistent.identity.clone();
                        if matches!(persistent.v4, lanforge_types::device::IPv4State::Dynamic(_)) {
                            runtime.v4 = persistent.v4.clone();
                        }
                        runtime.v6.retain(|state| {
                            !matches!(state, lanforge_types::device::IPv6State::Dynamic(_))
                        });
                        runtime.v6.extend(
                            persistent
                                .v6
                                .iter()
                                .filter(|state| {
                                    matches!(state, lanforge_types::device::IPv6State::Dynamic(_))
                                })
                                .cloned(),
                        );
                        runtime.v6_prefixes.clone_from(&persistent.v6_prefixes);
                    }
                    runtime.status = lanforge_types::device::DeviceStatus::Offline;
                    table.insert_device(runtime.mac, runtime);
                }
            }
            Err(error) => warn!(%error, "Could not hydrate volatile device observations"),
        }

        // 2c. Check/reconcile DHCPv4 topology sanity against physical interface and host identity
        #[cfg(feature = "dhcp")]
        if is_provisioned {
            Self::reconcile_dhcp_v4_topology_sanity(cfg, &table, host_ifaces);
        }

        #[cfg(feature = "dns")]
        {
            table.reverse_resolvers.clone_from(&cfg.dns.reverse);
        }

        Self::log_db_status(&db, &log_db, &table, cfg, user_count);
        Self::inject_self_device(&mut table, cfg, host_ifaces);

        // Trigger early collision validation and logging
        let _ = table.get_static_registry();

        Ok((table, db, log_db))
    }

    fn open_databases(cfg: &Config) -> Result<(LanforgeDb, LogDb)> {
        let db_target = if cfg.database.is_in_memory() {
            "in-memory".to_string()
        } else {
            lanforge_db::sanitize_db_url(&cfg.database.config_path)
        };
        info!("Loading database from {db_target}");

        let db = match LanforgeDb::open(&cfg.database) {
            Ok(db) => db,
            Err(e) => {
                warn!(
                    "Database: Persistent database unavailable at '{}' ({e})",
                    lanforge_db::sanitize_db_url(&cfg.database.config_path)
                );
                warn!(
                    "Database: Entering RECOVERY MODE — running in-memory without disk persistence"
                );
                LanforgeDb::open_in_memory()?
            }
        };

        let log_db = match LogDb::open(&cfg.database.runtime_path) {
            Ok(ldb) => ldb,
            Err(e) => {
                warn!(
                    "Database: Log storage unavailable at '{}' ({e}), running in in-memory fallback mode",
                    cfg.database.runtime_path
                );
                LogDb::open_in_memory()
            }
        };

        Ok((db, log_db))
    }

    /// Recovery mode: the persistent DB did not open and an in-memory one stands in for it.
    /// Not to be confused with `storage = "in_memory"` in the config, an intentional
    /// memory-only run that provisions like any first run.
    fn is_recovery(cfg: &Config, db: &LanforgeDb) -> bool {
        db.is_in_memory() && !cfg.database.is_in_memory()
    }

    /// Decides first-run (provisioning) mode, which makes DHCP/RA/PPPoE dormant and opens
    /// `/setup`. Fails toward "provisioned": an unreadable flag or user table, or recovery
    /// mode (an in-memory stand-in for a persistent DB that did not open), is not a first
    /// run — treating it as one takes the LAN offline and lets anyone on it claim the admin.
    fn check_provisioning_mode(cfg: &mut Config, db: &LanforgeDb) -> bool {
        let recovery = Self::is_recovery(cfg, db);
        if recovery {
            error!(
                "Bootstrap: RECOVERY MODE — setup stays locked and services run from '{}'; \
                 fix the database and restart",
                cfg.config_path
            );
            // The stand-in DB is what `/setup` and setup-status consult: lock them.
            if let Err(e) = db.set_provisioned(true) {
                warn!("Bootstrap: Failed to mark the in-memory database provisioned: {e}");
            }
        }

        let is_provisioned = recovery
            || db.is_provisioned().unwrap_or(true)
            || db.count_users().map_or(true, |n| n > 0)
            || cfg.system.auto_provision;

        if cfg.system.auto_provision && !db.is_provisioned().unwrap_or(false) {
            info!("Bootstrap: Auto-provisioning enabled via configuration/CLI");
            if let Err(e) = db.set_provisioned(true) {
                warn!("Bootstrap: Failed to persist provisioned state in database: {e}");
            }
        }

        #[allow(clippy::if_not_else)]
        if !is_provisioned {
            warn!("┌─────────────────────────────────────────────────────────────┐");
            warn!("│  ⚠️  Lanforge PROVISIONING MODE: First-run setup required.  │");
            warn!("│  Networking services (DHCP, RA, PPPoE) are DORMANT.        │");
            warn!("│  Open the Web UI to complete initial onboarding setup.      │");
            warn!("└─────────────────────────────────────────────────────────────┘");

            #[cfg(feature = "ra")]
            {
                cfg.ra_enabled = false;
            }
            #[cfg(feature = "dhcp")]
            {
                cfg.dhcpv4_enabled = false;
                cfg.dhcpv6_enabled = false;
            }
            #[cfg(feature = "pppoe")]
            {
                cfg.pppoe_enabled = false;
            }
        }

        is_provisioned
    }

    /// Warns about configuration an older binary left in the database (nothing reads it any
    /// more: the config files are the only source) and derives the start-up configs that
    /// depend on several sections.
    fn prepare_provisioned_configs(db: &LanforgeDb, cfg: &mut Config) {
        match db.legacy_config_keys() {
            Ok(keys) if !keys.is_empty() => warn!(
                ?keys,
                "Config: the database still holds settings of an older lanforge; they are \
                 ignored (configuration lives in '{}'). Upgrade through a release that moves \
                 them, or set them in the file",
                cfg.config_path
            ),
            Ok(_) => {}
            Err(e) => warn!("Config: could not check the database for old settings: {e}"),
        }

        #[cfg(feature = "dhcp")]
        Self::sync_dhcp_service_configs(cfg);
    }

    /// Carries `cfg.dhcp` (what the daemon runs) into the services' start-up configs.
    #[cfg(feature = "dhcp")]
    fn sync_dhcp_service_configs(cfg: &mut Config) {
        cfg.dhcpv4_enabled = cfg.dhcp.options.v4.enabled;
        cfg.dhcpv6_enabled = cfg.dhcp.options.v6.enabled;
        cfg.dhcpv4_toml.pools.clone_from(&cfg.dhcp.v4_pools);
        cfg.dhcpv6_toml.pools.clone_from(&cfg.dhcp.v6_pools);
        cfg.dhcpv4_toml.range_start = None;
        cfg.dhcpv4_toml.range_end = None;
        #[cfg(feature = "tftp")]
        crate::config::toml::apply_tftp_options(&mut cfg.tftp_toml, &cfg.dhcp.options.tftp);
    }

    /// Writes an automatic change of `cfg.dhcp` (startup sanity) to `[dhcp]`, as it used to be
    /// written to the database; a read-only file keeps it in memory for this run.
    #[cfg(feature = "dhcp")]
    fn persist_dhcp_heal(cfg: &Config) {
        use lanforge_api::config_file::{ConfigFile, SectionSet, persist_sections};

        let path = std::path::Path::new(&cfg.config_path);
        if cfg.dhcp_set_aside {
            warn!(
                "DHCPv4 Startup Sanity: [dhcp] in '{}' is unreadable (see the config issues); \
                 the correction applies to this run only, the section is left as written",
                path.display()
            );
            return;
        }
        if !cfg.config_writable || !path.exists() {
            warn!(
                "DHCPv4 Startup Sanity: '{}' is read-only; the correction applies to this run only",
                path.display()
            );
            return;
        }
        let mut file = ConfigFile::default();
        file.set_dhcp_settings(&cfg.dhcp);
        match persist_sections(path, &file, SectionSet::DHCP) {
            Ok(()) => info!(
                "DHCPv4 Startup Sanity: correction saved to [dhcp] in '{}'",
                path.display()
            ),
            Err(e) => warn!(
                "DHCPv4 Startup Sanity: could not save the correction to '{}': {e}",
                path.display()
            ),
        }
    }

    fn log_db_status(
        db: &LanforgeDb,
        log_db: &LogDb,
        table: &State,
        cfg: &Config,
        user_count: i64,
    ) {
        let schema = db.schema_version().unwrap_or(1);
        let size_str = db.path().map_or_else(
            || {
                if cfg.database.is_in_memory() {
                    "in-memory".to_string()
                } else {
                    "in-memory (recovery mode)".to_string()
                }
            },
            |path| {
                std::fs::metadata(path).map_or_else(
                    |_| "unknown".to_string(),
                    |m| ByteSize::b(m.len()).to_string(),
                )
            },
        );
        let device_count = table.devices().count();
        let log_db_desc = if log_db.is_in_memory() {
            "in-memory".to_string()
        } else {
            lanforge_db::sanitize_db_url(&cfg.database.runtime_path)
        };

        info!(
            "Database loaded (schema: {schema}, size: {size_str}, devices: {device_count}, users: {user_count}, runtime: {log_db_desc})"
        );
    }

    /// Checks whether Lanforge is running with sufficient privileges (EUID 0 / root).
    fn check_privileges(cfg: &Config) -> Result<()> {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            if cfg.system.allow_unprivileged {
                warn!(
                    "⚠️  Lanforge is running without root privileges (EUID != 0). \
                     Kernel network operations (Netlink route sockets, nftables firewall, raw packet sockets for DHCP/RA/PPPoE, and binding ports 53/67) may fail unless capabilities are granted."
                );
            } else {
                anyhow::bail!(
                    "Lanforge requires root privileges (sudo).\n\
                     Kernel network orchestration (Netlink route sockets, nftables firewall, raw packet sockets for DHCP/RA/PPPoE, and binding ports 53/67) requires root (EUID 0).\n\
                     Please run with: sudo lanforge [options] (or pass --allow-unprivileged / --dev if testing in an unprivileged or capability-granted environment)."
                );
            }
        }
        Ok(())
    }

    /// Prints the user-friendly startup banner when all services are fully initialized and ready.
    pub fn print_startup_banner(cfg: &Config, target_ifindex: u32, db: &LanforgeDb) {
        let host_ip = {
            let interfaces = pnet::datalink::interfaces();
            interfaces
                .iter()
                .find(|i| i.index == target_ifindex)
                .and_then(|i| i.ips.iter().find(|ip| ip.is_ipv4()))
                .map_or_else(|| "localhost".to_string(), |ip| ip.ip().to_string())
        };
        let http_port = feat_flag!(http, cfg.http_toml.listen.port(), 8088);

        let console_url = format!("http://{host_ip}:{http_port}");
        let is_first_run = !(db.is_provisioned().unwrap_or(false)
            || db.count_users().unwrap_or(0) > 0
            || cfg.system.auto_provision);
        let db_desc = if db.is_in_memory() {
            if cfg.database.is_in_memory() {
                "in-memory (non-persistent)".to_string()
            } else {
                "RECOVERY MODE (in-memory)".to_string()
            }
        } else {
            let schema = db.schema_version().unwrap_or(1);
            let size = db
                .path()
                .and_then(|p| std::fs::metadata(p).ok())
                .map_or_else(
                    || "unknown".to_string(),
                    |m| ByteSize::b(m.len()).to_string(),
                );
            format!("redb (schema v{schema}, {size})")
        };

        info!("┌─────────────────────────────────────────────────────────────┐");
        info!("│  ⚡ Lanforge — Router & Network Orchestrator                 │");
        info!("├─────────────────────────────────────────────────────────────┤");
        info!("│  LAN Interface:  {:<42} │", cfg.system.iface);
        info!("│  Database:       {:<42} │", db_desc);
        info!("│  Web Console:    {:<42} │", console_url);
        if is_first_run {
            let setup_url = format!("{console_url}/setup");
            info!("│  First-Run:      {:<42} │", setup_url);
        }
        info!("└─────────────────────────────────────────────────────────────┘");
    }

    /// Injects the host machine as a system device in the state table.
    fn inject_self_device(
        table: &mut State,
        cfg: &Config,
        interfaces: &[pnet::datalink::NetworkInterface],
    ) {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map_or_else(|_| "lanforge".to_string(), |s| s.trim().to_string());

        if let Some(iface) = interfaces.iter().find(|i| i.name == cfg.system.iface)
            && let Some(mac) = iface.mac
        {
            let mac = MacAddr(mac.octets());
            info!(
                hostname = %hostname,
                mac = %mac,
                "Self-Resolution: Registered system host device"
            );

            // Use current V4 if available to seed the device
            let v4_static = iface.ips.iter().find_map(|ip| {
                if let IpNetwork::V4(v4) = ip {
                    Some(v4.ip())
                } else {
                    None
                }
            });

            // Use ULA if available; otherwise GUA; never Link-Local for the system host
            let mut ula_v6 = None;
            let mut gua_v6 = None;
            for ip in &iface.ips {
                if let IpNetwork::V6(v6) = ip {
                    let addr = v6.ip();
                    if is_ula(&addr) {
                        ula_v6 = Some(addr);
                    } else if matches!(classify_ipv6(&addr), IpClassification::Gua) {
                        gua_v6 = Some(addr);
                    }
                }
            }
            let v6_static = ula_v6.or(gua_v6).map(Ipv6AddrOrSuffix::Full);

            table.add_static_device(
                mac,
                hostname,
                None, // DUID not required for the host itself here
                v4_static,
                v6_static,
                None,
                Origin::System,
            );
        }
    }

    #[cfg(feature = "dhcp")]
    fn reconcile_dhcp_v4_topology_sanity(
        cfg: &mut Config,
        table: &State,
        all_ifaces: &[pnet::datalink::NetworkInterface],
    ) {
        let target_iface = all_ifaces
            .iter()
            .find(|i| !cfg.system.iface.is_empty() && i.name == cfg.system.iface)
            .or_else(|| all_ifaces.iter().find(|i| !i.is_loopback()));

        let Some(iface) = target_iface else {
            return;
        };

        let iface_v4 = iface.ips.iter().find_map(|ip| match ip {
            IpNetwork::V4(v4) => Some(*v4),
            IpNetwork::V6(_) => None,
        });

        let Some(v4) = iface_v4 else {
            return;
        };

        let iface_ip = v4.ip();
        let iface_mask = v4.mask();

        // Check if the previous host device in state was registered as the gateway
        let prev_host_ip = iface
            .mac
            .and_then(|m| {
                let mac = MacAddr(m.octets());
                table.devices.get(&mac).and_then(|d| d.v4.ip())
            })
            .or_else(|| {
                table
                    .devices
                    .values()
                    .find(|d| d.origin == Origin::System)
                    .and_then(|d| d.v4.ip())
            });

        let healed_options =
            Self::audit_and_heal_dhcp_options(cfg, v4, iface_ip, iface_mask, prev_host_ip);
        let healed_pools = Self::audit_and_heal_dhcp_pools(cfg, v4);
        if healed_options || healed_pools {
            Self::sync_dhcp_service_configs(cfg);
            Self::persist_dhcp_heal(cfg);
        }
    }

    #[cfg(feature = "dhcp")]
    /// Corrects the advertised gateway and mask in `cfg.dhcp` to the LAN interface; true when
    /// something changed.
    fn audit_and_heal_dhcp_options(
        cfg: &mut Config,
        v4: Ipv4Network,
        iface_ip: std::net::Ipv4Addr,
        iface_mask: std::net::Ipv4Addr,
        prev_host_ip: Option<std::net::Ipv4Addr>,
    ) -> bool {
        let opts = &mut cfg.dhcp.options;
        let mut opts_modified = false;

        match opts.v4.router {
            None => {
                info!(
                    "DHCPv4 Startup Sanity: Gateway unconfigured / auto — advertising interface IP {iface_ip}."
                );
                opts.v4.router = Some(iface_ip);
                opts_modified = true;
            }
            Some(r) => {
                let was_self = prev_host_ip.is_some_and(|prev| prev == r);

                if was_self && r != iface_ip {
                    info!(
                        "DHCPv4 Startup Sanity: Host interface IP changed from {r} to {iface_ip}. Auto-migrating gateway to {iface_ip}."
                    );
                    opts.v4.router = Some(iface_ip);
                    opts_modified = true;
                } else if !v4.contains(r) {
                    warn!(
                        "DHCPv4 Startup Sanity: Configured gateway '{r}' is outside interface '{}' subnet ({}/{}). Auto-healing to {iface_ip}.",
                        cfg.system.iface,
                        v4.network(),
                        v4.prefix()
                    );
                    opts.v4.router = Some(iface_ip);
                    opts_modified = true;
                }
            }
        }

        if opts.v4.subnet_mask != Some(iface_mask) {
            warn!(
                "DHCPv4 Startup Sanity: Configured subnet mask {:?} does not match interface '{}' mask {iface_mask}. Auto-healing.",
                opts.v4.subnet_mask, cfg.system.iface
            );
            opts.v4.subnet_mask = Some(iface_mask);
            opts_modified = true;
        }

        opts_modified
    }

    /// Replaces the `DHCPv4` pools in `cfg.dhcp` with one derived from the LAN interface when
    /// none of them is in its subnet; true when it did.
    #[cfg(feature = "dhcp")]
    fn audit_and_heal_dhcp_pools(cfg: &mut Config, v4: Ipv4Network) -> bool {
        let pools = &cfg.dhcp.v4_pools;
        if pools.is_empty()
            || pools
                .iter()
                .any(|p| v4.contains(p.range_start) && v4.contains(p.range_end))
        {
            return false;
        }
        warn!(
            "DHCPv4 Startup Sanity: Configured DHCPv4 pools are outside interface '{}' subnet ({}). Auto-healing dynamic pools.",
            cfg.system.iface, v4
        );
        let derived = derive_dhcp_defaults_from_v4(&v4);
        cfg.dhcp.v4_pools = vec![Dhcpv4Pool {
            name: Some("Auto-Healed LAN Scope".to_string()),
            range_start: derived.range_start,
            range_end: derived.range_end,
            lease_time: Some(cfg.dhcp.options.v4.lease_time),
            router: Some(derived.router),
            subnet_mask: Some(derived.subnet_mask),
            dns_servers: vec![derived.router],
            ..Default::default()
        }];
        true
    }

    fn find_target_interface(
        cfg: &mut Config,
        interfaces: &[pnet::datalink::NetworkInterface],
    ) -> Result<u32> {
        if !cfg.system.iface.is_empty()
            && let Some(iface) = interfaces
                .iter()
                .find(|iface| iface.name == cfg.system.iface)
        {
            return Ok(iface.index);
        }

        if let Some(fallback) = interfaces.iter().find(|i| !i.is_loopback()) {
            if !cfg.system.iface.is_empty() {
                warn!(
                    target = %cfg.system.iface,
                    fallback = %fallback.name,
                    "Target interface not found, falling back to active interface"
                );
            }
            cfg.system.iface.clone_from(&fallback.name);
            return Ok(fallback.index);
        }

        anyhow::bail!("No usable network interface found on system")
    }

    fn init_netlink() -> Result<(rtnetlink::Handle, NetlinkRawReceiver)> {
        use netlink_sys::AsyncSocket;

        let (mut connection, handle, messages) = new_connection()?;
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTNLGRP_NEIGH)?;
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTNLGRP_IPV6_IFADDR)?;
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTNLGRP_IPV4_IFADDR)?;
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTNLGRP_LINK)?;

        tokio::spawn(connection);
        Ok((handle, messages))
    }

    async fn perform_initial_scan(
        handle: &rtnetlink::Handle,
        _messages: &NetlinkMessages,
        target_ifindex: u32,
        ctx: &LanforgeContext,
    ) -> Result<InterfaceState> {
        refresh_interface(handle, target_ifindex, ctx)
            .await
            .map_err(|e| anyhow::anyhow!("Initial interface scan failed: {e}"))
    }

    fn log_welcome_banner(cfg: &Config, if_state: &InterfaceState) {
        let ll_str = if_state
            .link_local
            .map_or_else(|| "none".to_string(), |ip| ip.to_string());
        let gua_str = if_state.gua.map_or_else(
            || "none".to_string(),
            |ip| Ipv6Prefix::from_addr(ip).to_string(),
        );
        info!(
            iface = %cfg.system.iface,
            link_local = %ll_str,
            gua_prefix = %gua_str,
            "Lanforge Daemon ready on interface"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_db::redb;
    use std::path::Path;

    fn config_with_db(path: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.database.config_path = path.display().to_string();
        cfg.database.runtime_path = "memory".to_string();
        cfg.system.auto_provision = false;
        cfg
    }

    #[test]
    fn unreadable_persistent_db_is_not_a_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.redb");
        std::fs::write(&path, b"definitely not a redb file").unwrap();
        let mut cfg = config_with_db(&path);

        let (db, _log_db) = Bootstrapper::open_databases(&cfg).unwrap();
        assert!(
            db.is_in_memory(),
            "an unopenable DB must enter recovery mode"
        );

        assert!(Bootstrapper::check_provisioning_mode(&mut cfg, &db));
        assert!(
            db.is_provisioned().unwrap(),
            "the stand-in DB must lock /setup"
        );
        assert!(
            !dir.path().join("lanforge.redb").exists() && !Path::new("lanforge.redb").exists(),
            "no fallback DB file may be created"
        );
    }

    #[test]
    fn memory_only_by_config_is_a_first_run() {
        let mut cfg = Config::default();
        cfg.database.config_path = "memory".to_string();
        cfg.database.runtime_path = "memory".to_string();
        cfg.system.auto_provision = false;
        assert!(cfg.database.is_in_memory());

        let (db, _log_db) = Bootstrapper::open_databases(&cfg).unwrap();
        assert!(db.is_in_memory());
        assert!(!Bootstrapper::is_recovery(&cfg, &db));
        assert!(
            !Bootstrapper::check_provisioning_mode(&mut cfg, &db),
            "an intentional memory-only run must offer first-run setup"
        );
        assert!(!db.is_provisioned().unwrap(), "setup must stay open");
    }

    /// Memory-only must be asked for by name: a blank path or a leftover SQL-era URL is a
    /// broken persistent config (recovery), never a fresh install with `/setup` open.
    #[test]
    fn blank_or_legacy_db_path_is_recovery_not_memory_only() {
        for path in ["", "  ", "sqlite:///var/lib/lanforge/lanforge.db"] {
            let mut cfg = Config::default();
            cfg.database.config_path = path.to_string();
            cfg.database.runtime_path = "memory".to_string();
            cfg.system.auto_provision = false;

            let (db, _log_db) = Bootstrapper::open_databases(&cfg).unwrap();
            assert!(
                Bootstrapper::is_recovery(&cfg, &db),
                "{path:?} must enter recovery mode"
            );
            assert!(
                Bootstrapper::check_provisioning_mode(&mut cfg, &db),
                "{path:?} must not look like a first run"
            );
        }
        assert!(
            !Path::new("sqlite:").exists(),
            "a URL must not be created as a relative directory"
        );
    }

    /// The owner's real firewall (2026-10-27, internal addresses replaced by documentation
    /// ones): the file it has yields the firewall the daemon ran with, and so the very same nft
    /// ruleset, byte for byte (`ppp0` up, as on the box).
    #[cfg(all(feature = "nft", feature = "pppoe", feature = "traffic"))]
    #[test]
    fn owner_firewall_file_keeps_the_same_ruleset() {
        use lanforge_api::config_file::ConfigFile;
        use lanforge_nft::{FirewallConfig, RulesetBuilder};

        const LIVE: &str = r#"{
          "bypass_dns": true, "bypass_vowifi": true, "custom_rules_file": null,
          "default_forward_policy": "Drop", "default_input_policy": "Drop", "enabled": true,
          "flow_offload": false,
          "forwardings": [
            {"from": "internal", "to": "external"}, {"from": "trusted", "to": "external"},
            {"from": "trusted", "to": "internal"}, {"from": "internal", "to": "trusted"}],
          "mode": "full", "on_stop": "lockdown",
          "port_forwards": [
            {"comment": "qBittorrent", "enable_hairpin": true, "external_port": 6881,
             "internal_ip": "192.0.2.128", "internal_port": 6881, "protocol": "Tcp", "src_zone": "external"},
            {"comment": "qBittorrent [IPv6]", "enable_hairpin": true, "external_port": 6881,
             "internal_ip": "2001:db8:cafe:3731::501", "internal_port": 6881, "protocol": "Tcp", "src_zone": "external"}],
          "table_name": "lanforge",
          "zones": [
            {"forward_policy": "Drop", "input_policy": "Drop", "interfaces": ["wan0"],
             "masquerade": true, "mtu_fix": true, "name": "external", "open_ports": []},
            {"forward_policy": "Accept", "input_policy": "Accept", "interfaces": ["lan0"],
             "masquerade": false, "mtu_fix": false, "name": "internal", "open_ports": [
               {"comment": null, "port": 22, "protocol": "Tcp"}, {"comment": null, "port": 53, "protocol": "Udp"},
               {"comment": null, "port": 53, "protocol": "Tcp"}, {"comment": null, "port": 67, "protocol": "Udp"},
               {"comment": null, "port": 8088, "protocol": "Tcp"}, {"comment": null, "port": 9090, "protocol": "Tcp"}]},
            {"forward_policy": "Accept", "input_policy": "Accept",
             "interfaces": ["tailscale0", "podman*"], "masquerade": false, "mtu_fix": false,
             "name": "trusted", "open_ports": []}]
        }"#;
        const FILE: &str = "[system]\niface = \"lan0\"\n\n[firewall]\nenabled = true\nflow_offload = false\nbypass_dns = true\nbypass_vowifi = true\ndefault_input_policy = \"drop\"\ndefault_forward_policy = \"drop\"\n\n[firewall.zones.external]\ninterfaces = [\"wan0\"]\ninput = \"drop\"\nforward = \"drop\"\nmasquerade = true\nmtu_fix = true\n\n[firewall.zones.internal]\ninterfaces = [\"lan0\"]\ninput = \"accept\"\nforward = \"accept\"\nmasquerade = false\nmtu_fix = false\nopen_ports = [\"22/tcp\", \"53/udp\", \"53/tcp\", \"67/udp\", \"8088/tcp\", \"9090/tcp\"]\n\n[firewall.zones.trusted]\ninterfaces = [\"tailscale0\", \"podman*\"]\ninput = \"accept\"\nforward = \"accept\"\nmasquerade = false\nmtu_fix = false\n\n[firewall.port_forwards.qBittorrent]\nproto = \"tcp\"\nport = 6881\nto = \"192.0.2.128\"\nto_port = 6881\ndescription = \"qBittorrent\"\n\n[firewall.port_forwards.\"qBittorrent [IPv6]\"]\nproto = \"tcp\"\nport = 6881\nto = \"2001:db8:cafe:3731::501\"\nto_port = 6881\ndescription = \"qBittorrent [IPv6]\"\n";

        let live: FirewallConfig = serde_json::from_str(LIVE).unwrap();
        let file = ConfigFile::parse(FILE).unwrap();
        let (from_file, issues) = file.firewall.to_config();
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(from_file, live, "the file holds the live firewall");

        let mut cfg = config_with_db(std::path::Path::new("memory"));
        cfg.system.iface = "lan0".into();
        // As on the box: SQM on (CAKE 770/380), PPPoE dataplane defaults.
        cfg.firewall_toml = from_file.effective(Some(&cfg.pppoe_toml.nftables), true, "lan0");
        assert_eq!(cfg.firewall_toml, live, "the daemon runs the live firewall");

        let ruleset = |fw: &FirewallConfig| {
            serde_json::to_string(
                &RulesetBuilder::new(fw)
                    .with_active_wan(Some("ppp0"))
                    .with_primary_lan(Some("lan0"))
                    .build(),
            )
            .unwrap()
        };
        assert_eq!(ruleset(&cfg.firewall_toml), ruleset(&live));
    }

    /// The owner's DHCP as redb holds it (`lanforge dhcp --json`, 2026-10-28; the pools filled
    /// with the scope values by the old seed).
    #[cfg(feature = "dhcp")]
    fn owner_stored_dhcp() -> lanforge_api::config_file::DhcpSettings {
        use lanforge_types::network::dhcp::Dhcpv6Pool;

        let options = serde_json::from_str(
            r#"{"tftp": {"block_size": 512, "enabled": false, "listen_addr": "0.0.0.0:69",
                "max_retries": 3, "root_dir": "/var/lib/lanforge/tftp", "timeout": 5},
              "v4": {"boot_file": null, "dns_servers": ["192.168.3.1"], "domain_name": "lan",
                "enabled": true, "lease_time": 86400, "ntp_servers": ["162.159.200.1", "216.239.35.0"],
                "raw_options": {}, "router": "192.168.3.1", "search_domains": [],
                "subnet_mask": "255.255.252.0", "tftp_server": null},
              "v6": {"boot_file": null, "dns_servers": [], "enabled": true, "lease_time": 86400,
                "ntp_servers": ["time.cloudflare.com", "time.google.com"], "raw_options": {},
                "search_domains": []}}"#,
        )
        .unwrap();
        let router = "192.168.3.1".parse().unwrap();
        lanforge_api::config_file::DhcpSettings {
            options,
            v4_pools: vec![Dhcpv4Pool {
                name: Some("Primary LAN".into()),
                range_start: "192.168.1.2".parse().unwrap(),
                range_end: "192.168.1.240".parse().unwrap(),
                subnet_mask: Some("255.255.252.0".parse().unwrap()),
                router: Some(router),
                dns_servers: vec![router],
                lease_time: Some(86400),
                ..Default::default()
            }],
            v6_pools: vec![Dhcpv6Pool {
                name: Some("Main Scope".into()),
                range_start: "::100".parse().ok(),
                range_end: "::1fff".parse().ok(),
                ..Default::default()
            }],
        }
    }

    /// The host moved to a new address: the gateway it advertised follows, and the correction
    /// is saved to the file — kept in memory only, the next boot (whose host record already
    /// has the new address) would advertise the old gateway again.
    #[cfg(feature = "dhcp")]
    #[test]
    fn a_gateway_that_followed_the_host_is_saved_to_the_file() {
        use lanforge_api::config_file::ConfigFile;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(&path, "[system]\niface = \"lan0\"\n").unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        cfg.config_path = path.display().to_string();
        cfg.config_writable = true;
        cfg.dhcp = owner_stored_dhcp();
        let v4: Ipv4Network = "192.168.3.2/22".parse().unwrap();
        let old = "192.168.3.1".parse().unwrap();

        assert!(Bootstrapper::audit_and_heal_dhcp_options(
            &mut cfg,
            v4,
            v4.ip(),
            v4.mask(),
            Some(old)
        ));
        assert!(
            !Bootstrapper::audit_and_heal_dhcp_pools(&mut cfg, v4),
            "pools still fit"
        );
        Bootstrapper::persist_dhcp_heal(&cfg);

        let text = std::fs::read_to_string(&path).unwrap();
        let (dhcp, _) = ConfigFile::parse(&text).unwrap().dhcp_settings();
        assert_eq!(dhcp.options.v4.router, Some(v4.ip()));
        assert_eq!(dhcp.v4_pools, owner_stored_dhcp().v4_pools);
    }

    #[test]
    fn unreadable_provisioning_state_is_not_a_first_run() {
        const META: redb::TableDefinition<u64, u64> = redb::TableDefinition::new("meta");
        const USERS: redb::TableDefinition<u64, u64> = redb::TableDefinition::new("users");
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        let (db, _log_db) = Bootstrapper::open_databases(&cfg).unwrap();
        assert!(!db.is_in_memory());
        {
            let txn = db.redb().begin_write().unwrap();
            txn.delete_table(redb::TableDefinition::<&str, &[u8]>::new("meta"))
                .unwrap();
            txn.open_table(META).unwrap();
            txn.open_table(USERS).unwrap();
            txn.commit().unwrap();
        }
        assert!(db.is_provisioned().is_err() && db.count_users().is_err());

        assert!(Bootstrapper::check_provisioning_mode(&mut cfg, &db));
    }

    /// An unreadable `[dhcp]` runs on defaults; a startup correction of those defaults must not
    /// be written over the section (it deleted the owner's pools: a v6 pool key the file form
    /// no longer has made `[dhcp]` unreadable, the sanity check then saved default pools).
    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_heal_never_overwrites_an_unreadable_dhcp_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        let text = "[dhcp.v4.pools.lan]\nrange = \"192.168.1.100-192.168.1.200\"\n\n\
                    [dhcp.v6.pools.main]\nrange = \"::100-::1fff\"\ndns = [\"fd00::1\"]\n";
        std::fs::write(&path, text).unwrap();
        let toml = crate::config::toml::load_toml(&path.display().to_string());
        assert!(toml.dhcp_set_aside, "{:?}", toml.config_issues);

        let cfg = Config {
            config_path: path.display().to_string(),
            dhcp_set_aside: toml.dhcp_set_aside,
            ..Config::default()
        };
        Bootstrapper::persist_dhcp_heal(&cfg);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }
}
