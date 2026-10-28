use anyhow::Result;
use bytesize::ByteSize;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_core::context::{ConfigPatch, LanforgeContext};
use lanforge_db::{
    AdblockStore, DnsStore, DnsUpstreamStore, FirewallConfigStore, LanforgeDb, LogDb, LogStore,
    PppoeConfigStore, RaConfigStore, TrafficConfigStore, UserStore,
};
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v4::sanity::derive_dhcp_defaults_from_v4;
use lanforge_discovery::refresh_interface;
#[cfg(feature = "dns")]
use lanforge_types::DnsListenConfig;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
#[cfg(feature = "dhcp")]
use lanforge_types::network::dhcp::Dhcpv4Pool;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::AdblockUrlEntry;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::adblock::{AdblockRuleEntry, AdblockUrlKind};
#[cfg(feature = "dns")]
use lanforge_types::network::dns::upstream::UpstreamMode;
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

const RTNLGRP_NEIGH: u32 = 3;
const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV6_IFADDR: u32 = 9;

type NetlinkRawMessage = (NetlinkMessage<RouteNetlinkMessage>, SocketAddr);
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
            "Starting Lanforge (RA: {}, DHCPv4: {}, DHCPv6: {}, DNS: {})",
            feat_flag!(ra, cfg.ra_enabled),
            feat_flag!(dhcp, cfg.dhcpv4_enabled),
            feat_flag!(dhcp, cfg.dhcpv6_enabled),
            feat_flag!(dns, cfg.dns_enabled)
        );

        let bus = Arc::new(EventBus::new());
        let host_ifaces = interfaces();
        let target_ifindex = Self::find_target_interface(&mut cfg, &host_ifaces)?;
        let (initial_table, db, log_db) = Self::init_device_table(&mut cfg, &host_ifaces)?;
        let db = Arc::new(db);
        let log_db = Arc::new(log_db);
        let cfg = Arc::new(cfg);

        let ctx = LanforgeContext::new(bus.clone(), initial_table, Some(target_ifindex));
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
            Self::load_dns_state_into_patch(db, cfg.dns_toml.upstream_mode, &mut patch);
            // The DNS service binds from the live listeners; the file is their source.
            let dns = cfg.to_dns_config();
            patch = patch.with_dns_listen(DnsListenConfig {
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

    #[cfg(feature = "dns")]
    /// `file_mode` (`[dns] upstream_mode`) seeds the live mode when the database has none.
    fn load_dns_state_into_patch(
        db: &LanforgeDb,
        file_mode: UpstreamMode,
        patch: &mut ConfigPatch,
    ) {
        if let Ok(upstreams) = db.load_dns_upstreams() {
            let list = upstreams.into_iter().map(|row| row.to_target()).collect();
            patch.dns_upstreams = Some(list);
        }
        patch.dns_upstream_mode = Some(match db.load_dns_upstream_mode() {
            Ok(Some(mode)) => mode,
            _ => file_mode,
        });
        if let Ok(rewrites) = db.load_dns_rewrites() {
            patch.dns_rewrites = Some(rewrites);
        }
        if let Ok(allowlist) = db.load_dns_allowlist() {
            patch.dns_allowlist = Some(allowlist.into_iter().map(|(_, d)| d).collect());
        }
        if let Ok(adblock) = db.load_adblock_config() {
            patch.dns_adblock = Some(adblock);
        }
        if let Ok(urls) = db.load_adblock_urls() {
            patch.dns_adblock_urls = Some(
                urls.into_iter()
                    .map(|(id, url, kind, format)| AdblockUrlEntry {
                        id: Some(id),
                        name: Some(lanforge_crypto::stable_id_or_hash(
                            None,
                            url.as_bytes(),
                            "src",
                        )),
                        url,
                        kind,
                        format,
                    })
                    .collect(),
            );
        }
        if let Ok(rules) = db.load_adblock_rules() {
            patch.dns_adblock_rules = Some(
                rules
                    .into_iter()
                    .map(|(id, domain, action, enabled)| AdblockRuleEntry {
                        id: Some(id),
                        name: Some(lanforge_crypto::slugify(&domain)),
                        domain,
                        action,
                        enabled,
                    })
                    .collect(),
            );
        }
    }

    #[cfg(feature = "dns")]
    fn load_dns_config(db: &LanforgeDb, cfg: &Config) -> Result<()> {
        // Seed upstreams if empty in DB
        let upstreams = db.load_dns_upstreams()?;
        if upstreams.is_empty() && !cfg.dns_toml.upstreams.is_empty() {
            for entry in &cfg.dns_toml.upstreams {
                let target = &entry.target;
                let _ =
                    db.add_dns_upstream(target.addr, target.protocol, target.domain.as_deref())?;
            }
            info!(
                "Seeded {} DNS upstreams from configuration into database",
                cfg.dns_toml.upstreams.len()
            );
        }

        // Seed rewrites if empty in DB
        let rewrites = db.load_dns_rewrites()?;
        if rewrites.is_empty() && !cfg.dns_toml.rewrites.is_empty() {
            for rule in &cfg.dns_toml.rewrites {
                db.upsert_dns_rewrite(&rule.domain, rule.rtype, &rule.answer)?;
            }
            info!(
                "Seeded {} DNS rewrites from configuration into database",
                cfg.dns_toml.rewrites.len()
            );
        }

        // Seed allowlist if empty in DB
        let allowlist = db.load_dns_allowlist()?;
        if allowlist.is_empty() && !cfg.dns_toml.allowlist.is_empty() {
            for domain in &cfg.dns_toml.allowlist {
                db.add_dns_allowlist(domain)?;
            }
            info!(
                "Seeded {} DNS allowlist domains from configuration into database",
                cfg.dns_toml.allowlist.len()
            );
        }

        // Seed adblock urls if empty in DB
        let adblock_urls = db.load_adblock_urls()?;
        let is_new_adblock = adblock_urls.is_empty();
        if is_new_adblock {
            let mut count = 0;
            for url in &cfg.dns_toml.adblock_urls {
                db.add_adblock_url(
                    url,
                    AdblockUrlKind::Blocklist,
                    lanforge_types::network::dns::adblock::AdblockSourceFormat::Auto,
                )?;
                count += 1;
            }
            for url in &cfg.dns_toml.adblock_allowlist_urls {
                db.add_adblock_url(
                    url,
                    AdblockUrlKind::Allowlist,
                    lanforge_types::network::dns::adblock::AdblockSourceFormat::Auto,
                )?;
                count += 1;
            }
            if count > 0 {
                info!("Seeded {count} Adblock source URLs from configuration into database");
            }

            // Seed adblock config overrides from TOML on first run
            let adblock_cfg = lanforge_types::network::dns::adblock::AdblockDbConfig {
                enabled: cfg.dns_toml.adblock_enabled,
                blocking_mode: cfg.dns_toml.blocking_mode,
                blocking_ip_v4: cfg.dns_toml.blocking_ip_v4,
                blocking_ip_v6: cfg.dns_toml.blocking_ip_v6,
                refresh_time: cfg.dns_toml.adblock_refresh_time,
            };
            db.save_adblock_config(&adblock_cfg)?;
        }

        // Seed adblock custom rules if empty in DB
        let adblock_rules = db.load_adblock_rules()?;
        if adblock_rules.is_empty() && !cfg.dns_toml.adblock_rules.is_empty() {
            for rule in &cfg.dns_toml.adblock_rules {
                let id = db.add_adblock_rule(&rule.domain, rule.action)?;
                if !rule.enabled {
                    let _ = db.update_adblock_rule_status(id, false);
                }
            }
            info!(
                "Seeded {} Adblock custom rules from configuration into database",
                cfg.dns_toml.adblock_rules.len()
            );
        }

        Ok(())
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
            crate::config::sync::sync_boot_config(&config_path, &db, cfg.config_writable)?;
            Self::seed_provisioned_configs(&db, cfg)?;
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

        if is_provisioned {
            Self::migrate_hosts(&db, cfg, &table)?;
        }

        // 2c. Check/reconcile DHCPv4 topology sanity against physical interface and host identity
        #[cfg(feature = "dhcp")]
        if is_provisioned {
            Self::reconcile_dhcp_v4_topology_sanity(cfg, &table, host_ifaces);
        }

        if let Ok(resolvers) = db.load_dns_reverse_resolvers() {
            table.reverse_resolvers = resolvers;
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

    fn seed_provisioned_configs(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        #[cfg(feature = "dhcp")]
        Self::migrate_dhcp_config(db, cfg)?;

        #[cfg(feature = "ra")]
        Self::migrate_ra_config(db, cfg)?;

        #[cfg(feature = "dns")]
        Self::load_dns_config(db, cfg)?;

        #[cfg(feature = "pppoe")]
        Self::migrate_pppoe_config(db, cfg)?;

        #[cfg(feature = "traffic")]
        Self::migrate_traffic_config(db, cfg)?;

        #[cfg(feature = "nft")]
        Self::migrate_firewall_config(db, cfg)?;

        Ok(())
    }

    /// Moves the DHCP options and pools an older binary kept in redb (three keys, the TFTP
    /// options inside the first) into `[dhcp]` and `[tftp]` (once). A key that is missing keeps
    /// what the file has.
    #[cfg(feature = "dhcp")]
    fn migrate_dhcp_config(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        use lanforge_db::config_keys::{DHCP_OPTIONS, DHCP_V4_POOLS, DHCP_V6_POOLS};

        let options = db.get(DHCP_OPTIONS)?;
        let v4_pools = db.get(DHCP_V4_POOLS)?;
        let v6_pools = db.get(DHCP_V6_POOLS)?;
        if options.is_some() || v4_pools.is_some() || v6_pools.is_some() {
            let stored = lanforge_api::config_file::DhcpSettings {
                options: options.unwrap_or_else(|| cfg.dhcp.options.clone()),
                v4_pools: v4_pools.unwrap_or_else(|| cfg.dhcp.v4_pools.clone()),
                v6_pools: v6_pools.unwrap_or_else(|| cfg.dhcp.v6_pools.clone()),
            };
            cfg.dhcp = stored.clone();
            Self::move_section_to_file(
                db,
                cfg,
                "DHCP",
                &[
                    DHCP_OPTIONS.name(),
                    DHCP_V4_POOLS.name(),
                    DHCP_V6_POOLS.name(),
                ],
                lanforge_api::config_file::SectionSet::DHCP
                    | lanforge_api::config_file::SectionSet::TFTP,
                |file| file.set_dhcp_settings(&stored),
            )?;
        }
        Self::sync_dhcp_service_configs(cfg);
        Ok(())
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

    /// Config-storage cut-over for `[hosts]`: static hosts lived in the device table, mirrored
    /// into the file by the db worker; the file is now their only source. Once, the table's
    /// static hosts (what the daemon ran with) are merged into `[hosts]` — a host only the file
    /// lists is kept — with a backup of the file, and a marker is set. Until the file can take
    /// them the merge is used for this run; an unreadable `[hosts]` waits for the next boot.
    fn migrate_hosts(db: &LanforgeDb, cfg: &mut Config, table: &State) -> Result<()> {
        use lanforge_db::ConfigStore;
        const MARKER: &str = "config_storage:hosts_in_file";

        if db.get_meta(MARKER)?.is_some() {
            return Ok(());
        }
        let Some(file_hosts) = cfg.static_hosts.as_ref() else {
            return Ok(());
        };
        let mut hosts: Vec<lanforge_types::device::StaticHost> = table
            .devices
            .values()
            .filter_map(|dev| dev.static_host())
            .collect();
        hosts.sort_by(|a, b| {
            (a.hostname.to_lowercase(), a.mac).cmp(&(b.hostname.to_lowercase(), b.mac))
        });
        for host in file_hosts {
            if !hosts.iter().any(|h| h.mac == host.mac) {
                hosts.push(host.clone());
            }
        }
        let moved = Self::move_section_to_file(
            db,
            cfg,
            "static hosts",
            &[],
            lanforge_api::config_file::SectionSet::HOSTS,
            |file| file.set_static_hosts(&hosts),
        )?;
        cfg.static_hosts = Some(hosts);
        if moved {
            db.set_meta(MARKER, &[1])?;
        }
        Ok(())
    }

    /// Moves the RA lists an older binary kept in redb (prefixes, RDNSS, DNSSL) into `[ra]`
    /// (once); its other keys were already file-only. A key that is missing keeps what the
    /// file has.
    #[cfg(feature = "ra")]
    fn migrate_ra_config(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        use lanforge_db::config_keys::{RA_DNSSL, RA_PREFIXES, RA_RDNSS};

        let prefixes = db.get(RA_PREFIXES)?;
        let rdnss = db.get(RA_RDNSS)?;
        let dnssl = db.get(RA_DNSSL)?;
        if prefixes.is_none() && rdnss.is_none() && dnssl.is_none() {
            return Ok(());
        }
        if let Some(prefixes) = prefixes {
            cfg.ra.prefixes = prefixes;
        }
        if let Some(rdnss) = rdnss {
            cfg.ra.rdnss = rdnss;
        }
        if let Some(dnssl) = dnssl {
            cfg.ra.dnssl = dnssl;
        }
        let stored = cfg.ra.clone();
        Self::move_section_to_file(
            db,
            cfg,
            "RA",
            &[RA_PREFIXES.name(), RA_RDNSS.name(), RA_DNSSL.name()],
            lanforge_api::config_file::SectionSet::RA,
            |file| file.ra = lanforge_api::config_file::RaFile::from_config(&stored),
        )
        .map(|_| ())
    }

    /// Config-storage cut-over for a file-owned section (`SectionSet::FILE_OWNED`), whose only
    /// source is now its table in the config file. The redb key an older binary left holds the
    /// full configuration the daemon ran with (the file kept only part of it): it is written to
    /// the file once, with a backup of the file, and then removed. Until the file can take it
    /// (read-only config, write error) the key is kept; the caller uses the stored value anyway.
    /// Returns whether the file took it.
    fn move_section_to_file(
        db: &LanforgeDb,
        cfg: &Config,
        name: &str,
        keys: &[&str],
        section: lanforge_api::config_file::SectionSet,
        fill: impl FnOnce(&mut lanforge_api::config_file::ConfigFile),
    ) -> Result<bool> {
        use lanforge_api::config_file::{ConfigFile, persist_sections};

        let path = std::path::Path::new(&cfg.config_path);
        if !cfg.config_writable || !path.exists() {
            warn!(
                "Config: {name} settings stay in the database until '{}' is writable",
                path.display()
            );
            return Ok(false);
        }
        let backup = path.with_extension("toml.bak");
        let mut section_cfg = ConfigFile::default();
        fill(&mut section_cfg);
        let moved = std::fs::copy(path, &backup)
            .and_then(|_| persist_sections(path, &section_cfg, section));
        if let Err(e) = moved {
            warn!(
                "Config: could not move {name} settings to '{}' ({e}); keeping them in the database",
                path.display()
            );
            return Ok(false);
        }
        db.write(|tx| keys.iter().try_for_each(|key| tx.remove_config(key)))?;
        info!(
            "Config: moved {name} settings from the database to '{}' (previous file kept as '{}')",
            path.display(),
            backup.display()
        );
        Ok(true)
    }

    #[cfg(feature = "pppoe")]
    fn migrate_pppoe_config(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        let Some(stored) = db.load_pppoe_config()? else {
            return Ok(());
        };
        cfg.pppoe_enabled = stored.enabled;
        cfg.pppoe_toml = stored.clone();
        Self::move_section_to_file(
            db,
            cfg,
            "PPPoE",
            &[lanforge_db::config_keys::PPPOE.name()],
            lanforge_api::config_file::SectionSet::PPPOE,
            |file| file.pppoe = stored,
        )
        .map(|_| ())
    }

    #[cfg(feature = "traffic")]
    fn migrate_traffic_config(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        let Some(stored) = db.load_traffic_config()? else {
            return Ok(());
        };
        cfg.traffic_toml = stored.clone();
        Self::move_section_to_file(
            db,
            cfg,
            "traffic",
            &[lanforge_db::config_keys::TRAFFIC.name()],
            lanforge_api::config_file::SectionSet::TRAFFIC,
            |file| file.traffic = stored,
        )
        .map(|_| ())
    }

    /// Moves a firewall an older binary kept in redb into `[firewall]` (once), then derives the
    /// firewall the daemon runs (`effective_firewall`): in memory only, the file keeps what the
    /// admin wrote.
    #[cfg(feature = "nft")]
    fn migrate_firewall_config(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        if let Some(stored) = db.load_firewall_config()? {
            cfg.firewall_toml = stored.clone();
            Self::move_section_to_file(
                db,
                cfg,
                "firewall",
                &[lanforge_db::config_keys::FIREWALL.name()],
                lanforge_api::config_file::SectionSet::FIREWALL,
                |file| {
                    file.firewall = lanforge_api::config_file::FirewallFile::from_config(&stored);
                },
            )?;
        }

        #[cfg(feature = "traffic")]
        let sqm_enabled = cfg.traffic_toml.sqm.enabled;
        #[cfg(not(feature = "traffic"))]
        let sqm_enabled = false;
        #[cfg(feature = "pppoe")]
        let pppoe = Some(&cfg.pppoe_toml);
        #[cfg(not(feature = "pppoe"))]
        let pppoe = None;
        let effective = lanforge_api::config_file::effective_firewall(
            cfg.firewall_toml.clone(),
            pppoe,
            sqm_enabled,
            &cfg.system.iface,
        );
        if effective != cfg.firewall_toml {
            info!(
                "Firewall: adjusted for PPPoE/SQM/LAN settings (in memory, not written to the file)"
            );
        }
        cfg.firewall_enabled = effective.enabled;
        cfg.firewall_toml = effective;
        Ok(())
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

    /// The cut-over moves the full `PPPoE` config an older binary kept in redb into the file,
    /// once: every field survives, the rest of the file (comments included) is untouched, the
    /// previous file is backed up and the key is gone.
    #[cfg(feature = "pppoe")]
    #[test]
    fn pppoe_config_moves_from_the_database_to_the_file_once() {
        use lanforge_api::config_file::ConfigFile;
        use lanforge_types::network::pppoe::{AuthMethod, PppoeConfig};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        let old_file = "# home router\n[system]\niface = \"lan0\" # LAN port\n\n\
                        [pppoe]\nenabled = true\nwan_iface = \"wan0\"\nusername = \"user\"\n";
        std::fs::write(&path, old_file).unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        cfg.config_path = path.display().to_string();
        cfg.config_writable = true;

        let db = LanforgeDb::open_in_memory().unwrap();
        let mut stored = PppoeConfig {
            enabled: true,
            wan_iface: "wan0".into(),
            username: "user".into(),
            password: "secret".into(),
            auth: AuthMethod::Pap,
            service_name: Some("isp".into()),
            lcp_echo_interval_secs: 30,
            ..PppoeConfig::default()
        };
        stored.nftables.bypass_vowifi = false;
        stored.nftables.lan_ifaces = vec!["lan0".into()];
        stored.terminal_probe.enabled = true;
        db.save_pppoe_config(&stored).unwrap();

        Bootstrapper::migrate_pppoe_config(&db, &mut cfg).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(ConfigFile::parse(&text).unwrap().pppoe, stored, "{text}");
        assert!(text.contains("# home router") && text.contains("# LAN port"));
        assert_eq!(cfg.pppoe_toml, stored);
        assert!(db.load_pppoe_config().unwrap().is_none(), "key removed");
        assert_eq!(
            std::fs::read_to_string(path.with_extension("toml.bak")).unwrap(),
            old_file
        );

        // Second boot: the file is the source, nothing moves.
        std::fs::remove_file(path.with_extension("toml.bak")).unwrap();
        Bootstrapper::migrate_pppoe_config(&db, &mut cfg).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert!(!path.with_extension("toml.bak").exists());
    }

    /// Same cut-over for traffic/SQM: the six SQM fields the old `[traffic]` dropped survive.
    #[cfg(feature = "traffic")]
    #[test]
    fn traffic_config_moves_from_the_database_to_the_file_once() {
        use lanforge_api::config_file::ConfigFile;
        use lanforge_types::network::traffic::TrafficConfig;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "# box\n[traffic.sqm]\nenabled = true\ndownload_mbps = 770\n",
        )
        .unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        cfg.config_path = path.display().to_string();
        cfg.config_writable = true;
        let db = LanforgeDb::open_in_memory().unwrap();
        let mut stored = TrafficConfig::default();
        stored.sqm.enabled = true;
        stored.sqm.download_mbps = 770;
        stored.sqm.upload_mbps = 380;
        stored.sqm.rtt_ms = Some(40);
        stored.sqm.per_host_isolation = false;
        stored.sqm.raw_cake_args = Some("ack-filter".into());
        stored.tuning.interfaces = vec!["lan0".into(), "wan0".into()];
        db.save_traffic_config(&stored).unwrap();

        Bootstrapper::migrate_traffic_config(&db, &mut cfg).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(ConfigFile::parse(&text).unwrap().traffic, stored, "{text}");
        assert!(text.starts_with("# box"));
        assert_eq!(cfg.traffic_toml, stored);
        assert!(db.load_traffic_config().unwrap().is_none(), "key removed");
    }

    /// The owner's real firewall (2026-10-27, internal addresses replaced by documentation
    /// ones) through the cut-over: the file it had, the redb value the daemon ran with. The
    /// firewall the daemon runs afterwards must be the same value, and so the very same nft
    /// ruleset, byte for byte (`ppp0` up, as on the box).
    #[cfg(all(feature = "nft", feature = "pppoe", feature = "traffic"))]
    #[test]
    fn owner_firewall_cut_over_keeps_the_same_ruleset() {
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
            {"allowed_subnets": [], "forward_policy": "Drop", "input_policy": "Drop", "interfaces": ["wan0"],
             "masquerade": true, "mtu_fix": true, "name": "external", "open_ports": []},
            {"allowed_subnets": [], "forward_policy": "Accept", "input_policy": "Accept", "interfaces": ["lan0"],
             "masquerade": false, "mtu_fix": false, "name": "internal", "open_ports": [
               {"comment": null, "port": 22, "protocol": "Tcp"}, {"comment": null, "port": 53, "protocol": "Udp"},
               {"comment": null, "port": 53, "protocol": "Tcp"}, {"comment": null, "port": 67, "protocol": "Udp"},
               {"comment": null, "port": 8088, "protocol": "Tcp"}, {"comment": null, "port": 9090, "protocol": "Tcp"}]},
            {"allowed_subnets": [], "forward_policy": "Accept", "input_policy": "Accept",
             "interfaces": ["tailscale0", "podman*"], "masquerade": false, "mtu_fix": false,
             "name": "trusted", "open_ports": []}]
        }"#;
        const OLD_FILE: &str = "[system]\niface = \"lan0\"\n\n[firewall]\nenabled = true\nflow_offload = false\nbypass_dns = true\nbypass_vowifi = true\ndefault_input_policy = \"drop\"\ndefault_forward_policy = \"drop\"\n\n[firewall.zones.external]\ninterfaces = [\"wan0\"]\ninput = \"drop\"\nforward = \"drop\"\nmasquerade = true\nmtu_fix = true\n\n[firewall.zones.internal]\ninterfaces = [\"lan0\"]\ninput = \"accept\"\nforward = \"accept\"\nmasquerade = false\nmtu_fix = false\nopen_ports = [\"22/tcp\", \"53/udp\", \"53/tcp\", \"67/udp\", \"8088/tcp\", \"9090/tcp\"]\n\n[firewall.zones.trusted]\ninterfaces = [\"tailscale0\", \"podman*\"]\ninput = \"accept\"\nforward = \"accept\"\nmasquerade = false\nmtu_fix = false\n\n[firewall.port_forwards.qBittorrent]\nproto = \"tcp\"\nport = 6881\nto = \"192.0.2.128\"\nto_port = 6881\ndescription = \"qBittorrent\"\n\n[firewall.port_forwards.\"qBittorrent [IPv6]\"]\nproto = \"tcp\"\nport = 6881\nto = \"2001:db8:cafe:3731::501\"\nto_port = 6881\ndescription = \"qBittorrent [IPv6]\"\n";

        let live: FirewallConfig = serde_json::from_str(LIVE).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(&path, OLD_FILE).unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        cfg.config_path = path.display().to_string();
        cfg.config_writable = true;
        cfg.system.iface = "lan0".into();
        // As on the box: SQM on (CAKE 770/380), PPPoE dataplane defaults.
        cfg.traffic_toml.sqm.enabled = true;
        let db = LanforgeDb::open_in_memory().unwrap();
        db.save_firewall_config(&live).unwrap();

        Bootstrapper::migrate_firewall_config(&db, &mut cfg).unwrap();

        assert!(db.load_firewall_config().unwrap().is_none(), "key removed");
        let file = ConfigFile::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let (from_file, issues) = file.firewall.to_config();
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(from_file, live, "the file holds the live firewall");
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

        // Next boot: the file is the only source and yields the same firewall again.
        let mut next = config_with_db(&dir.path().join("config.redb"));
        next.config_path = cfg.config_path.clone();
        next.config_writable = true;
        next.system.iface = "lan0".into();
        next.traffic_toml.sqm.enabled = true;
        next.firewall_toml = from_file;
        Bootstrapper::migrate_firewall_config(&db, &mut next).unwrap();
        assert_eq!(next.firewall_toml, live);
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
                lease_time: Some(86400),
                ..Default::default()
            }],
        }
    }

    /// DHCP cut-over on the owner's data: the three redb keys land in `[dhcp]`/`[tftp]`
    /// exactly, the rest of the file is kept, and the keys are gone.
    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_config_moves_from_the_database_to_the_file_once() {
        use lanforge_api::config_file::ConfigFile;
        use lanforge_db::DhcpConfigStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "# box\n[system]\niface = \"lan0\"\n\n[dhcp.v4]\nenabled = true\nlease = \"1d\"\n\n\
             [dhcp.v4.pools.\"Primary LAN\"]\nrange = \"192.168.1.2-192.168.1.240\"\n",
        )
        .unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        cfg.config_path = path.display().to_string();
        cfg.config_writable = true;
        let db = LanforgeDb::open_in_memory().unwrap();
        let stored = owner_stored_dhcp();
        db.save_dhcp_options(&stored.options).unwrap();
        db.save_dhcp_v4_pools(&stored.v4_pools).unwrap();
        db.save_dhcp_v6_pools(&stored.v6_pools).unwrap();

        Bootstrapper::migrate_dhcp_config(&db, &mut cfg).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let (from_file, issues) = ConfigFile::parse(&text).unwrap().dhcp_settings();
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(from_file, stored, "{text}");
        assert!(text.starts_with("# box"));
        assert!(text.contains("iface = \"lan0\""));
        assert_eq!(cfg.dhcp, stored);
        assert_eq!(cfg.dhcpv4_toml.pools, stored.v4_pools);
        assert_eq!(cfg.dhcpv6_toml.pools, stored.v6_pools);
        assert!(db.load_dhcp_options().unwrap().is_none(), "keys removed");
        assert_eq!(db.load_dhcp_v4_pools().unwrap(), Vec::new());
        assert_eq!(db.load_dhcp_v6_pools().unwrap(), Vec::new());

        // Second boot: nothing left to move, the file is the source.
        let before = std::fs::read_to_string(&path).unwrap();
        let mut cfg2 = config_with_db(&dir.path().join("config.redb"));
        cfg2.config_path = cfg.config_path.clone();
        cfg2.config_writable = true;
        cfg2.dhcp = from_file;
        Bootstrapper::migrate_dhcp_config(&db, &mut cfg2).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(cfg2.dhcp, stored);
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

    /// RA cut-over on the owner's data: the redb lists (ULA first) land in `[ra]` exactly, with
    /// the scalars the file already had; the file's comment stays and the keys are gone.
    #[cfg(feature = "ra")]
    #[test]
    fn ra_lists_move_from_the_database_to_the_file_once() {
        use lanforge_api::config_file::ConfigFile;
        use lanforge_types::network::ra::{
            DnsslConfig, PrefixLifetime, PrefixSource, RAPrefix, RdnssConfig,
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "# box\n[ra]\nenabled = true\nmanaged = true\nother_config = true\n\
             max_interval = \"200s\"\nlifetime = \"10m\"\nmtu = 1500\n\n\
             [ra.prefixes.auto_gua]\nsource = \"auto_gua\"\nvalid_lifetime = \"30d\"\n\
             preferred_lifetime = \"7d\"\n",
        )
        .unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        cfg.config_path = path.display().to_string();
        cfg.config_writable = true;
        cfg.ra = ConfigFile::parse(&std::fs::read_to_string(&path).unwrap())
            .unwrap()
            .ra
            .to_config()
            .0;
        let db = LanforgeDb::open_in_memory().unwrap();
        let prefixes = vec![
            RAPrefix::ula("fd97:f00d:cafe:3731::/64"),
            RAPrefix {
                source: PrefixSource::AutoGua,
                valid_lifetime: PrefixLifetime::Secs(2_592_000),
                preferred_lifetime: PrefixLifetime::Secs(604_800),
                ..RAPrefix::gua_dynamic()
            },
        ];
        let rdnss = vec![RdnssConfig::new(vec![
            "fd97:f00d:cafe:3731::1".parse().unwrap(),
        ])];
        let dnssl = vec![DnsslConfig {
            domains: vec!["lan".into()],
            lifetime: None,
        }];
        db.save_ra_prefixes(&prefixes).unwrap();
        db.save_ra_rdnss(&rdnss).unwrap();
        db.save_ra_dnssl(&dnssl).unwrap();

        Bootstrapper::migrate_ra_config(&db, &mut cfg).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let (from_file, issues) = ConfigFile::parse(&text).unwrap().ra.to_config();
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(from_file, cfg.ra, "{text}");
        assert_eq!(from_file.prefixes, prefixes, "ULA stays first");
        assert_eq!((from_file.rdnss, from_file.dnssl), (rdnss, dnssl));
        assert_eq!(from_file.lifetime_secs, Some(600), "file scalars kept");
        assert_eq!(from_file.mtu, Some(1500));
        assert!(text.starts_with("# box"));
        assert_eq!(db.load_ra_prefixes().unwrap(), Vec::new(), "keys removed");
        assert_eq!(db.load_ra_rdnss().unwrap(), Vec::new());
        assert_eq!(db.load_ra_dnssl().unwrap(), Vec::new());
    }

    /// Hosts cut-over on the owner's data: the table's static hosts (incl. a boot file the old
    /// `[hosts]` could not hold) land in the file, a host only the file listed is kept, the
    /// marker is set and a second boot changes nothing.
    #[test]
    fn static_hosts_move_from_the_device_table_to_the_file_once() {
        use lanforge_api::config_file::ConfigFile;
        use lanforge_types::device::{Ipv6AddrOrSuffix, StaticHost};
        use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        let old_file = "# box\n[hosts.media-container]\nmac = \"02:4d:45:44:49:41\"\n\
                        v4 = \"192.168.2.9\"\nv6_suffix = \"fd97:f00d:cafe:3731::f00f\"\ndns = false\n\n\
                        [hosts.handwritten]\nmac = \"aa:bb:cc:00:00:01\"\nv4 = \"192.168.0.50\"\n";
        std::fs::write(&path, old_file).unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        cfg.config_path = path.display().to_string();
        cfg.config_writable = true;
        cfg.static_hosts = Some(ConfigFile::parse(old_file).unwrap().static_hosts().0);
        let db = LanforgeDb::open_in_memory().unwrap();

        let table_hosts = [
            (
                "02:4d:45:44:49:41",
                "media-container",
                "192.168.2.9",
                Some("fd97:f00d:cafe:3731::f00f"),
                None,
            ),
            (
                "04:d9:f5:0a:25:94",
                "solarium",
                "192.168.0.128",
                Some("::501"),
                Some("pxelinux.0"),
            ),
            (
                "bc:fc:e7:8a:a9:73",
                "archie",
                "192.168.0.2",
                Some("::1057:cafe"),
                None,
            ),
        ];
        let mut table = State::new();
        for (mac, name, v4, v6, boot) in table_hosts {
            let _ = table.apply_update(
                DeviceUpdate::CliHostUpdated {
                    mac: MacAddr::parse(mac).unwrap(),
                    update: Box::new(CliHostUpdate {
                        hostname: FieldUpdate::Set(name.into()),
                        duid: FieldUpdate::NoChange,
                        v4_static: FieldUpdate::Set(v4.parse().unwrap()),
                        v6_suffix: v6.and_then(Ipv6AddrOrSuffix::parse).into(),
                        boot_file: boot.map(String::from).into(),
                        dns_fallback: FieldUpdate::NoChange,
                        class: FieldUpdate::NoChange,
                        origin: Origin::Static,
                    }),
                },
                &lanforge_core::context::state::DiscoveryStore::default(),
            );
        }

        Bootstrapper::migrate_hosts(&db, &mut cfg, &table).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let (from_file, issues) = ConfigFile::parse(&text).unwrap().static_hosts();
        assert!(issues.is_empty(), "{issues:?}");
        let names: Vec<_> = from_file.iter().map(|h| h.hostname.as_str()).collect();
        assert_eq!(
            names,
            ["archie", "media-container", "solarium", "handwritten"],
            "{text}"
        );
        let solarium: &StaticHost = &from_file[2];
        assert_eq!(solarium.boot_file.as_deref(), Some("pxelinux.0"));
        assert!(text.starts_with("# box"));
        assert!(!text.contains("dns ="), "{text}");
        assert_eq!(cfg.static_hosts.as_deref(), Some(from_file.as_slice()));

        // Second boot: the marker is set, the file is the only source.
        std::fs::write(&path, "[hosts.archie]\nmac = \"bc:fc:e7:8a:a9:73\"\n").unwrap();
        let mut cfg2 = config_with_db(&dir.path().join("config.redb"));
        cfg2.config_path = cfg.config_path.clone();
        cfg2.config_writable = true;
        cfg2.static_hosts = Some(Vec::new());
        Bootstrapper::migrate_hosts(&db, &mut cfg2, &table).unwrap();
        assert_eq!(cfg2.static_hosts, Some(Vec::new()), "not merged again");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[hosts.archie]\nmac = \"bc:fc:e7:8a:a9:73\"\n"
        );
    }

    /// A file that cannot take the config keeps it in the database, in use.
    #[cfg(feature = "pppoe")]
    #[test]
    fn pppoe_config_stays_in_the_database_if_the_file_cannot_take_it() {
        use lanforge_types::network::pppoe::PppoeConfig;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(&path, "[pppoe\nbroken").unwrap();
        let mut cfg = config_with_db(&dir.path().join("config.redb"));
        cfg.config_path = path.display().to_string();
        cfg.config_writable = true;
        let db = LanforgeDb::open_in_memory().unwrap();
        let stored = PppoeConfig {
            username: "kept".into(),
            ..PppoeConfig::default()
        };
        db.save_pppoe_config(&stored).unwrap();

        Bootstrapper::migrate_pppoe_config(&db, &mut cfg).unwrap();

        assert_eq!(cfg.pppoe_toml, stored);
        assert_eq!(db.load_pppoe_config().unwrap(), Some(stored));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[pppoe\nbroken");
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
}
