use anyhow::Result;
use bytesize::ByteSize;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::state::State;
use lanforge_core::context::{ConfigPatch, LanforgeContext};
use lanforge_db::{
    AdblockStore, DhcpConfigStore, DnsStore, DnsUpstreamStore, FirewallConfigStore, LanforgeDb,
    LogDb, LogStore, PppoeConfigStore, RaConfigStore, TrafficConfigStore, UserStore,
};
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v4::sanity::derive_dhcp_defaults_from_v4;
use lanforge_discovery::refresh_interface;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::{
    IpClassification, Ipv6AddrOrSuffix, Ipv6Prefix, classify_ipv6, is_ula,
};
#[cfg(feature = "dhcp")]
use lanforge_types::network::dhcp::{
    DhcpOptionsConfig, Dhcpv4Options, Dhcpv4Pool, Dhcpv6Options, TftpOptions,
};
#[cfg(feature = "dns")]
use lanforge_types::network::dns::AdblockUrlEntry;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::adblock::{AdblockRuleEntry, AdblockUrlKind};
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
use tracing::{debug, info, warn};

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

        let _ = bus.publish(LanforgeEvent::System(SystemEvent::StateReady));

        // --- PHASE 2: Netlink Setup ---
        let (handle, messages) = Self::start_netlink_dispatcher()?;

        // --- PHASE 3: Initial Scan ---
        // Crucial: updates ctx with current GUA/ULA/Link-Local before services start.
        let if_state = Self::perform_initial_scan(&handle, &messages, target_ifindex, &ctx).await?;
        Self::log_welcome_banner(&cfg, &if_state);

        if let Ok(Some(stored_gua)) = db.load_last_gua_prefix() {
            info!("Restored stored GUA prefix from DB: {stored_gua}");
            let _ = ctx.signal_gua_prefix_change(target_ifindex, stored_gua, 7200, 7200);
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
        if db.is_in_memory() && !cfg.database.is_in_memory() {
            ctx.set_recovery_mode(true);
        }
        ctx.set_config_path(&cfg.config_path);
        ctx.set_config_writable(cfg.config_writable);

        let mut patch = ConfigPatch::new();

        #[cfg(feature = "dhcp")]
        {
            patch = patch
                .with_dhcp_v4_pools(cfg.dhcpv4_toml.pools.clone())
                .with_dhcp_v6_pools(cfg.dhcpv6_toml.pools.clone());
            if let Ok(Some(opts)) = db.load_dhcp_options() {
                patch = patch.with_dhcp_options(opts);
            }
        }
        #[cfg(feature = "ra")]
        {
            let ra_cfg = cfg.to_ra_config();
            let ra_srv = lanforge_types::network::ra::RaServerConfig {
                enabled: cfg.ra_toml.enabled,
                iface: Some(ra_cfg.iface),
                managed: ra_cfg.managed,
                other_config: ra_cfg.other_config,
                hop_limit: ra_cfg.hop_limit,
                priority: ra_cfg.priority,
                max_interval_secs: ra_cfg.max_interval.as_secs(),
                min_interval_secs: ra_cfg.min_interval.map(|d| d.as_secs()),
                lifetime_secs: ra_cfg.lifetime.map(|d| d.as_secs()),
                reachable_time_ms: ra_cfg.reachable_time,
                retrans_timer_ms: ra_cfg.retrans_timer,
                mtu: ra_cfg.mtu,
                prefixes: cfg.ra_toml.prefixes.clone(),
                rdnss: cfg.ra_toml.rdnss.clone(),
                dnssl: cfg.ra_toml.dnssl.clone(),
                deprecate_on_renumber: ra_cfg.deprecate_on_renumber,
            };
            patch = patch.with_ra_server(ra_srv);
        }

        #[cfg(feature = "dns")]
        Self::load_dns_state_into_patch(db, &mut patch);

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
    fn load_dns_state_into_patch(db: &LanforgeDb, patch: &mut ConfigPatch) {
        if let Ok(upstreams) = db.load_dns_upstreams() {
            let list = upstreams.into_iter().map(|row| row.to_target()).collect();
            patch.dns_upstreams = Some(list);
        }
        if let Ok(Some(mode)) = db.load_dns_upstream_mode() {
            patch.dns_upstream_mode = Some(mode);
        }
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
        let is_provisioned = Self::check_provisioning_mode(cfg, &db, user_count);

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

        // 2c. Check/reconcile DHCPv4 topology sanity against physical interface and host identity
        #[cfg(feature = "dhcp")]
        if is_provisioned {
            Self::reconcile_dhcp_v4_topology_sanity(&db, cfg, &table, host_ifaces);
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

    fn check_provisioning_mode(cfg: &mut Config, db: &LanforgeDb, user_count: i64) -> bool {
        let is_provisioned =
            db.is_provisioned().unwrap_or(false) || (user_count > 0) || cfg.system.auto_provision;

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
        Self::seed_dhcp_configs(db, cfg)?;

        #[cfg(feature = "ra")]
        Self::seed_ra_configs(db, cfg)?;

        #[cfg(feature = "dns")]
        Self::load_dns_config(db, cfg)?;

        #[cfg(feature = "pppoe")]
        Self::seed_pppoe_config(db, cfg)?;

        #[cfg(feature = "traffic")]
        Self::seed_traffic_config(db, cfg)?;

        #[cfg(feature = "nft")]
        Self::seed_firewall_config(db, cfg)?;

        Ok(())
    }

    #[cfg(feature = "dhcp")]
    fn seed_dhcp_configs(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        let mut seed_v4 = Vec::new();
        for mut pool in cfg.dhcpv4_toml.get_effective_pools() {
            if pool.lease_time.is_none() {
                pool.lease_time = Some(cfg.dhcpv4_toml.lease_time);
            }
            seed_v4.push(pool);
        }
        if seed_v4.is_empty() {
            use std::net::Ipv4Addr;

            seed_v4.push(Dhcpv4Pool {
                name: Some("Primary LAN Scope".to_string()),
                range_start: Ipv4Addr::new(192, 168, 1, 100),
                range_end: Ipv4Addr::new(192, 168, 1, 240),
                lease_time: Some(cfg.dhcpv4_toml.lease_time),
                router: Some(cfg.dhcpv4_toml.router),
                subnet_mask: Some(cfg.dhcpv4_toml.subnet_mask),
                dns_servers: cfg.dhcpv4_toml.dns.clone(),
                ..Default::default()
            });
        }
        if db.seed_dhcp_v4_if_empty(&seed_v4)? {
            info!(
                "Seeded {} DHCPv4 pools from configuration into database",
                seed_v4.len()
            );
        }
        cfg.dhcpv4_toml.pools = db.load_dhcp_v4_pools()?;
        cfg.dhcpv4_toml.range_start = None;
        cfg.dhcpv4_toml.range_end = None;

        let mut seed_v6 = Vec::new();
        for pool in &cfg.dhcpv6_toml.pools {
            let mut p = pool.clone();
            if p.lease_time.is_none() {
                p.lease_time = Some(cfg.dhcpv6_toml.lease_time);
            }
            seed_v6.push(p);
        }
        if db.seed_dhcp_v6_if_empty(&seed_v6)? {
            info!(
                "Seeded {} DHCPv6 pools from TOML configuration into database",
                seed_v6.len()
            );
        }
        cfg.dhcpv6_toml.pools = db.load_dhcp_v6_pools()?;

        let seed_opts = DhcpOptionsConfig {
            v4: Dhcpv4Options {
                enabled: cfg.dhcpv4_toml.enabled,
                lease_time: cfg.dhcpv4_toml.lease_time,
                router: Some(cfg.dhcpv4_toml.router),
                subnet_mask: Some(cfg.dhcpv4_toml.subnet_mask),
                dns_servers: cfg.dhcpv4_toml.dns.clone(),
                domain_name: cfg.dhcpv4_toml.domain_name.clone(),
                search_domains: cfg.dhcpv4_toml.search_domains.clone(),
                ntp_servers: cfg.dhcpv4_toml.ntp_servers.clone(),
                tftp_server: cfg.dhcpv4_toml.tftp_server.clone(),
                boot_file: cfg.dhcpv4_toml.boot_file.clone(),
                raw_options: cfg.dhcpv4_toml.options.clone(),
            },
            v6: Dhcpv6Options {
                enabled: cfg.dhcpv6_toml.enabled,
                lease_time: cfg.dhcpv6_toml.lease_time,
                dns_servers: cfg.dhcpv6_toml.dns_servers.clone(),
                search_domains: cfg.dhcpv6_toml.search_domains.clone(),
                ntp_servers: cfg.dhcpv6_toml.ntp_servers.clone(),
                boot_file: cfg.dhcpv6_toml.boot_file.clone(),
                raw_options: cfg.dhcpv6_toml.options.clone(),
            },
            #[cfg(feature = "tftp")]
            tftp: TftpOptions {
                enabled: cfg.tftp_toml.enabled,
                listen_addr: cfg.tftp_toml.listen.to_string(),
                root_dir: cfg.tftp_toml.root_dir.to_string_lossy().to_string(),
                block_size: cfg.tftp_toml.block_size,
                timeout: cfg.tftp_toml.timeout,
                max_retries: cfg.tftp_toml.max_retries,
            },
            #[cfg(not(feature = "tftp"))]
            tftp: TftpOptions::default(),
        };

        if db.seed_dhcp_options_if_empty(&seed_opts)? {
            info!("Seeded DHCP & TFTP scope options from configuration into database");
        }

        Ok(())
    }

    #[cfg(feature = "ra")]
    fn seed_ra_configs(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        if db.seed_ra_prefixes_if_empty(&cfg.ra_toml.prefixes)? {
            info!(
                "Seeded {} RA prefixes from TOML configuration into database",
                cfg.ra_toml.prefixes.len()
            );
        }
        cfg.ra_toml.prefixes = db.load_ra_prefixes()?;

        if db.seed_ra_rdnss_if_empty(&cfg.ra_toml.rdnss)? {
            info!(
                "Seeded {} RA RDNSS options from TOML configuration into database",
                cfg.ra_toml.rdnss.len()
            );
        }
        cfg.ra_toml.rdnss = db.load_ra_rdnss()?;

        if db.seed_ra_dnssl_if_empty(&cfg.ra_toml.dnssl)? {
            info!(
                "Seeded {} RA DNSSL options from TOML configuration into database",
                cfg.ra_toml.dnssl.len()
            );
        }
        cfg.ra_toml.dnssl = db.load_ra_dnssl()?;
        Ok(())
    }

    #[cfg(feature = "pppoe")]
    fn seed_pppoe_config(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        if db.seed_pppoe_if_empty(&cfg.pppoe_toml)? {
            info!("Seeded PPPoE configuration from TOML into database");
        }
        if let Some(loaded) = db.load_pppoe_config()? {
            cfg.pppoe_enabled = loaded.enabled;
            cfg.pppoe_toml = loaded;
        }
        Ok(())
    }

    #[cfg(feature = "traffic")]
    fn seed_traffic_config(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        if db.seed_traffic_if_empty(&cfg.traffic_toml)? {
            info!("Seeded Traffic configuration from TOML into database");
        }
        if let Some(loaded) = db.load_traffic_config()? {
            cfg.traffic_toml = loaded;
        }
        Ok(())
    }

    #[cfg(feature = "nft")]
    fn seed_firewall_config(db: &LanforgeDb, cfg: &mut Config) -> Result<()> {
        #[cfg(feature = "pppoe")]
        {
            if !cfg.pppoe_toml.nftables.flow_offload {
                cfg.firewall_toml.flow_offload = false;
            }
            if !cfg.pppoe_toml.nftables.bypass_dns {
                cfg.firewall_toml.bypass_dns = false;
            }
            if !cfg.pppoe_toml.nftables.bypass_vowifi {
                cfg.firewall_toml.bypass_vowifi = false;
            }
        }

        // Ensure primary LAN interface is included in internal zone
        if !cfg.system.iface.is_empty() {
            for zone in &mut cfg.firewall_toml.zones {
                if (zone.name == "internal" || zone.name == "lan")
                    && !zone.interfaces.contains(&cfg.system.iface)
                {
                    zone.interfaces.push(cfg.system.iface.clone());
                }
            }
        }

        if db.seed_firewall_if_empty(&cfg.firewall_toml)? {
            info!("Seeded Firewall configuration from TOML into database");
        }
        if let Some(mut loaded) = db.load_firewall_config()? {
            let mut modified = false;
            #[cfg(feature = "pppoe")]
            {
                if !cfg.pppoe_toml.nftables.flow_offload && loaded.flow_offload {
                    info!(
                        "Firewall bootstrap: disabling flow_offload to match existing PPPoE/SQM configuration"
                    );
                    loaded.flow_offload = false;
                    modified = true;
                }
            }
            #[cfg(feature = "traffic")]
            {
                if cfg.traffic_toml.sqm.enabled && loaded.flow_offload {
                    info!(
                        "Firewall bootstrap: disabling flow_offload because SQM (CAKE) traffic shaping is active"
                    );
                    loaded.flow_offload = false;
                    modified = true;
                }
            }
            // Auto-heal / assign primary LAN interface to internal zone if unassigned in any zone
            if !cfg.system.iface.is_empty() {
                let is_assigned = loaded
                    .zones
                    .iter()
                    .any(|z| z.interfaces.contains(&cfg.system.iface));
                if !is_assigned
                    && let Some(internal_zone) = loaded
                        .zones
                        .iter_mut()
                        .find(|z| z.name == "internal" || z.name == "lan")
                {
                    info!(
                        iface = %cfg.system.iface,
                        zone = %internal_zone.name,
                        "Firewall bootstrap: auto-assigning primary LAN interface to internal firewall zone"
                    );
                    internal_zone.interfaces.push(cfg.system.iface.clone());
                    modified = true;
                }
            }
            // Auto-heal / ensure trusted zone includes container wildcard "podman*"
            if let Some(trusted_zone) = loaded.zones.iter_mut().find(|z| z.name == "trusted") {
                if !trusted_zone
                    .interfaces
                    .iter()
                    .any(|i| i == "podman*" || i.starts_with("podman"))
                {
                    info!("Firewall bootstrap: adding 'podman*' wildcard to trusted firewall zone");
                    trusted_zone.interfaces.push("podman*".into());
                    modified = true;
                } else if !trusted_zone.interfaces.iter().any(|i| i == "podman*") {
                    info!(
                        "Firewall bootstrap: ensuring 'podman*' wildcard in trusted firewall zone"
                    );
                    trusted_zone.interfaces.push("podman*".into());
                    modified = true;
                }
            }
            if modified {
                let _ = db.save_firewall_config(&loaded);
            }
            cfg.firewall_enabled = loaded.enabled;
            cfg.firewall_toml = loaded;
        }
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
        db: &LanforgeDb,
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

        Self::audit_and_heal_dhcp_options(db, cfg, v4, iface_ip, iface_mask, prev_host_ip);
        Self::audit_and_heal_dhcp_pools(db, cfg, v4);
    }

    #[cfg(feature = "dhcp")]
    fn audit_and_heal_dhcp_options(
        db: &LanforgeDb,
        cfg: &Config,
        v4: Ipv4Network,
        iface_ip: std::net::Ipv4Addr,
        iface_mask: std::net::Ipv4Addr,
        prev_host_ip: Option<std::net::Ipv4Addr>,
    ) {
        let Ok(Some(mut opts)) = db.load_dhcp_options() else {
            return;
        };
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
                        "DHCPv4 Startup Sanity: Database gateway '{r}' is outside interface '{}' subnet ({}/{}). Auto-healing database to {iface_ip}.",
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
                "DHCPv4 Startup Sanity: Database subnet mask {:?} does not match interface '{}' mask {iface_mask}. Auto-healing database.",
                opts.v4.subnet_mask, cfg.system.iface
            );
            opts.v4.subnet_mask = Some(iface_mask);
            opts_modified = true;
        }

        if opts_modified {
            if let Err(e) = db.save_dhcp_options(&opts) {
                warn!(
                    "DHCPv4 Startup Sanity: Failed to persist auto-healed DHCP options to DB: {e}"
                );
            } else {
                info!("DHCPv4 Startup Sanity: Auto-healed DHCP options saved to database.");
            }
        }
    }

    #[cfg(feature = "dhcp")]
    fn audit_and_heal_dhcp_pools(db: &LanforgeDb, cfg: &mut Config, v4: Ipv4Network) {
        if cfg.dhcpv4_toml.pools.is_empty() {
            return;
        }
        let any_in_subnet = cfg
            .dhcpv4_toml
            .pools
            .iter()
            .any(|p| v4.contains(p.range_start) && v4.contains(p.range_end));

        if !any_in_subnet {
            warn!(
                "DHCPv4 Startup Sanity: Stored DHCPv4 pools are outside interface '{}' subnet ({}). Auto-healing dynamic pools in database.",
                cfg.system.iface, v4
            );
            let derived = derive_dhcp_defaults_from_v4(&v4);
            let healed_pool = Dhcpv4Pool {
                name: Some("Auto-Healed LAN Scope".to_string()),
                range_start: derived.range_start,
                range_end: derived.range_end,
                lease_time: Some(cfg.dhcpv4_toml.lease_time),
                router: Some(derived.router),
                subnet_mask: Some(derived.subnet_mask),
                dns_servers: vec![derived.router],
                ..Default::default()
            };
            cfg.dhcpv4_toml.pools = vec![healed_pool];
            if let Err(e) = db.save_dhcp_v4_pools(&cfg.dhcpv4_toml.pools) {
                warn!("DHCPv4 Startup Sanity: Failed to persist auto-healed pools to DB: {e}");
            } else {
                info!("DHCPv4 Startup Sanity: Auto-healed dynamic pools saved to database.");
            }
        }
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
