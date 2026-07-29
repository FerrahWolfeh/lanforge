use anyhow::Result;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_db::DynamicConfigStore;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_host::ifmon::AddressMonitor;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::AdblockUrlEntry;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::adblock::AdblockUrlKind;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::{Ipv6AddrOrSuffix, Ipv6Prefix};
use lanforge_types::update::InterfaceState;
use netlink_sys::SocketAddr;
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use rtnetlink::new_connection;
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_route::RouteNetlinkMessage;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::config::Config;

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
    #[allow(clippy::too_many_lines)]
    pub async fn run() -> Result<(BootstrapResult, LanforgeContext)> {
        // --- PHASE 1: Initialization ---
        let mut cfg = Config::load();

        let ra_print = {
            #[cfg(feature = "ra")]
            {
                cfg.ra_enabled
            }
            #[cfg(not(feature = "ra"))]
            {
                false
            }
        };
        let dhcpv4_print = {
            #[cfg(feature = "dhcp")]
            {
                cfg.dhcpv4_enabled
            }
            #[cfg(not(feature = "dhcp"))]
            {
                false
            }
        };
        let dhcpv6_print = {
            #[cfg(feature = "dhcp")]
            {
                cfg.dhcpv6_enabled
            }
            #[cfg(not(feature = "dhcp"))]
            {
                false
            }
        };
        let dns_print = {
            #[cfg(feature = "dns")]
            {
                cfg.dns_enabled
            }
            #[cfg(not(feature = "dns"))]
            {
                false
            }
        };

        info!(
            "🚀 Starting Lanforge (RA: {}, DHCPv4: {}, DHCPv6: {}, DNS: {})",
            ra_print, dhcpv4_print, dhcpv6_print, dns_print
        );

        let bus = Arc::new(EventBus::new());
        let (initial_table, db, log_db) = Self::init_device_table(&mut cfg).await?;
        let db = Arc::new(db);
        let log_db = Arc::new(log_db);
        let cfg = Arc::new(cfg);

        let target_ifindex = Self::find_target_interface(&cfg)?;
        let ctx = LanforgeContext::new(bus.clone(), initial_table, Some(target_ifindex));
        #[cfg(feature = "dhcp")]
        {
            ctx.update_dhcp_v4_pools(cfg.dhcpv4_toml.pools.clone());
            ctx.update_dhcp_v6_pools(cfg.dhcpv6_toml.pools.clone());
        }
        #[cfg(feature = "ra")]
        ctx.update_ra_config(
            cfg.ra_toml.prefixes.clone(),
            cfg.ra_toml.rdnss.clone(),
            cfg.ra_toml.dnssl.clone(),
        );
        ctx.set_status(cfg.to_system_status());

        // Load DNS settings from database into context
        #[cfg(feature = "dns")]
        {
            if let Ok(upstreams) = db.load_dns_upstreams().await {
                let mut list = Vec::new();
                for row in upstreams {
                    let proto_lower = row.protocol.to_lowercase();
                    let prefix = row.domain.as_ref().map_or_else(
                        || format!("{proto_lower}://"),
                        |d| format!("{proto_lower}://{d}@"),
                    );
                    let full_str = format!("{prefix}{}", row.addr);
                    if let Ok(target) = <UpstreamTarget as std::str::FromStr>::from_str(&full_str) {
                        list.push(target);
                    }
                }
                ctx.update_dns_upstreams(list);
            }
            if let Ok(rewrites) = db.load_dns_rewrites().await {
                ctx.update_dns_rewrites(rewrites);
            }
            if let Ok(allowlist) = db.load_dns_allowlist().await {
                ctx.update_dns_allowlist(allowlist.into_iter().map(|(_, d)| d).collect());
            }
            if let Ok(adblock) = db.load_adblock_config().await {
                ctx.update_dns_adblock(adblock);
            }
            if let Ok(urls) = db.load_adblock_urls().await {
                ctx.update_dns_adblock_urls(
                    urls.into_iter()
                        .map(|(id, url, kind)| AdblockUrlEntry {
                            id: Some(id),
                            url,
                            kind,
                        })
                        .collect(),
                );
            }
        }

        let _ = bus.publish(LanforgeEvent::System(SystemEvent::StateReady));

        // --- PHASE 2: Netlink Setup ---
        let (handle, messages_rx) = Self::init_netlink()?;
        let (tx, _rx) = broadcast::channel(NETLINK_BROADCAST_CAPACITY);
        let messages = tx.clone();

        // Netlink Dispatcher Task
        let dispatcher_tx = tx.clone();
        tokio::spawn(async move {
            let mut rx = messages_rx;
            while let Some(msg) = rx.next().await {
                if dispatcher_tx.send(msg).is_err() {
                    // All receivers dropped — this is expected during shutdown,
                    // but we log it once if the dispatcher is still running.
                    debug!("Netlink dispatcher: zero active subscribers");
                }
            }
        });

        // --- PHASE 3: Initial Scan ---
        // Crucial: updates ctx with current GUA/ULA/Link-Local before services start.
        let if_state = Self::perform_initial_scan(&handle, &messages, target_ifindex, &ctx).await?;
        Self::log_welcome_banner(&cfg, &if_state);

        ctx.set_if_ready(true);
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::InterfaceReady));

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

    #[cfg(feature = "dhcp")]
    async fn load_dhcp4_pools<D: DynamicConfigStore>(db: &D, cfg: &mut Config) -> Result<()> {
        let v4_pools = db.load_dhcp_v4_pools().await?;
        if v4_pools.is_empty() {
            let mut seed = Vec::new();
            for mut pool in cfg.dhcpv4_toml.get_effective_pools() {
                if pool.lease_time.is_none() {
                    pool.lease_time = Some(cfg.dhcpv4_toml.lease_time);
                }
                seed.push(pool);
            }
            db.save_dhcp_v4_pools(&seed).await?;
            info!(
                "Seeded {} DHCPv4 pools from TOML configuration into database",
                seed.len()
            );
        }
        cfg.dhcpv4_toml.pools = db.load_dhcp_v4_pools().await?;
        Ok(())
    }

    #[cfg(feature = "dhcp")]
    async fn load_dhcp6_pools<D: DynamicConfigStore>(db: &D, cfg: &mut Config) -> Result<()> {
        let v6_pools = db.load_dhcp_v6_pools().await?;
        if v6_pools.is_empty() {
            let mut seed = Vec::new();
            for pool in &cfg.dhcpv6_toml.pools {
                let mut p = pool.clone();
                if p.lease_time.is_none() {
                    p.lease_time = Some(cfg.dhcpv6_toml.lease_time);
                }
                seed.push(p);
            }
            db.save_dhcp_v6_pools(&seed).await?;
            info!(
                "Seeded {} DHCPv6 pools from TOML configuration into database",
                seed.len()
            );
        }
        cfg.dhcpv6_toml.pools = db.load_dhcp_v6_pools().await?;
        Ok(())
    }

    #[cfg(feature = "ra")]
    async fn load_ra_prefix<D: DynamicConfigStore>(db: &D, cfg: &mut Config) -> Result<()> {
        let ra_prefixes = db.load_ra_prefixes().await?;
        if ra_prefixes.is_empty() {
            db.save_ra_prefixes(&cfg.ra_toml.prefixes).await?;
            info!(
                "Seeded {} RA prefixes from TOML configuration into database",
                cfg.ra_toml.prefixes.len()
            );
        }
        cfg.ra_toml.prefixes = db.load_ra_prefixes().await?;
        Ok(())
    }

    #[cfg(feature = "ra")]
    async fn load_ra_rdnss<D: DynamicConfigStore>(db: &D, cfg: &mut Config) -> Result<()> {
        let ra_rdnss = db.load_ra_rdnss().await?;
        if ra_rdnss.is_empty() {
            db.save_ra_rdnss(&cfg.ra_toml.rdnss).await?;
            info!(
                "Seeded {} RA RDNSS options from TOML configuration into database",
                cfg.ra_toml.rdnss.len()
            );
        }
        cfg.ra_toml.rdnss = db.load_ra_rdnss().await?;
        Ok(())
    }

    #[cfg(feature = "ra")]
    async fn load_ra_dnssl<D: DynamicConfigStore>(db: &D, cfg: &mut Config) -> Result<()> {
        let ra_dnssl = db.load_ra_dnssl().await?;
        if ra_dnssl.is_empty() {
            db.save_ra_dnssl(&cfg.ra_toml.dnssl).await?;
            info!(
                "Seeded {} RA DNSSL options from TOML configuration into database",
                cfg.ra_toml.dnssl.len()
            );
        }
        cfg.ra_toml.dnssl = db.load_ra_dnssl().await?;
        Ok(())
    }

    #[cfg(feature = "pppoe")]
    async fn load_pppoe_config<D: DynamicConfigStore>(db: &D, cfg: &mut Config) -> Result<()> {
        let pppoe_cfg = db.load_pppoe_config().await?;
        if let Some(loaded) = pppoe_cfg {
            cfg.pppoe_toml = loaded;
        } else {
            db.save_pppoe_config(&cfg.pppoe_toml).await?;
            info!("Seeded PPPoE configuration from TOML into database");
        }
        Ok(())
    }

    #[cfg(feature = "dns")]
    async fn load_dns_config(db: &LanforgeDb, cfg: &Config) -> Result<()> {
        // Seed upstreams if empty in DB
        let upstreams = db.load_dns_upstreams().await?;
        if upstreams.is_empty() && !cfg.dns_toml.upstreams.is_empty() {
            for entry in &cfg.dns_toml.upstreams {
                let target = &entry.target;
                let _ = db
                    .add_dns_upstream(
                        &target.addr.to_string(),
                        &target.protocol.to_string(),
                        target.hostname.as_deref(),
                    )
                    .await?;
            }
            info!(
                "Seeded {} DNS upstreams from configuration into database",
                cfg.dns_toml.upstreams.len()
            );
        }

        // Seed rewrites if empty in DB
        let rewrites = db.load_dns_rewrites().await?;
        if rewrites.is_empty() && !cfg.dns_toml.rewrites.is_empty() {
            for rule in &cfg.dns_toml.rewrites {
                db.upsert_dns_rewrite(&rule.domain, rule.rtype, &rule.answer.to_string())
                    .await?;
            }
            info!(
                "Seeded {} DNS rewrites from configuration into database",
                cfg.dns_toml.rewrites.len()
            );
        }

        // Seed allowlist if empty in DB
        let allowlist = db.load_dns_allowlist().await?;
        if allowlist.is_empty() && !cfg.dns_toml.allowlist.is_empty() {
            for domain in &cfg.dns_toml.allowlist {
                db.add_dns_allowlist(domain).await?;
            }
            info!(
                "Seeded {} DNS allowlist domains from configuration into database",
                cfg.dns_toml.allowlist.len()
            );
        }

        // Seed adblock urls if empty in DB
        let adblock_urls = db.load_adblock_urls().await?;
        let is_new_adblock = adblock_urls.is_empty();
        if is_new_adblock {
            let mut count = 0;
            for url in &cfg.dns_toml.adblock_urls {
                db.add_adblock_url(url, AdblockUrlKind::Blocklist).await?;
                count += 1;
            }
            for url in &cfg.dns_toml.adblock_allowlist_urls {
                db.add_adblock_url(url, AdblockUrlKind::Allowlist).await?;
                count += 1;
            }
            if count > 0 {
                info!("Seeded {count} Adblock source URLs from configuration into database");
            }

            // Seed adblock config overrides from TOML on first run
            db.set_adblock_config_value(
                "enabled",
                if cfg.dns_toml.adblock_enabled {
                    "true"
                } else {
                    "false"
                },
            )
            .await?;
            db.set_adblock_config_value("blocking_mode", &cfg.dns_toml.blocking_mode.to_string())
                .await?;
            if let Some(ip) = cfg.dns_toml.blocking_ip_v4 {
                db.set_adblock_config_value("blocking_ip_v4", &ip.to_string())
                    .await?;
            }
            if let Some(ip) = cfg.dns_toml.blocking_ip_v6 {
                db.set_adblock_config_value("blocking_ip_v6", &ip.to_string())
                    .await?;
            }
            db.set_adblock_config_value(
                "refresh_hours",
                &cfg.dns_toml.adblock_refresh_hours.to_string(),
            )
            .await?;
            db.set_adblock_config_value(
                "refresh_at_night",
                if cfg.dns_toml.adblock_refresh_at_night {
                    "true"
                } else {
                    "false"
                },
            )
            .await?;
        }

        Ok(())
    }

    async fn init_device_table(cfg: &mut Config) -> Result<(State, LanforgeDb, LogDb)> {
        let db = LanforgeDb::open(&cfg.database).await.map_err(|e| {
            error!("❌ Erro fatal abrindo leases DB: {e}");
            e
        })?;

        let log_db = LogDb::open(&cfg.database.log_url).await.map_err(|e| {
            error!("❌ Erro fatal abrindo logs DB: {e}");
            e
        })?;

        // 1. Check/seed/load DHCPv4 Pools
        #[cfg(feature = "dhcp")]
        {
            Self::load_dhcp4_pools(&db, cfg).await?;
            cfg.dhcpv4_toml.range_start = None;
            cfg.dhcpv4_toml.range_end = None;
        }

        // 2. Check/seed/load DHCPv6 Pools
        #[cfg(feature = "dhcp")]
        Self::load_dhcp6_pools(&db, cfg).await?;

        // 3. Check/seed/load RA Prefixes
        #[cfg(feature = "ra")]
        Self::load_ra_prefix(&db, cfg).await?;

        // 4. Check/seed/load RA RDNSS
        #[cfg(feature = "ra")]
        Self::load_ra_rdnss(&db, cfg).await?;

        // 5. Check/seed/load RA DNSSL
        #[cfg(feature = "ra")]
        Self::load_ra_dnssl(&db, cfg).await?;

        // 6. Check/seed/load DNS Config
        #[cfg(feature = "dns")]
        Self::load_dns_config(&db, cfg).await?;

        // 7. Check/seed/load PPPoE Config
        #[cfg(feature = "pppoe")]
        Self::load_pppoe_config(&db, cfg).await?;

        let mut table = db.load_table().await.unwrap_or_else(|e| {
            warn!("Falha ao carregar DB ({e}), iniciando do zero");
            State::new()
        });

        match db.load_dns_reverse_resolvers().await {
            Ok(resolvers) => {
                info!(
                    "Loaded {} DNS reverse resolvers from database",
                    resolvers.len()
                );
                table.reverse_resolvers = resolvers;
            }
            Err(e) => {
                warn!("Failed to load reverse resolvers from database: {e}");
            }
        }

        info!(
            "📦 Databases initialized (Main: {}, Logs: {})",
            crate::config::sanitize_db_url(&cfg.database.url),
            crate::config::sanitize_db_url(&cfg.database.log_url)
        );
        Self::inject_self_device(&mut table, cfg);

        // Trigger early collision validation and logging
        let _ = table.get_static_registry();

        Ok((table, db, log_db))
    }

    /// Injects the host machine as a system device in the state table.
    fn inject_self_device(table: &mut State, cfg: &Config) {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map_or_else(|_| "lanforge".to_string(), |s| s.trim().to_string());

        let interfaces = interfaces();
        if let Some(iface) = interfaces.iter().find(|i| i.name == cfg.system.iface)
            && let Some(mac) = iface.mac
        {
            let mac = MacAddr(mac.octets());
            info!(
                "⚙️ Self-Resolution: Injecting system device '{}' ({})",
                hostname, mac
            );

            // Use current V4 if available to seed the device
            let v4_static = iface.ips.iter().find_map(|ip| {
                if let IpNetwork::V4(v4) = ip {
                    Some(v4.ip())
                } else {
                    None
                }
            });

            table.add_static_device(
                mac,
                hostname,
                None, // DUID not required for the host itself here
                v4_static,
                None, // V6 suffix will be picked up by scan
                None,
                Origin::System,
            );
        }
    }

    fn find_target_interface(cfg: &Config) -> Result<u32> {
        let interfaces = interfaces();
        interfaces
            .iter()
            .find(|iface| iface.name == cfg.system.iface)
            .map(|iface| iface.index)
            .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", cfg.system.iface))
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
        messages: &NetlinkMessages,
        target_ifindex: u32,
        ctx: &LanforgeContext,
    ) -> Result<InterfaceState> {
        let ifmon_init = AddressMonitor::new(
            handle.clone(),
            messages.subscribe(),
            target_ifindex,
            ctx.clone(),
        );
        ifmon_init
            .initial_scan()
            .await
            .map_err(|e| anyhow::anyhow!("Initial interface scan failed: {e}"))
    }

    fn log_welcome_banner(cfg: &Config, if_state: &InterfaceState) {
        info!("╔══════════════════════════════════════════╗");
        info!("║         Lanforge Network Daemon          ║");
        info!("╠══════════════════════════════════════════╣");
        info!("║  Interface : {:<27} ║", cfg.system.iface);
        if let Some(ll) = if_state.link_local {
            info!("║  Link-Local: {:<27} ║", ll);
        }
        if let Some(gua) = if_state.gua {
            info!(
                "║  GUA Prefix: {:<27} ║",
                Ipv6Prefix::from_addr(gua).to_string()
            );
        }
        info!("╚══════════════════════════════════════════╝");
    }

    /// Reloads static devices from configuration into the provided state table.
    pub fn reload_static_devices_into_state(table: &mut State, cfg: &Config) {
        for dev in &cfg.devices {
            let Some(mac) = MacAddr::parse(&dev.mac) else {
                warn!("Invalid MAC '{}' in config", dev.mac);
                continue;
            };
            let v4 = dev.v4_ip.as_ref().and_then(|s| s.parse().ok());
            let duid = dev.duid.as_ref().and_then(|s| s.parse().ok());
            let v6_suffix = dev
                .v6_suffix
                .as_ref()
                .and_then(|s| Ipv6AddrOrSuffix::parse(s));

            table.add_static_device(
                mac,
                dev.hostname.clone(),
                duid,
                v4,
                v6_suffix,
                dev.boot_file.clone(),
                Origin::Static,
            );
        }
    }
}
