use anyhow::Result;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use lanforge_core::bus::{EventBus, LanforgeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::{InterfaceState, State};
use lanforge_db::engine::LeaseDb;
use lanforge_network::ifmon::InterfaceMonitor;
use netlink_sys::SocketAddr;
use pnet::datalink::interfaces;
use rtnetlink::constants::RTMGRP_NEIGH;
use rtnetlink::new_connection;
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_route::RouteNetlinkMessage;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::config::{Config, load_devices_only};

const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV6_IFADDR: u32 = 9;

type NetlinkRawMessage = (NetlinkMessage<RouteNetlinkMessage>, SocketAddr);
type NetlinkMessages = broadcast::Sender<NetlinkRawMessage>;
type NetlinkRawReceiver = UnboundedReceiver<NetlinkRawMessage>;

const NETLINK_BROADCAST_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct BootstrapResult {
    pub cfg: Arc<Config>,
    pub rt_handle: rtnetlink::Handle,
    pub messages: NetlinkMessages,
    pub target_ifindex: u32,
}

/// Orchestrates the initial state of the Lanforge daemon.
pub struct Bootstrapper;

impl Bootstrapper {
    /// Executes the full bootstrap sequence.
    pub async fn run() -> Result<(BootstrapResult, LanforgeContext)> {
        let cfg = Arc::new(Self::load_config());

        info!(
            "🚀 Starting Lanforge (RA: {}, DHCPv4: {}, DHCPv6: {}, DNS: {})",
            cfg.ra_enabled, cfg.dhcpv4_enabled, cfg.dhcpv6_enabled, cfg.dns_enabled
        );

        let bus = Arc::new(EventBus::new());
        let initial_table = Self::init_device_table(&cfg)?;

        let target_ifindex = Self::find_target_interface(&cfg)?;
        let ctx = LanforgeContext::new(bus.clone(), initial_table, Some(target_ifindex));
        let _ = bus.publish(LanforgeEvent::StateReady);

        let (handle, messages_rx) = Self::init_netlink()?;
        let (tx, _rx) = broadcast::channel(NETLINK_BROADCAST_CAPACITY);
        let messages = tx.clone();

        // Netlink Dispatcher Task
        let dispatcher_tx = tx.clone();
        tokio::spawn(async move {
            let mut rx = messages_rx;
            while let Some(msg) = rx.next().await {
                if dispatcher_tx.send(msg).is_err() {
                    // All receivers dropped, but keep dispatcher alive if possible?
                    // Actually, if all dropped, nothing to do.
                }
            }
        });

        let if_state = Self::perform_initial_scan(&handle, &messages, target_ifindex, &ctx).await?;
        Self::log_welcome_banner(&cfg, &if_state);

        ctx.set_if_ready(true);
        let _ = bus.publish(LanforgeEvent::InterfaceReady);

        Ok((
            BootstrapResult {
                cfg,
                rt_handle: handle,
                messages,
                target_ifindex,
            },
            ctx,
        ))
    }

    fn load_config() -> Config {
        #[cfg(feature = "debug-commands")]
        let mut cfg = Config::load();

        #[cfg(not(feature = "debug-commands"))]
        let cfg = Config::load();

        #[cfg(feature = "debug-commands")]
        if let crate::config::Command::Run { only: Some(s) } = &cfg.command {
            let modules: Vec<&str> = s.split(',').collect();
            cfg.ra_enabled = modules.contains(&"ra");
            cfg.dhcpv4_enabled = modules.contains(&"dhcpv4") || modules.contains(&"dhcp");
            cfg.dhcpv6_enabled = modules.contains(&"dhcpv6") || modules.contains(&"dhcp");
            cfg.dns_enabled = modules.contains(&"dns");
            info!("🎯 Running ONLY (Debug Mode): {:?}", modules);
        }

        cfg
    }

    fn init_device_table(cfg: &Config) -> Result<State> {
        let leases_db_path = PathBuf::from(&cfg.leases_db);

        let mut table = match LeaseDb::open(&leases_db_path) {
            Ok(db) => match db.load_table() {
                Ok(persisted) => {
                    info!("📦 Database loaded: {}", cfg.leases_db);
                    persisted
                }
                Err(e) => {
                    warn!("Falha ao carregar DB ({e}), iniciando do zero");
                    State::new()
                }
            },
            Err(e) => {
                error!("❌ Erro fatal abrindo leases DB: {e}");
                return Err(e.into());
            }
        };

        // Load static devices
        let mut all_static_devices = cfg.devices.clone();
        if let Some(ref extra_path) = cfg.devices_file {
            info!("📂 Carregando devices adicionais de {extra_path}");
            let mut extra = load_devices_only(extra_path);
            all_static_devices.append(&mut extra);
        }

        for e in &all_static_devices {
            if let Some(mac) = MacAddr::parse(&e.mac) {
                let v4_ip = e.v4_ip.as_ref().and_then(|s| s.parse().ok());
                let v6_suffix = e
                    .v6_suffix
                    .as_ref()
                    .and_then(|s| Ipv6AddrOrSuffix::parse(s));
                let duid = e.duid.as_ref().and_then(|s| s.parse().ok());
                table.add_static_device(mac, e.hostname.clone(), duid, v4_ip, v6_suffix);
            }
        }

        // Trigger early collision validation and logging
        let _ = table.get_static_registry();

        Ok(table)
    }

    fn find_target_interface(cfg: &Config) -> Result<u32> {
        let interfaces = interfaces();
        interfaces
            .iter()
            .find(|iface| iface.name == cfg.iface_lan)
            .map(|iface| iface.index)
            .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", cfg.iface_lan))
    }

    fn init_netlink() -> Result<(rtnetlink::Handle, NetlinkRawReceiver)> {
        use netlink_sys::AsyncSocket;

        let (mut connection, handle, messages) = new_connection()?;
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTMGRP_NEIGH)?;
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
        let ifmon_init = InterfaceMonitor::new(
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
        info!("║  Interface : {:<27} ║", cfg.iface_lan);
        if let Some(ll) = if_state.link_local {
            info!("║  Link-Local: {:<27} ║", ll);
        }
        if let Some(gua) = if_state.gua {
            info!("║  GUA Prefix: {:<24}/64 ║", gua);
        }
        info!("╚══════════════════════════════════════════╝");
    }
}
