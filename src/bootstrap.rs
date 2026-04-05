use anyhow::Result;
use futures::channel::mpsc::UnboundedReceiver;
use lanforge_core::bus::{EventBus, LanforgeEvent, ManagedTable};
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::DeviceTable;
use lanforge_db::engine::LeaseDb;
use lanforge_network::ifmon::InterfaceMonitor;
use netlink_sys::SocketAddr;
use rtnetlink::constants::RTMGRP_NEIGH;
use rtnetlink::new_connection;
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_route::RouteNetlinkMessage;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::{Config, load_devices_only};

const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV6_IFADDR: u32 = 9;

type NetlinkMessages = UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

#[derive(Clone)]
pub struct BootstrapResult {
    pub cfg: Arc<Config>,
    pub bus: Arc<EventBus>,
    pub table: Arc<ManagedTable>,
    pub rt_handle: rtnetlink::Handle,
    pub messages: Arc<Mutex<NetlinkMessages>>,
    pub target_ifindex: u32,
}

/// Orchestrates the initial state of the Lanforge daemon.
pub struct Bootstrapper;

impl Bootstrapper {
    /// Executes the full bootstrap sequence.
    pub async fn run() -> Result<BootstrapResult> {
        let cfg = Arc::new(Self::load_config());

        info!(
            "🚀 Starting Lanforge (RA: {}, DHCPv4: {}, DHCPv6: {}, DNS: {})",
            cfg.ra_enabled, cfg.dhcpv4_enabled, cfg.dhcpv6_enabled, cfg.dns_enabled
        );

        let bus = Arc::new(EventBus::new());
        let initial_table = Self::init_device_table(&cfg)?;

        let target_ifindex = Self::find_target_interface(&cfg)?;

        let table = Arc::new(ManagedTable::from_table(
            bus.clone(),
            initial_table,
            Some(target_ifindex),
        ));

        LanforgeContext::init(bus.clone(), table.clone());
        let _ = bus.publish(LanforgeEvent::StateReady);

        let (handle, messages) = Self::init_netlink()?;
        let messages = Arc::new(Mutex::new(messages));

        let if_state = Self::perform_initial_scan(&handle, &messages, target_ifindex).await?;
        Self::log_welcome_banner(&cfg, &if_state);

        LanforgeContext::set_if_ready(true);
        let _ = bus.publish(LanforgeEvent::InterfaceReady);

        Ok(BootstrapResult {
            cfg,
            bus,
            table,
            rt_handle: handle,
            messages,
            target_ifindex,
        })
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

    fn init_device_table(cfg: &Config) -> Result<DeviceTable> {
        let leases_db_path = std::path::PathBuf::from(&cfg.leases_db);

        let mut table = match LeaseDb::open(&leases_db_path) {
            Ok(db) => match db.load_table() {
                Ok(persisted) => {
                    info!("📦 Database loaded: {}", cfg.leases_db);
                    persisted
                }
                Err(e) => {
                    warn!("Falha ao carregar DB ({e}), iniciando do zero");
                    DeviceTable::new()
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
                table.add_static_device(mac, e.hostname.clone(), v4_ip, v6_suffix);
            }
        }

        // Trigger early collision validation and logging
        let _ = table.get_static_registry();

        Ok(table)
    }

    fn find_target_interface(cfg: &Config) -> Result<u32> {
        let interfaces = pnet::datalink::interfaces();
        interfaces
            .iter()
            .find(|iface| iface.name == cfg.iface_lan)
            .map(|iface| iface.index)
            .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", cfg.iface_lan))
    }

    fn init_netlink() -> Result<(rtnetlink::Handle, NetlinkMessages)> {
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
        messages: &Arc<Mutex<NetlinkMessages>>,
        target_ifindex: u32,
    ) -> Result<lanforge_core::state::InterfaceState> {
        let ifmon_init = InterfaceMonitor::new(handle.clone(), messages.clone(), target_ifindex);
        ifmon_init
            .initial_scan()
            .await
            .map_err(|e| anyhow::anyhow!("Initial interface scan failed: {e}"))
    }

    fn log_welcome_banner(cfg: &Config, if_state: &lanforge_core::state::InterfaceState) {
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
