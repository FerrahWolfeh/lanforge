use anyhow::Result;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use std::net::Ipv6Addr;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use tracing::{debug, info};

use crate::bootstrap::BootstrapResult;
use crate::config::Config;
use crate::event_loop::run_event_loop;
use crate::registry::ServiceRegistry;
use lanforge_api::http::HttpService;
use lanforge_api::server::ControlService;
use lanforge_db::worker::DbWorker;
use lanforge_dns::server::DnsService;
use lanforge_network::dhcp::v4::Dhcpv4Service;
use lanforge_network::dhcp::v6::Dhcpv6Service;
use lanforge_network::ifmon::InterfaceMonitor;
use lanforge_network::mdns::MdnsProber;
use lanforge_network::netlink::NdpMonitor;
use lanforge_network::ra::RaService;

/// The central application controller for the Lanforge daemon.
pub struct Daemon {
    bootstrap: BootstrapResult,
    registry: ServiceRegistry,
}

impl Daemon {
    /// Creates a new Daemon instance from a bootstrap result.
    pub const fn new(bootstrap: BootstrapResult) -> Self {
        Self {
            bootstrap,
            registry: ServiceRegistry::new(),
        }
    }

    /// Runs the daemon's main execution cycle.
    ///
    /// This method performs the following steps:
    /// 1. Subscribes to the event bus (captured in the main thread).
    /// 2. Spawns all configured services.
    /// 3. Executes the main event loop.
    /// 4. Handles graceful shutdown.
    pub async fn run(mut self) -> Result<()> {
        let bus = self.bootstrap.bus.clone();

        // 1. Subscribe to bus BEFORE spawning services to capture all ServiceReady events
        let bus_rx = bus.subscribe();

        // 2. Register and Spawn Services
        self.spawn_services();

        // 3. Run Event Loop
        run_event_loop(self.bootstrap.clone(), bus_rx).await?;

        // 4. Shutdown Sequence
        self.shutdown().await
    }

    fn spawn_services(&mut self) {
        let cfg = &self.bootstrap.cfg;
        let target_ifindex = self.bootstrap.target_ifindex;
        let netlink_handle = &self.bootstrap.rt_handle;
        let messages = &self.bootstrap.messages;

        // DB Worker (Sync)
        let db_path = std::path::PathBuf::from(&cfg.leases_db);
        let log_db_path = std::path::PathBuf::from(&cfg.log_db);
        self.registry
            .spawn_sync(move || DbWorker::new(db_path.clone(), log_db_path.clone()));

        // mDNS Prober (Async)
        self.registry.spawn_async(MdnsProber::new);

        // Interface Monitor (Async)
        let h1 = netlink_handle.clone();
        let m1 = messages.clone();
        self.registry
            .spawn_async(move || InterfaceMonitor::new(h1.clone(), m1.clone(), target_ifindex));

        // Ndp Monitor (Async)
        let h2 = netlink_handle.clone();
        let m2 = messages.clone();
        self.registry
            .spawn_async(move || NdpMonitor::new(h2.clone(), m2.clone(), target_ifindex));

        // RA Service (Async)
        if cfg.ra_enabled {
            let ra_cfg = cfg.to_ra_config();
            self.registry
                .spawn_async(move || RaService::new(ra_cfg.clone()));
        }

        // DHCPv4 Service (Sync)
        if cfg.dhcpv4_enabled {
            let d4_cfg = cfg.to_dhcpv4_config();
            self.registry
                .spawn_sync(move || Dhcpv4Service::new(d4_cfg.clone()));
        }

        // DHCPv6 Service (Sync)
        if cfg.dhcpv6_enabled {
            let d6_cfg = cfg.to_dhcpv6_config();
            self.registry
                .spawn_sync(move || Dhcpv6Service::new(d6_cfg.clone()));
        }

        // DNS Service (Async)
        if cfg.dns_enabled {
            let dns_cfg = cfg.to_dns_config();
            self.registry
                .spawn_async(move || DnsService::new(dns_cfg.clone()));
        }

        // API & Control Services
        let api_cfg = Arc::new(cfg.to_api_config());

        let api_cfg_ctrl = api_cfg.clone();
        self.registry
            .spawn_async(move || ControlService::new(api_cfg_ctrl.clone()));

        if cfg.http_listen.is_some() {
            let api_cfg_http = api_cfg;
            self.registry
                .spawn_async(move || HttpService::new(api_cfg_http.clone()));
        }
    }

    async fn shutdown(self) -> Result<()> {
        info!("🛑 Iniciando sequência de shutdown...");
        LanforgeContext::terminate();
        let _ = self.bootstrap.bus.publish(LanforgeEvent::Shutdown);

        // Wait for all services to stop (with timeout)
        tokio::select! {
            _ = tokio::task::spawn_blocking(move || self.registry.wait_all()) => {
                info!("All services shut down cleanly.");
            }
            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                info!("Shutdown timeout reached, exiting.");
            }
        }

        info!("👋 Lanforge encerrado.");
        Ok(())
    }
}

/// Helper public functions needed by modules
pub async fn run_scan(
    cfg: &Config,
    handle: &rtnetlink::Handle,
    gua: Option<Ipv6Addr>,
    ula: Option<Ipv6Addr>,
    target_ifindex: u32,
) -> Result<()> {
    lanforge_network::slaac::bootstrap_table(
        &cfg.target_prefix,
        handle,
        gua,
        ula,
        Some(target_ifindex),
    )
    .await
    .map_err(anyhow::Error::from)
}

pub fn sd_notify_ready() {
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        debug!("systemd: Notificando READY=1 via {}", path);
        if let Ok(sock) = UnixDatagram::unbound()
            && sock.connect(path).is_ok()
        {
            let _ = sock.send(b"READY=1\n");
        }
    }
}
