use anyhow::Result;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_network::slaac::bootstrap_table;
use std::net::Ipv6Addr;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
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
use lanforge_network::ndp::NeighborMonitor;
use lanforge_network::ra::RaService;

/// The central application controller for the Lanforge daemon.
pub struct Daemon {
    bootstrap: BootstrapResult,
    registry: ServiceRegistry,
    ctx: LanforgeContext,
}

impl Daemon {
    /// Creates a new Daemon instance from a bootstrap result and context.
    pub const fn new(bootstrap: BootstrapResult, ctx: LanforgeContext) -> Self {
        Self {
            bootstrap,
            registry: ServiceRegistry::new(),
            ctx,
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
        let bus = self.ctx.bus();

        // 1. Subscribe to bus BEFORE spawning services to capture all ServiceReady events
        let bus_rx = bus.subscribe();

        // 2. Register and Spawn Services
        self.spawn_services();

        // 3. Run Event Loop
        run_event_loop(self.bootstrap.clone(), self.ctx.clone(), bus_rx).await?;

        // 4. Shutdown Sequence
        self.shutdown().await
    }

    fn spawn_services(&mut self) {
        let cfg = &self.bootstrap.cfg;
        let target_ifindex = self.bootstrap.target_ifindex;
        let netlink_handle = &self.bootstrap.rt_handle;
        let messages = &self.bootstrap.messages;

        // DB Worker (Sync)
        let db_path = PathBuf::from(&cfg.leases_db);
        let log_db_path = PathBuf::from(&cfg.log_db);
        let ctx_db = self.ctx.clone();
        self.registry.spawn_sync(&self.ctx, move || {
            DbWorker::new(db_path.clone(), log_db_path.clone(), ctx_db.clone())
        });

        // mDNS Prober (Async)
        let ctx_mdns = self.ctx.clone();
        self.registry
            .spawn_async(&self.ctx, move || MdnsProber::new(ctx_mdns.clone()));

        // Interface Monitor (Async)
        let h1 = netlink_handle.clone();
        let m1 = messages.clone();
        let ctx_ifmon = self.ctx.clone();
        self.registry.spawn_async(&self.ctx, move || {
            InterfaceMonitor::new(
                h1.clone(),
                m1.subscribe(),
                target_ifindex,
                ctx_ifmon.clone(),
            )
        });

        // Ndp Monitor (Async)
        let h2 = netlink_handle.clone();
        let m2 = messages.clone();
        let ctx_ndp = self.ctx.clone();
        let scan_interval = Duration::from_secs(cfg.neighbor_scan_mins * 60);

        self.registry.spawn_async(&self.ctx, move || {
            NeighborMonitor::new(
                h2.clone(),
                m2.subscribe(),
                target_ifindex,
                ctx_ndp.clone(),
                scan_interval,
            )
        });

        // RA Service (Async)
        if cfg.ra_enabled {
            let ra_cfg = cfg.to_ra_config();
            let ctx_ra = self.ctx.clone();
            self.registry.spawn_async(&self.ctx, move || {
                RaService::new(ra_cfg.clone(), ctx_ra.clone())
            });
        }

        // DHCPv4 Service (Sync)
        if cfg.dhcpv4_enabled {
            let d4_cfg = cfg.to_dhcpv4_config();
            let ctx_v4 = self.ctx.clone();
            self.registry.spawn_sync(&self.ctx, move || {
                Dhcpv4Service::new(d4_cfg.clone(), ctx_v4.clone())
            });
        }

        // DHCPv6 Service (Sync)
        if cfg.dhcpv6_enabled {
            let d6_cfg = cfg.to_dhcpv6_config();
            let ctx_v6 = self.ctx.clone();
            self.registry.spawn_sync(&self.ctx, move || {
                Dhcpv6Service::new(d6_cfg.clone(), ctx_v6.clone())
            });
        }

        // DNS Service (Async)
        if cfg.dns_enabled {
            let dns_cfg = cfg.to_dns_config();
            let ctx_dns = self.ctx.clone();
            self.registry.spawn_async(&self.ctx, move || {
                DnsService::new(dns_cfg.clone(), ctx_dns.clone())
            });
        }

        // API & Control Services
        let api_cfg = Arc::new(cfg.to_api_config());

        let api_cfg_ctrl = api_cfg.clone();
        let ctx_ctrl = self.ctx.clone();
        self.registry.spawn_async(&self.ctx, move || {
            ControlService::new(api_cfg_ctrl.clone(), ctx_ctrl.clone())
        });

        if cfg.http_listen.is_some() {
            let api_cfg_http = api_cfg;
            let ctx_http = self.ctx.clone();
            self.registry.spawn_async(&self.ctx, move || {
                HttpService::new(api_cfg_http.clone(), ctx_http.clone())
            });
        }
    }

    async fn shutdown(self) -> Result<()> {
        info!("🛑 Iniciando sequência de shutdown...");
        self.ctx.terminate();
        let _ = self.ctx.bus().publish(LanforgeEvent::Shutdown);
        let _ = self.ctx.bus().publish(LanforgeEvent::Shutdown);

        // Wait for all services to stop (with timeout)
        tokio::select! {
            _ = tokio::task::spawn_blocking(move || self.registry.wait_all()) => {
                info!("All services shut down cleanly.");
            }
            () = tokio::time::sleep(Duration::from_secs(5)) => {
                info!("Shutdown timeout reached, exiting.");
            }
        }

        info!("👋 Lanforge encerrado.");
        Ok(())
    }
}

/// Helper public functions needed by modules
pub async fn run_scan(
    ctx: &LanforgeContext,
    cfg: &Config,
    handle: &rtnetlink::Handle,
    gua: Option<Ipv6Addr>,
    ula: Option<Ipv6Addr>,
    target_ifindex: u32,
) -> Result<()> {
    bootstrap_table(
        ctx,
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
