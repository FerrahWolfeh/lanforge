use anyhow::Result;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::bootstrap::BootstrapResult;
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
use lanforge_network::slaac::SlaacTracker;

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
    pub async fn run(mut self) -> Result<()> {
        let bus = self.ctx.bus();
        let bus_rx = bus.subscribe();

        self.spawn_services();

        run_event_loop(self.bootstrap.clone(), self.ctx.clone(), bus_rx).await?;

        self.shutdown().await
    }

    fn spawn_services(&mut self) {
        let cfg = &self.bootstrap.cfg;
        let target_ifindex = self.bootstrap.target_ifindex;
        let rt_handle = &self.bootstrap.rt_handle;
        let messages = &self.bootstrap.messages;

        // 1. Core Services (DB, mDNS)
        let db_url = cfg.db_url.clone();
        let log_db_url = cfg.log_db_url.clone();
        let ctx = self.ctx.clone();
        self.registry.spawn_async(&self.ctx, move || {
            DbWorker::new(db_url.clone(), log_db_url.clone(), ctx.clone())
        });

        let ctx = self.ctx.clone();
        self.registry
            .spawn_async(&self.ctx, move || MdnsProber::new(ctx.clone()));

        // 2. Network Monitoring (Interface, Neighbors)
        let ctx = self.ctx.clone();
        let h = rt_handle.clone();
        let m = messages.clone();
        self.registry.spawn_async(&self.ctx, move || {
            InterfaceMonitor::new(h.clone(), m.subscribe(), target_ifindex, ctx.clone())
        });

        let ctx = self.ctx.clone();
        let h = rt_handle.clone();
        let m = messages.clone();
        self.registry.spawn_async(&self.ctx, move || {
            NeighborMonitor::new(h.clone(), m.subscribe(), target_ifindex, ctx.clone())
        });

        // 3. IPv6 Protocol Services (RA, SLAAC)
        if cfg.ra_enabled {
            let ra_cfg = cfg.to_ra_config();
            let ctx = self.ctx.clone();
            self.registry.spawn_async(&self.ctx, move || {
                RaService::new(ra_cfg.clone(), ctx.clone())
            });

            let ctx = self.ctx.clone();
            self.registry.spawn_async(&self.ctx, move || {
                SlaacTracker::new(target_ifindex, ctx.clone())
            });
        }

        // 4. Address Assignment (DHCPv4, DHCPv6)
        if cfg.dhcpv4_enabled {
            let d4_cfg = cfg.to_dhcpv4_config();
            let ctx = self.ctx.clone();
            self.registry.spawn_sync(&self.ctx, move || {
                Dhcpv4Service::new(d4_cfg.clone(), ctx.clone())
            });
        }

        if cfg.dhcpv6_enabled {
            let d6_cfg = cfg.to_dhcpv6_config();
            let ctx = self.ctx.clone();
            self.registry.spawn_sync(&self.ctx, move || {
                Dhcpv6Service::new(d6_cfg.clone(), ctx.clone())
            });
        }

        // 5. Application Services (DNS, API)
        if cfg.dns_enabled {
            let dns_cfg = cfg.to_dns_config();
            let ctx = self.ctx.clone();
            self.registry.spawn_async(&self.ctx, move || {
                DnsService::new(dns_cfg.clone(), ctx.clone())
            });
        }

        let api_cfg = Arc::new(cfg.to_api_config());
        let ctx = self.ctx.clone();
        let api_cfg_ctrl = api_cfg.clone();
        self.registry.spawn_async(&self.ctx, move || {
            ControlService::new(api_cfg_ctrl.clone(), ctx.clone())
        });

        if cfg.http_listen.is_some() {
            let ctx = self.ctx.clone();
            let api_cfg_http = api_cfg;
            self.registry.spawn_async(&self.ctx, move || {
                HttpService::new(api_cfg_http.clone(), ctx.clone())
            });
        }
    }

    async fn shutdown(self) -> Result<()> {
        info!("🛑 Starting shutdown sequence...");
        self.ctx.terminate();
        let _ = self.ctx.bus().publish(LanforgeEvent::Shutdown);

        tokio::select! {
            _ = tokio::task::spawn_blocking(move || self.registry.wait_all()) => {
                info!("All services shut down cleanly.");
            }
            () = tokio::time::sleep(Duration::from_secs(5)) => {
                info!("Shutdown timeout reached, exiting.");
            }
        }

        info!("👋 Lanforge terminated.");
        Ok(())
    }
}

pub fn sd_notify_ready() {
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        debug!("systemd: Notifying READY=1 via {}", path);
        if let Ok(sock) = UnixDatagram::unbound()
            && sock.connect(path).is_ok()
        {
            let _ = sock.send(b"READY=1\n");
        }
    }
}
