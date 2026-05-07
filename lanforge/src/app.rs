use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::bootstrap::BootstrapResult;
use crate::event_loop::{LoopResult, run_event_loop};
use crate::registry::ServiceRegistry;
use lanforge_api::server::ControlService;
use lanforge_db::worker::DbWorker;
#[cfg(feature = "doq")]
use lanforge_dns::DoqService;
#[cfg(feature = "dot")]
use lanforge_dns::DotService;
use lanforge_dns::server::DnsService;
#[cfg(feature = "http")]
use lanforge_http::HttpService;
use lanforge_network::dhcp::v4::Dhcpv4Service;
use lanforge_network::dhcp::v6::Dhcpv6Service;
use lanforge_network::ifmon::AddressMonitor;
use lanforge_network::lldp::LldpMonitor;
use lanforge_network::mdns::MdnsProber;
use lanforge_network::ndp::NeighborMonitor;
use lanforge_network::ra::RaService;
use lanforge_network::slaac::SlaacTracker;
use lanforge_tftp::TftpService;

/// The central application controller for the Lanforge daemon.
pub struct Daemon {
    bootstrap: BootstrapResult,
    registry: ServiceRegistry,
    ctx: LanforgeContext,
}

impl Daemon {
    /// Creates a new Daemon instance from a bootstrap result and context.
    #[must_use]
    pub fn new(bootstrap: BootstrapResult, ctx: LanforgeContext) -> Self {
        Self {
            bootstrap,
            registry: ServiceRegistry::new(),
            ctx,
        }
    }

    /// Runs the daemon's main execution cycle.
    pub async fn run(mut self) -> Result<()> {
        loop {
            let bus = self.ctx.bus();
            let bus_rx = bus.subscribe();

            self.validate_features();
            self.spawn_services();
            let expected = self.registry.registered_ids();

            match run_event_loop(self.bootstrap.clone(), self.ctx.clone(), bus_rx, expected).await?
            {
                LoopResult::Reload => {
                    info!("Daemon: Configuration reload requested. Starting soft-reboot...");

                    // 1. Signal shutdown to current services
                    self.ctx.terminate();
                    let _ = self
                        .ctx
                        .bus()
                        .publish(LanforgeEvent::System(SystemEvent::Shutdown));

                    // 2. Wait for all services to exit
                    let registry = std::mem::take(&mut self.registry);
                    tokio::task::spawn_blocking(move || registry.wait_all()).await?;

                    // 3. Reset context state (not the full registry, just the 'running' flag and readiness)
                    self.ctx.reset_lifecycle();

                    // 4. Reload configuration from disk
                    let new_cfg = Arc::new(crate::bootstrap::Bootstrapper::load_config());
                    self.bootstrap.cfg = new_cfg.clone();

                    // 5. Re-synchronize static devices from new config into existing state
                    let mut state = self.ctx.write();
                    crate::bootstrap::Bootstrapper::reload_static_devices_into_state(
                        &mut state, &new_cfg,
                    );
                    drop(state);

                    info!("Daemon: Soft-reboot complete. Restarting services...");
                }
                LoopResult::Shutdown => break,
            }
        }

        self.shutdown().await
    }

    fn validate_features(&self) {
        #[allow(unused_variables)]
        let cfg = &self.bootstrap.cfg;

        #[cfg(not(feature = "dot"))]
        if cfg.dns_toml.dot_enabled {
            tracing::error!(
                "❌ Feature 'dot' (DNS-over-TLS) is enabled in configuration but not compiled in the binary!"
            );
        }

        #[cfg(not(feature = "doq"))]
        if cfg.dns_toml.doq_enabled {
            tracing::error!(
                "❌ Feature 'doq' (DNS-over-QUIC) is enabled in configuration but not compiled in the binary!"
            );
        }

        #[cfg(not(feature = "http"))]
        if cfg.http_toml.enabled {
            tracing::error!(
                "❌ Feature 'http' (REST API / Metrics) is enabled in configuration but not compiled in the binary!"
            );
        }

        #[cfg(not(feature = "adblock"))]
        if cfg.dns_enabled && cfg.dns_toml.adblock_enabled {
            tracing::error!(
                "❌ Feature 'adblock' is enabled in configuration but not compiled in the binary!"
            );
        }

        // Database checks
        #[cfg(not(feature = "sqlite"))]
        if cfg.database.url.starts_with("sqlite") {
            tracing::error!(
                "❌ Database URL suggests SQLite but feature 'sqlite' is not compiled in!"
            );
        }

        #[cfg(not(feature = "postgres"))]
        if cfg.database.url.starts_with("postgres") || cfg.database.url.starts_with("postgresql") {
            tracing::error!(
                "❌ Database URL suggests PostgreSQL but feature 'postgres' is not compiled in!"
            );
        }
    }

    fn spawn_services(&mut self) {
        let cfg = &self.bootstrap.cfg;
        let target_ifindex = self.bootstrap.target_ifindex;
        let rt_handle = &self.bootstrap.rt_handle;
        let messages = &self.bootstrap.messages;

        if !cfg.monitor_toml.enabled {
            tracing::warn!(
                "⚠️  Neighbor Monitor is DISABLED. Passive device discovery and 'last_seen' tracking will be unavailable."
            );
        }

        // 1. Core Services (DB, mDNS)
        let rt_handle = rt_handle.clone();
        let messages = messages.clone();
        let ifname = cfg.system.iface.clone();

        let ctx = self.ctx.clone();
        let cfg = cfg.clone();

        lanforge_core::spawn_services!(self.registry, &self.ctx, {
            async [ctx, cfg] => DbWorker::new(cfg.database.clone(), ctx),
            async [ctx, cfg] if cfg.mdns_toml.enabled => MdnsProber::new(cfg.mdns_toml.clone(), ctx),

            // 2. Network Monitoring (Interface, Neighbors, LLDP)
            async [ctx, rt_handle, messages] => AddressMonitor::new(rt_handle, messages.subscribe(), target_ifindex, ctx),
            async [ctx, rt_handle, messages, cfg] if cfg.monitor_toml.enabled => NeighborMonitor::new(cfg.monitor_toml.clone(), rt_handle, messages.subscribe(), target_ifindex, ctx),
            async [ctx, ifname] => LldpMonitor::new(ifname, target_ifindex, ctx),

            // 3. IPv6 Protocol Services (RA, SLAAC)
            async [ctx, cfg] if cfg.ra_enabled => RaService::new(cfg.to_ra_config(), ctx),
            async [ctx] if cfg.ra_enabled => SlaacTracker::new(target_ifindex, ctx),

            // 4. Address Assignment (DHCPv4, DHCPv6)
            async [ctx, cfg] if cfg.dhcpv4_enabled => Dhcpv4Service::new(cfg.to_dhcpv4_config(), ctx),
            async [ctx, cfg] if cfg.dhcpv6_enabled => Dhcpv6Service::new(cfg.to_dhcpv6_config(), ctx),

            // 5. Application Services (DNS, API, TFTP)
            async [ctx, cfg] if cfg.dns_enabled => DnsService::new(cfg.to_dns_config(), ctx),

            #[cfg(feature = "dot")]
            async [ctx, cfg] if cfg.dns_enabled && cfg.dns_toml.dot_enabled => DotService::new(Arc::new(cfg.to_dns_config()), ctx),

            #[cfg(feature = "doq")]
            async [ctx, cfg] if cfg.dns_enabled && cfg.dns_toml.doq_enabled => DoqService::new(Arc::new(cfg.to_dns_config()), ctx),
            async [ctx, cfg] if cfg.api_toml.enabled => ControlService::new(Arc::new(cfg.to_api_config()), ctx),

            #[cfg(feature = "http")]
            async [ctx, cfg] if cfg.http_toml.enabled => HttpService::new(Arc::new(cfg.to_api_config()), ctx),

            async [ctx, cfg] if cfg.tftp_toml.enabled => TftpService::new(
                ctx,
                cfg.tftp_toml.clone(),
            ),
        });
    }

    async fn shutdown(self) -> Result<()> {
        info!("🛑 Starting shutdown sequence...");
        self.ctx.terminate();
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::Shutdown));

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
