use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::bootstrap::BootstrapResult;
use crate::config::Config;
use crate::event_loop::{LoopResult, run_event_loop};
use crate::registry::ServiceRegistry;
use lanforge_db::worker::DbWorker;
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v4::Dhcpv4Service;
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v6::Dhcpv6Service;
#[cfg(feature = "discovery")]
use lanforge_discovery::{mdns::MdnsProber, ndp::DiscoveryService};
#[cfg(feature = "dns")]
use lanforge_dns::server::service::DnsService;
#[cfg(all(feature = "dns", feature = "dns-doq"))]
use lanforge_dns::server::transport::doq::DoqService;
#[cfg(all(feature = "dns", feature = "dns-dot"))]
use lanforge_dns::server::transport::dot::DotService;
use lanforge_host::ifmon::AddressMonitor;
#[cfg(feature = "http")]
use lanforge_http::HttpService;
#[cfg(feature = "ra")]
use lanforge_ra::RaService;
#[cfg(feature = "tftp")]
use lanforge_tftp::TftpService;
#[cfg(feature = "uds")]
use lanforge_uds::server::ControlService;

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
                    let new_cfg = Arc::new(Config::load());
                    self.bootstrap.cfg = new_cfg.clone();

                    // 5. Re-synchronize static devices from new config into existing state (Deprecated)
                    // let mut state = self.ctx.write();
                    // crate::bootstrap::Bootstrapper::reload_static_devices_into_state(
                    //     &mut state, &new_cfg,
                    // );
                    // drop(state);

                    info!("Daemon: Soft-reboot complete. Restarting services...");
                }
                LoopResult::Shutdown => break,
            }
        }

        self.shutdown().await
    }

    #[allow(clippy::missing_const_for_fn)]
    fn validate_features(&self) {
        #[allow(unused_variables)]
        let cfg = &self.bootstrap.cfg;

        #[cfg(feature = "dns")]
        {
            #[cfg(not(feature = "dns-dot"))]
            if cfg.dns_toml.dot_enabled {
                tracing::error!(
                    "❌ Feature 'dns-dot' (DNS-over-TLS) is enabled in configuration but not compiled in the binary!"
                );
            }

            #[cfg(not(feature = "dns-doq"))]
            if cfg.dns_toml.doq_enabled {
                tracing::error!(
                    "❌ Feature 'dns-doq' (DNS-over-QUIC) is enabled in configuration but not compiled in the binary!"
                );
            }

            #[cfg(not(feature = "adblock"))]
            if cfg.dns_enabled && cfg.dns_toml.adblock_enabled {
                tracing::error!(
                    "❌ Feature 'adblock' is enabled in configuration but not compiled in the binary!"
                );
            }
        }

        #[cfg(feature = "http")]
        if cfg.http_toml.enabled {
            tracing::error!(
                "❌ Feature 'http' (REST API / Metrics) is enabled in configuration but not compiled in the binary!"
            );
        }

        // Database checks
        if cfg.database.url.starts_with("sqlite") {
            tracing::error!(
                "❌ SQLite databases are no longer supported! Please use a PostgreSQL connection string."
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
        let cfg = self.bootstrap.cfg.clone();
        let target_ifindex = self.bootstrap.target_ifindex;
        let rt_handle = self.bootstrap.rt_handle.clone();
        let messages = self.bootstrap.messages.clone();
        let db = self.bootstrap.db.clone();
        let log_db = self.bootstrap.log_db.clone();
        let ctx = self.ctx.clone();

        #[cfg(feature = "discovery")]
        if !cfg.monitor_toml.enabled {
            tracing::warn!(
                "⚠️  Neighbor Monitor is DISABLED. Passive device discovery and 'last_seen' tracking will be unavailable."
            );
        }

        lanforge_core::spawn_services!(self.registry, &self.ctx, {
            async [ctx, cfg, db, log_db] => DbWorker::new(cfg.database.clone(), ctx, db, log_db),

            #[cfg(feature = "discovery")]
            async [ctx, cfg] if cfg.mdns_toml.enabled => MdnsProber::new(cfg.mdns_toml.clone(), ctx),

            // 2. Network Monitoring (Interface, Neighbors)
            async [ctx, rt_handle, messages] => AddressMonitor::new(rt_handle, messages.subscribe(), target_ifindex, ctx),

            #[cfg(feature = "discovery")]
            async [ctx, rt_handle, messages, cfg] if cfg.monitor_toml.enabled => DiscoveryService::new(cfg.monitor_toml.clone(), rt_handle, messages.subscribe(), target_ifindex, ctx),

            // 3. IPv6 Protocol Services (RA)
            #[cfg(feature = "ra")]
            async [ctx, cfg] if cfg.ra_enabled => RaService::new(cfg.to_ra_config(), ctx),

            // 4. Address Assignment (DHCPv4, DHCPv6)
            #[cfg(feature = "dhcp")]
            async [ctx, cfg] if cfg.dhcpv4_enabled => Dhcpv4Service::new(cfg.to_dhcpv4_config(), ctx),
            #[cfg(feature = "dhcp")]
            async [ctx, cfg] if cfg.dhcpv6_enabled => Dhcpv6Service::new(cfg.to_dhcpv6_config(), ctx),

            // 5. Application Services (DNS, API, TFTP)
            #[cfg(feature = "dns")]
            async [ctx, cfg] if cfg.dns_enabled => DnsService::new(cfg.to_dns_config(), ctx),

            #[cfg(all(feature = "dns", feature = "dns-dot"))]
            async [ctx, cfg] if cfg.dns_enabled && cfg.dns_toml.dot_enabled => DotService::new(Arc::new(cfg.to_dns_config()), ctx),

            #[cfg(all(feature = "dns", feature = "dns-doq"))]
            async [ctx, cfg] if cfg.dns_enabled && cfg.dns_toml.doq_enabled => DoqService::new(Arc::new(cfg.to_dns_config()), ctx),

            #[cfg(feature = "uds")]
            async [ctx, cfg, db, log_db] if cfg.api_toml.enabled => ControlService::new(Arc::new(cfg.to_api_config()), ctx, db, log_db),

            #[cfg(feature = "http")]
            async [ctx, cfg, db, log_db] if cfg.http_toml.enabled => HttpService::new(Arc::new(cfg.to_http_config()), ctx, db, log_db),

            #[cfg(feature = "tftp")]
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
