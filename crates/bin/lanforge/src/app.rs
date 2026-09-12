use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use sd_notify::{NotifyState, notify};
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
#[cfg(feature = "http")]
use lanforge_http::HttpService;
#[cfg(feature = "pppoe")]
use lanforge_db::PppoeConfigStore;
#[cfg(feature = "pppoe")]
use lanforge_pppoe::PppoeService;
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
            let sys_rx = self.ctx.bus().subscribe_system();
            let net_rx = self.ctx.bus().subscribe_network();
            let sto_rx = self.ctx.bus().subscribe_storage();

            self.validate_features();
            self.spawn_services().await;
            let expected = self.registry.registered_ids();

            match run_event_loop(
                self.bootstrap.clone(),
                self.ctx.clone(),
                sys_rx,
                net_rx,
                sto_rx,
                expected,
            )
            .await?
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
                    let mut new_cfg = Config::load();
                    #[cfg(feature = "pppoe")]
                    if let Ok(Some(pppoe_db)) = self.bootstrap.db.load_pppoe_config().await {
                        new_cfg.pppoe_enabled = pppoe_db.enabled;
                        new_cfg.pppoe_toml = pppoe_db.clone();
                        self.ctx.update_pppoe_config(pppoe_db);
                    }
                    let new_cfg = Arc::new(new_cfg);
                    self.bootstrap.cfg = new_cfg.clone();

                    let _ = self
                        .ctx
                        .bus()
                        .publish(LanforgeEvent::System(SystemEvent::InterfaceReady));

                    if !new_cfg.pppoe_enabled {
                        self.ctx.set_pppoe_ready(true);
                    }

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
                    "Feature 'dns-dot' (DNS-over-TLS) is enabled in configuration but not compiled in binary"
                );
            }

            #[cfg(not(feature = "dns-doq"))]
            if cfg.dns_toml.doq_enabled {
                tracing::error!(
                    "Feature 'dns-doq' (DNS-over-QUIC) is enabled in configuration but not compiled in binary"
                );
            }

            #[cfg(not(feature = "adblock"))]
            if cfg.dns_enabled && cfg.dns_toml.adblock_enabled {
                tracing::error!(
                    "Feature 'adblock' is enabled in configuration but not compiled in binary"
                );
            }
        }

        #[cfg(not(feature = "http"))]
        if cfg.http_toml.enabled {
            tracing::error!(
                "Feature 'http' (REST API / Metrics) is enabled in configuration but not compiled in binary"
            );
        }

        // Database checks
        if cfg.database.config_path.starts_with("sqlite") || cfg.database.config_path.starts_with("postgres") || cfg.database.config_path.starts_with("postgresql") {
            tracing::warn!(
                "External SQL databases are no longer supported. Lanforge uses embedded redb storage."
            );
        }
    }

    async fn spawn_services(&mut self) {
        let cfg = self.bootstrap.cfg.clone();
        let target_ifindex = self.bootstrap.target_ifindex;
        let rt_handle = self.bootstrap.rt_handle.clone();
        let messages = self.bootstrap.messages.clone();
        let db = self.bootstrap.db.clone();
        let log_db = self.bootstrap.log_db.clone();
        let ctx = self.ctx.clone();

        let monitored_ifindexes = {
            let mut indexes = Vec::new();
            if cfg.monitor_toml.ifaces.is_empty() {
                indexes.push(target_ifindex);
            } else {
                let host_ifaces = pnet::datalink::interfaces();
                for ifname in &cfg.monitor_toml.ifaces {
                    if let Some(iface) = host_ifaces.iter().find(|i| &i.name == ifname) {
                        indexes.push(iface.index);
                    } else {
                        tracing::warn!("Discovery: Configured monitor interface '{ifname}' not found on host");
                    }
                }
                if indexes.is_empty() {
                    indexes.push(target_ifindex);
                }
            }
            indexes
        };

        #[cfg(feature = "discovery")]
        if !cfg.monitor_toml.enabled {
            tracing::warn!(
                "Discovery: Neighbor Monitor is disabled. Passive device discovery will be unavailable."
            );
        }

        #[cfg(feature = "dns")]
        let dns_lifetime = log_db.load_dns_lifetime_stats().await.unwrap_or_default();

        lanforge_core::spawn_services!(self.registry, &self.ctx, {
            async [ctx, cfg, db, log_db] => DbWorker::new(cfg.database.clone(), ctx, db, log_db),

            #[cfg(feature = "discovery")]
            async [ctx, cfg] => MdnsProber::new(cfg.mdns_toml.clone(), ctx),

            // 2. Network Discovery & Interface Monitoring
            #[cfg(feature = "discovery")]
            async [ctx, rt_handle, messages, cfg] => DiscoveryService::new(cfg.monitor_toml.clone(), rt_handle, messages.subscribe(), monitored_ifindexes.clone(), ctx),

            // 3. IPv6 Protocol Services (RA)
            #[cfg(feature = "ra")]
            async [ctx, cfg] => RaService::new(cfg.to_ra_config(), ctx),

            // 4. Address Assignment (DHCPv4, DHCPv6)
            #[cfg(feature = "dhcp")]
            async [ctx, cfg] => Dhcpv4Service::new(cfg.to_dhcpv4_config(), ctx),
            #[cfg(feature = "dhcp")]
            async [ctx, cfg] => Dhcpv6Service::new(cfg.to_dhcpv6_config(), ctx),

            // 5. Application Services (DNS, API, TFTP)
            #[cfg(feature = "dns")]
            async [ctx, cfg, dns_lifetime] => DnsService::with_lifetime(cfg.to_dns_config(), ctx, dns_lifetime),

            #[cfg(all(feature = "dns", feature = "dns-dot"))]
            async [ctx, cfg] => DotService::new(Arc::new(cfg.to_dns_config()), ctx),

            #[cfg(all(feature = "dns", feature = "dns-doq"))]
            async [ctx, cfg] => DoqService::new(Arc::new(cfg.to_dns_config()), ctx),

            #[cfg(feature = "uds")]
            async [ctx, cfg, db, log_db] => ControlService::new(Arc::new(cfg.to_api_config()), ctx, db, log_db),

            #[cfg(feature = "http")]
            async [ctx, cfg, db, log_db] => HttpService::new(Arc::new(cfg.to_http_config()), ctx, db, log_db),

            #[cfg(feature = "tftp")]
            async [ctx, cfg] => TftpService::new(
                ctx,
                cfg.tftp_toml.clone(),
            ),

            #[cfg(feature = "pppoe")]
            async [ctx, cfg] => PppoeService::new(
                ctx.get_pppoe_config().unwrap_or_else(|| cfg.pppoe_toml.clone()),
                ctx,
            ),
        });
    }

    async fn shutdown(self) -> Result<()> {
        sd_notify_stopping();
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

pub fn sd_notify_ready(status: &str) {
    if let Err(e) = notify(&[NotifyState::Ready, NotifyState::Status(status)]) {
        debug!("systemd: sd_notify failed or not running under systemd: {e}");
    }
}

pub fn sd_notify_stopping() {
    let _ = notify(&[
        NotifyState::Stopping,
        NotifyState::Status("Shutting down..."),
    ]);
}
