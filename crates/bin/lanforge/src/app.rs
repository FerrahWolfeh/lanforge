use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use sd_notify::{NotifyState, notify};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::bootstrap::BootstrapResult;
use crate::event_loop::run_event_loop;
use crate::registry::ServiceRegistry;
use crate::synthetic::{InterfacesService, WanService};
use lanforge_db::LogStore;
use lanforge_db::worker::DbWorker;
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v4::Dhcpv4Service;
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v6::Dhcpv6Service;
#[cfg(feature = "discovery")]
use lanforge_discovery::{mdns::MdnsProber, ndp::DiscoveryService};
#[cfg(feature = "dns")]
use lanforge_dns::server::service::DnsService;
#[cfg(feature = "http")]
use lanforge_http::HttpService;
#[cfg(feature = "nft")]
use lanforge_nft::NftService;
use lanforge_pppoe::PppoeService;
#[cfg(feature = "ra")]
use lanforge_ra::RaService;
#[cfg(feature = "tftp")]
use lanforge_tftp::TftpService;
#[cfg(feature = "traffic")]
use lanforge_traffic::TrafficService;
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
        let sys_rx = self.ctx.bus().subscribe_system();
        let net_rx = self.ctx.bus().subscribe_network();

        self.validate_features();
        self.spawn_services();
        let expected = self.registry.registered_ids();
        let registry = std::mem::take(&mut self.registry);
        let supervisor = registry.start(&self.ctx)?;

        run_event_loop(
            self.bootstrap.clone(),
            self.ctx.clone(),
            sys_rx,
            net_rx,
            expected,
            &supervisor,
        )
        .await?;

        supervisor
            .shutdown(&self.ctx, Duration::from_secs(10))
            .await;
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
        if cfg.database.config_path.starts_with("sqlite")
            || cfg.database.config_path.starts_with("postgres")
            || cfg.database.config_path.starts_with("postgresql")
        {
            tracing::warn!(
                "External SQL databases are no longer supported. Lanforge uses embedded redb storage."
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

        let monitored_ifindexes = if cfg.monitor_toml.ifaces.is_empty() {
            vec![target_ifindex]
        } else {
            let host_ifaces = pnet::datalink::interfaces();
            let mut indexes: Vec<u32> = cfg
                .monitor_toml
                .ifaces
                .iter()
                .filter_map(|ifname| {
                    let iface = host_ifaces.iter().find(|i| &i.name == ifname);
                    if iface.is_none() {
                        tracing::warn!("Configured monitor interface '{ifname}' not found on host");
                    }
                    iface.map(|i| i.index)
                })
                .collect();
            if indexes.is_empty() {
                indexes.push(target_ifindex);
            }
            indexes
        };

        #[cfg(feature = "discovery")]
        if !cfg.monitor_toml.enabled {
            tracing::warn!(
                "Neighbor Monitor is disabled. Passive device discovery will be unavailable."
            );
        }

        crate::spawn_services!(self.registry, &self.ctx, {
            // 0. Synthetic Graph Nodes (Supervisor & Observer Managed)
            async [cfg] => InterfacesService::new(cfg.system.iface.clone()),
            async [] => WanService::new(),

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
            async [ctx, cfg] => DnsService::new(cfg.to_dns_config(), ctx),

            #[cfg(feature = "uds")]
            async [ctx, cfg] => ControlService::new(Arc::new(cfg.to_api_config()), ctx),

            #[cfg(feature = "http")]
            async [ctx, cfg, db, log_db] => HttpService::new(Arc::new(cfg.to_http_config()), ctx, Arc::new(db.redb().clone()), log_db),

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

            #[cfg(feature = "nft")]
            async [] => NftService::new(),

            #[cfg(feature = "traffic")]
            async [ctx, cfg] => TrafficService::new(
                ctx.get_traffic_config().unwrap_or_else(|| cfg.traffic_toml.clone()),
            ),
        });
    }

    async fn shutdown(self) -> Result<()> {
        sd_notify_stopping();
        info!("Starting shutdown sequence...");
        let log_db = self.bootstrap.log_db.clone();
        self.ctx.terminate();
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::Shutdown));

        #[cfg(feature = "traffic")]
        {
            let history = lanforge_traffic::get_traffic_history_snapshot().await;
            if !history.is_empty() {
                let _ = log_db.save_traffic_history(&history);
            }
        }

        info!("Lanforge terminated.");
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
