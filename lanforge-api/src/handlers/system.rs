use crate::api::{
    Capabilities, Compression, DbStatus, DevicesStats, Encoding, NetworkStatus, ResourcesStatus,
    Response, ServiceStatusInfo, ServicesStatus, SimpleSuccess, StatusResponse,
};
use crate::server::ClientContext;
use lanforge_core::types::{
    Device, IPv6State, LanforgeEvent, NetworkEvent, Origin, StorageEvent, SystemEvent,
};
use lanforge_core::utils::auth::hash_password;
use std::fs::metadata;
use std::sync::Arc;

impl ClientContext {
    /// Generates a full `StatusResponse` by gathering data from the configuration
    /// and the active device table.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) async fn handle_status(&self) -> Response {
        let mut status = StatusResponse {
            uptime_secs: self.uptime_secs,
            version: env!("CARGO_PKG_VERSION").to_string(),
            services: ServicesStatus::default(),
            db: self.gather_db_status(),
            network: self.gather_network_status().await,
            resources: Self::gather_resource_status(),
            devices: DevicesStats::default(),
            capabilities: Self::gather_capabilities(),
        };

        let devices = self.ctx.all_devices();
        self.populate_service_and_device_stats(&mut status, &devices);

        Response::Status(Box::new(status))
    }

    pub(crate) fn gather_db_status(&self) -> DbStatus {
        let mut db = DbStatus {
            path: self.cfg.db_path.clone(),
            ..Default::default()
        };
        if let Ok(meta) = metadata(&self.cfg.db_path) {
            db.size_bytes = meta.len();
        }
        if let Some(last_flush) = self.ctx.last_db_flush() {
            db.last_flush_secs_ago = last_flush.elapsed().unwrap_or_default().as_secs();
        }
        db
    }

    pub(crate) fn gather_resource_status() -> ResourcesStatus {
        let mut res = ResourcesStatus::default();
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let mut parts = statm.split_whitespace();
            if let (Some(vms_pages), Some(rss_pages)) = (parts.next(), parts.next()) {
                let page_size = 4096;
                res.memory_vms_bytes = vms_pages.parse::<u64>().unwrap_or(0) * page_size;
                res.memory_rss_bytes = rss_pages.parse::<u64>().unwrap_or(0) * page_size;
            }
        }
        res
    }

    pub(crate) async fn gather_network_status(&self) -> NetworkStatus {
        let mut net = NetworkStatus {
            lan_iface: self.cfg.lan_iface.clone(),
            ..Default::default()
        };
        if let Some(ifindex) = self.ctx.target_ifindex() {
            let state = self.ctx.read();
            if let Some(if_ips) = state.interfaces.interface_ips.get(&ifindex) {
                if let Some((ip, prefix)) = if_ips.v4 {
                    net.lan_ipv4 = Some(ip.to_string());
                    net.lan_ipv4_cidr = Some(format!("{ip}/{prefix}"));
                }
                net.gua = if_ips.gua.map(|ip| ip.to_string());
                net.ula = if_ips.ula.map(|ip| ip.to_string());
                net.lan_ipv6 = if_ips.link_local.map(|ip| ip.to_string());
            }
        }
        if net.gua.is_none() {
            net.gua.clone_from(&self.current_gua);
        }
        if net.ula.is_none() {
            net.ula.clone_from(&self.cfg.ula_prefix);
        }
        net
    }

    pub(crate) fn gather_capabilities() -> Capabilities {
        Capabilities {
            encodings: vec![Encoding::Json, Encoding::Postcard],
            compression: {
                #[cfg(feature = "zstd")]
                {
                    vec![Compression::None, Compression::Zstd]
                }
                #[cfg(not(feature = "zstd"))]
                {
                    vec![Compression::None]
                }
            },
        }
    }

    pub(crate) fn populate_service_and_device_stats(
        &self,
        status: &mut StatusResponse,
        devices: &[Arc<Device>],
    ) {
        // Services -> RA
        status.services.ra.state = if self.cfg.ra_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.ra.uptime_secs = self.uptime_secs;
        status.services.ra.gua.clone_from(&self.current_gua);
        status.services.ra.ula.clone_from(&status.network.ula);

        let mut counts = (0, 0, 0, 0, 0, 0, 0); // online, static, dynamic, v4_dyn, v6_dyn, slaac, managed_cli
        for dev in devices {
            if dev.last_seen.elapsed().unwrap_or_default().as_secs() < 300 {
                counts.0 += 1;
            }
            if dev.is_static() {
                counts.1 += 1;
            } else {
                counts.2 += 1;
                if dev.v4.ip().is_some() {
                    counts.3 += 1;
                }
                if dev.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_))) {
                    counts.4 += 1;
                }
            }
            counts.5 += dev
                .v6
                .iter()
                .filter(|s| {
                    matches!(
                        s,
                        IPv6State::Slaac(..) | IPv6State::Discovery(..) | IPv6State::LinkLocal(..)
                    )
                })
                .count();
            if dev.origin == Origin::Cli {
                counts.6 += 1;
            }
        }

        status.services.dhcp_v4.leases_active = counts.3;
        status.services.dhcp_v4.state = if self.cfg.dhcp_v4_enabled {
            "active"
        } else {
            "inactive"
        }
        .to_string();
        status.services.dhcp_v4.pool_free = usize::try_from(
            self.cfg
                .dhcp_v4_range_size
                .saturating_sub(u32::try_from(counts.3).unwrap_or(u32::MAX)),
        )
        .unwrap_or_default();

        status.services.dhcp_v6.leases_active = counts.4;
        status.services.dhcp_v6.state = if self.cfg.dhcp_v6_enabled {
            "active"
        } else {
            "inactive"
        }
        .to_string();
        status.services.dhcp_v6.pool_free = self.cfg.dhcp_v6_pool_size.map_or(9999, |total| {
            usize::try_from(total.saturating_sub(counts.4 as u64)).unwrap_or_default()
        });
        status.services.dhcp_v6.ula.clone_from(&self.cfg.ula_prefix);
        status.services.dhcp_v6.gua.clone_from(&self.current_gua);
        status.services.dhcp_v6.uptime_secs = self.uptime_secs;

        status.services.dns.state = if self.cfg.dns_enabled {
            "online"
        } else {
            "offline"
        }
        .to_string();
        status.services.dns.uptime_secs = self.uptime_secs;
        status
            .services
            .dns
            .upstream
            .clone_from(&self.cfg.dns_upstream);

        status.services.db_worker.state = "online".to_string();
        status.services.mdns_prober.state = "active".to_string();
        status.services.iface_monitor.state = "online".to_string();
        status.services.control_api.state = "online".to_string();
        if self.cfg.http_enabled {
            status.services.http_api = Some(ServiceStatusInfo {
                state: "online".to_string(),
            });
        }

        status.devices.total = devices.len();
        status.devices.online = counts.0;
        status.devices.static_toml = counts.1;
        status.devices.managed_cli = counts.6;
        status.devices.dynamic = counts.2;
        status.services.ndp_monitor.addrs_tracked = counts.5;
        status.services.ndp_monitor.state = "online".to_string();
        status.services.ndp_monitor.uptime_secs = self.uptime_secs;
    }

    pub(crate) async fn handle_reload(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
        Response::Success(SimpleSuccess {
            message: "Configuration reload triggered".to_string(),
        })
    }

    pub(crate) async fn handle_shutdown(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::Shutdown));
        Response::Success(SimpleSuccess {
            message: "Daemon shutdown initiated".to_string(),
        })
    }

    pub(crate) async fn handle_db_vacuum(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbVacuum));
        Response::Success(SimpleSuccess {
            message: "Database VACUUM task queued".to_string(),
        })
    }

    pub(crate) async fn handle_db_log_clean(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbLogClean));
        Response::Success(SimpleSuccess {
            message: "Transient log cleanup task queued".to_string(),
        })
    }

    pub(crate) async fn handle_db_prune(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbPrune));
        Response::Success(SimpleSuccess {
            message: "Database pruning task queued".to_string(),
        })
    }

    pub(crate) async fn handle_db_reset(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbReset));
        Response::Success(SimpleSuccess {
            message: "Factory reset initiated. Database will be cleared and daemon restarted."
                .to_string(),
        })
    }

    pub(crate) async fn handle_config_set_password(&self, password: String) -> Response {
        let hash = hash_password(&password);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ConfigUpdate {
                password_hash: hash,
            }));
        Response::Success(SimpleSuccess {
            message: "API password updated and persisted to database".to_string(),
        })
    }

    pub(crate) async fn handle_context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> Response {
        let mut state = self.ctx.read().clone();
        if only_devices {
            state.discovery.orphaned_v6.clear();
        }
        if only_orphans {
            state.devices.clear();
        }
        Response::ContextDump(Box::new(state))
    }

    pub(crate) async fn handle_watch(&self) -> Response {
        // Handled by the server loop to upgrade connection
        Response::Success(SimpleSuccess {
            message: "Watch mode initiated".to_string(),
        })
    }

    pub(crate) async fn handle_log(&self, _follow: bool, _n: Option<usize>) -> Response {
        // Handled by the server loop to upgrade connection
        Response::Success(SimpleSuccess {
            message: "Log stream initiated".to_string(),
        })
    }

    pub(crate) async fn handle_scan(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Network(NetworkEvent::ScanRequested));
        Response::Success(SimpleSuccess {
            message: "Network scan triggered".to_string(),
        })
    }
}
