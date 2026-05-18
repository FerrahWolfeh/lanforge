use crate::ClientContext;
use lanforge_api::api::{
    Capabilities, Compression, DbStatus, DevicesStats, Encoding, NetworkStatus, ResourcesStatus,
    Response, ServiceStatusInfo, ServicesStatus, StatusResponse,
};
use lanforge_core::context::CompiledCaps;
use lanforge_types::device::{Device, IPv6State, Origin};
use std::fs::metadata;
use std::sync::Arc;

impl ClientContext {
    /// Generates a full `StatusResponse` by gathering data from the configuration
    /// and the active device table.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_status(&self) -> Response {
        let mut status = StatusResponse {
            uptime_secs: self.uptime_secs,
            version: env!("CARGO_PKG_VERSION").to_string(),
            services: ServicesStatus::default(),
            db: self.gather_db_status(),
            network: self.gather_network_status().await,
            resources: Self::gather_resource_status(),
            devices: DevicesStats::default(),
            capabilities: Self::gather_capabilities(),
            server_caps: CompiledCaps::detect(),
            service_banners: self
                .ctx
                .status_providers()
                .iter()
                .map(|p| p.banner())
                .collect(),
        };

        let devices = self.ctx.all_devices();
        self.populate_service_and_device_stats(&mut status, &devices);

        Response::Status(Box::new(status))
    }

    #[must_use]
    pub fn gather_db_status(&self) -> DbStatus {
        let status = self.ctx.get_status().unwrap_or_default();
        let mut db = DbStatus {
            path: status.db_path.clone(),
            ..Default::default()
        };
        if !status.db_path.is_empty()
            && let Ok(meta) = metadata(&status.db_path)
        {
            db.size_bytes = meta.len();
        }
        if let Some(last_flush) = self.ctx.last_db_flush() {
            db.last_flush_secs_ago = last_flush.elapsed().unwrap_or_default().as_secs();
        }
        db
    }

    #[must_use]
    pub fn gather_resource_status() -> ResourcesStatus {
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

    pub async fn gather_network_status(&self) -> NetworkStatus {
        let status = self.ctx.get_status().unwrap_or_default();
        let mut net = NetworkStatus {
            lan_iface: status.lan_iface.clone(),
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
            net.ula.clone_from(&status.ula_prefix);
        }
        net
    }

    #[must_use]
    pub fn gather_capabilities() -> Capabilities {
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

    pub fn populate_service_and_device_stats(
        &self,
        status: &mut StatusResponse,
        devices: &[Arc<Device>],
    ) {
        let sys_status = self.ctx.get_status().unwrap_or_default();

        // Services -> RA
        status.services.ra.state = if sys_status.ra_enabled {
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
            if dev.origin == Origin::Static {
                counts.6 += 1;
            }
        }

        status.services.dhcp_v4.leases_active = counts.3;
        status.services.dhcp_v4.state = if sys_status.dhcp_v4_enabled {
            "active"
        } else {
            "inactive"
        }
        .to_string();
        status.services.dhcp_v4.pool_free = usize::try_from(
            sys_status
                .dhcp_v4_range_size
                .saturating_sub(u32::try_from(counts.3).unwrap_or(u32::MAX)),
        )
        .unwrap_or_default();

        status.services.dhcp_v6.leases_active = counts.4;
        status.services.dhcp_v6.state = if sys_status.dhcp_v6_enabled {
            "active"
        } else {
            "inactive"
        }
        .to_string();
        status.services.dhcp_v6.pool_free = sys_status.dhcp_v6_pool_size.map_or(9999, |total| {
            usize::try_from(total.saturating_sub(counts.4 as u64)).unwrap_or_default()
        });
        status
            .services
            .dhcp_v6
            .ula
            .clone_from(&sys_status.ula_prefix);
        status.services.dhcp_v6.gua.clone_from(&self.current_gua);
        status.services.dhcp_v6.uptime_secs = self.uptime_secs;

        status.services.dns.state = if sys_status.dns_enabled {
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
            .clone_from(&sys_status.dns_upstream);

        status.services.db_worker.state = "online".to_string();
        status.services.mdns_prober.state = "active".to_string();
        status.services.iface_monitor.state = "online".to_string();
        status.services.control_api.state = "online".to_string();

        if sys_status.http_enabled {
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
}
