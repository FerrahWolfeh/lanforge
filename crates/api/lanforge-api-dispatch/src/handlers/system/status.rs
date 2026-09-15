use crate::ClientContext;
use lanforge_api::api::{
    Capabilities, Compression, DbStatus, DevicesStats, Encoding, NetworkStatus, ResourcesStatus,
    Response, ServiceBannersResponse, ServiceDoh, ServiceDoq, ServiceDot, ServiceStatusInfo,
    ServicesStatus, StatusResponse,
};
use lanforge_core::context::CompiledCaps;
use lanforge_types::device::{IPv6State, Origin};
use lanforge_types::network::firewall::{FirewallPolicy, FirewallStatus};
use lanforge_types::system::ServiceState;
use std::fs::metadata;

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
            service_banners: self.ctx.service_banners(),
        };

        let (total_devices, counts) = self.ctx.with_state(|state| {
            let mut counts = (0, 0, 0, 0, 0, 0, 0); // online, static, dynamic, v4_dyn, v6_dyn, slaac, managed_cli
            for dev in state.devices.values() {
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
            (state.devices.len(), counts)
        });

        let first_upstream = self
            .db
            .load_dns_upstreams()
            .await
            .ok()
            .and_then(|rows| rows.into_iter().next())
            .map(|r| format!("{}://{}", r.protocol, r.addr));
        self.populate_service_and_device_stats(&mut status, total_devices, counts, first_upstream);

        Response::Status(Box::new(status))
    }

    pub async fn handle_service_banners(&self) -> Response {
        let banners = self.ctx.service_banners();
        Response::ServiceBanners(ServiceBannersResponse { banners })
    }

    pub async fn handle_pppoe_status(&self) -> Response {
        let pppoe_status = self.ctx.read().interfaces.pppoe_status.clone();
        let mut status = pppoe_status.unwrap_or_else(|| Box::new(lanforge_types::system::PppoeStatusResponse {
            enabled: self
                .ctx
                .get_status()
                .map(|s| s.pppoe_enabled)
                .unwrap_or(false),
            state: lanforge_types::system::PppoeSessionState::Disconnected,
            ..Default::default()
        }));
        if status.auth.is_none() {
            status.auth = self
                .db
                .load_pppoe_config()
                .await
                .ok()
                .flatten()
                .map(|cfg| cfg.auth);
        }

        Response::PppoeStatus(status)
    }


    pub async fn handle_ra_status(&self) -> Response {
        let ra_status = self.ctx.read().interfaces.ra_status.clone();
        let status = ra_status.unwrap_or_else(|| {
            let target_ifindex = self.ctx.target_ifindex().unwrap_or(0);
            let if_ips = self.ctx.get_interface_state(target_ifindex);
            let cfg = self.ctx.get_ra_server_config();
            Box::new(lanforge_types::system::RaStatusResponse {
                enabled: self
                    .ctx
                    .get_status()
                    .map(|s| s.ra_enabled)
                    .unwrap_or(false),
                interface: cfg.iface.clone(),
                link_local: if_ips.link_local,
                active_gua_prefix: if_ips.gua,
                active_ula_prefix: if_ips.ula,
                prefixes: cfg.prefixes.clone(),
                rdnss: cfg.rdnss.clone(),
                dnssl: cfg.dnssl.clone(),
                managed: cfg.managed,
                other_config: cfg.other_config,
                hop_limit: cfg.hop_limit,
                priority: cfg.priority,
                max_interval_secs: cfg.max_interval_secs,
                min_interval_secs: cfg.min_interval_secs.unwrap_or_else(|| (cfg.max_interval_secs / 3).max(3)),
                router_lifetime_secs: cfg.lifetime_secs.unwrap_or(cfg.max_interval_secs * 3),
                mtu: cfg.mtu,
                uptime_secs: Some(self.uptime_secs),
                ..Default::default()
            })
        });
        Response::RaStatus(status)
    }

    pub async fn handle_firewall_status(&self) -> Response {
        let cfg = self.ctx.get_firewall_config().unwrap_or_default();
        let dynamic_ports = self.ctx.registered_service_ports();
        let internal_zone = cfg.zones.iter().find(|z| z.name == "internal");
        let lan_ifaces = internal_zone.map_or_else(Vec::new, |z| z.interfaces.clone());
        let external_zone = cfg.zones.iter().find(|z| z.name == "external");
        let active_wan = external_zone.and_then(|z| z.interfaces.first().cloned());
        #[allow(clippy::cast_possible_truncation)]
        let open_ports_count = (cfg.zones.iter().map(|z| z.open_ports.len()).sum::<usize>()
            + dynamic_ports.len()) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let rules_count = open_ports_count
            + (cfg.port_forwards.len() + cfg.forwardings.len()) as u32;

        let status = FirewallStatus {
            table: cfg.table_name,
            active_wan,
            lan_ifaces,
            last_applied_secs_ago: None,
            open_ports_count,
            rules_count,
            enabled: cfg.enabled,
            flow_offload_active: cfg.flow_offload,
            default_drop_active: cfg.default_input_policy == FirewallPolicy::Drop,
        };

        Response::FirewallStatus(Box::new(status))
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
                    net.lan_ipv4 = Some(ip);
                    net.lan_ipv4_cidr = Some(prefix);
                }
                net.gua = if_ips.gua;
                net.ula = if_ips.ula;
                net.lan_ipv6 = if_ips.link_local;
            }
        }
        if net.gua.is_none() {
            net.gua = self.current_gua;
        }
        if net.ula.is_none() {
            net.ula = status.ula_prefix.map(|prefix| prefix.to_addr());
        }
        net
    }

    #[must_use]
    pub fn gather_capabilities() -> Capabilities {
        Capabilities {
            encodings: vec![Encoding::Json, Encoding::Postcard],
            compression: vec![Compression::None],
        }
    }

    pub fn populate_service_and_device_stats(
        &self,
        status: &mut StatusResponse,
        total_devices: usize,
        counts: (usize, usize, usize, usize, usize, usize, usize),
        first_upstream: Option<String>,
    ) {
        let sys_status = self.ctx.get_status().unwrap_or_default();

        // Services -> RA
        status.services.ra.state = if sys_status.ra_enabled {
            ServiceState::Online
        } else {
            ServiceState::Offline
        };
        status.services.ra.uptime_secs = self.uptime_secs;
        status.services.ra.gua.clone_from(&self.current_gua);
        status.services.ra.ula.clone_from(&status.network.ula);

        status.services.dhcp_v4.leases_active = counts.3;
        status.services.dhcp_v4.state = if sys_status.dhcp_v4_enabled {
            ServiceState::Online
        } else {
            ServiceState::Offline
        };
        status.services.dhcp_v4.pool_free = usize::try_from(
            sys_status
                .dhcp_v4_range_size
                .saturating_sub(u32::try_from(counts.3).unwrap_or(u32::MAX)),
        )
        .unwrap_or_default();

        status.services.dhcp_v6.leases_active = counts.4;
        status.services.dhcp_v6.state = if sys_status.dhcp_v6_enabled {
            ServiceState::Online
        } else {
            ServiceState::Offline
        };
        status.services.dhcp_v6.pool_free = sys_status.dhcp_v6_pool_size.map_or(9_999, |total| {
            usize::try_from(total.saturating_sub(counts.4 as u64)).unwrap_or_default()
        });
        status.services.dhcp_v6.ula = sys_status.ula_prefix.as_ref().map(|p| p.to_addr());
        status.services.dhcp_v6.gua.clone_from(&self.current_gua);
        status.services.dhcp_v6.uptime_secs = self.uptime_secs;

        status.services.dns.state = if sys_status.dns_enabled {
            ServiceState::Online
        } else {
            ServiceState::Offline
        };
        status.services.dns.uptime_secs = self.uptime_secs;
        status.services.dns.upstream = first_upstream;
        status.services.dns.port = sys_status.dns_port;

        // Populate DoT/DoQ/DoH subservice statuses from service banners
        for banner in self.ctx.service_banners() {
            match banner.name.as_str() {
                "DNS over TLS" => {
                    let port = banner
                        .stats
                        .iter()
                        .find(|(k, _)| k.as_ref() == "port")
                        .and_then(|(_, v)| v.parse().ok())
                        .unwrap_or(853);
                    status.services.dns.dot = Some(ServiceDot {
                        state: banner.state,
                        uptime_secs: banner.uptime_secs,
                        upstream: None,
                        port,
                    });
                }
                "DNS over QUIC" => {
                    let port = banner
                        .stats
                        .iter()
                        .find(|(k, _)| k.as_ref() == "port")
                        .and_then(|(_, v)| v.parse().ok())
                        .unwrap_or(853);
                    status.services.dns.doq = Some(ServiceDoq {
                        state: banner.state,
                        uptime_secs: banner.uptime_secs,
                        port,
                    });
                }
                "HTTP API" => {
                    let doh_enabled = banner
                        .stats
                        .iter()
                        .find(|(k, _)| k.as_ref() == "doh_enabled")
                        .is_some_and(|(_, v)| v == "true");
                    if doh_enabled {
                        let port = banner
                            .stats
                            .iter()
                            .find(|(k, _)| k.as_ref() == "listen")
                            .and_then(|(_, v)| v.parse::<std::net::SocketAddr>().ok())
                            .map_or(443, |a| a.port());
                        status.services.dns.doh = Some(ServiceDoh {
                            state: banner.state,
                            uptime_secs: banner.uptime_secs,
                            port,
                        });
                    }
                }
                _ => {}
            }
        }

        status.services.db_worker.state = ServiceState::Online;
        status.services.mdns_prober.state = ServiceState::Online;
        status.services.iface_monitor.state = ServiceState::Online;
        status.services.control_api.state = ServiceState::Online;

        if sys_status.http_enabled {
            status.services.http_api = Some(ServiceStatusInfo {
                state: ServiceState::Online,
            });
        }

        status.devices.total = total_devices;
        status.devices.online = counts.0;
        status.devices.static_toml = counts.1;
        status.devices.managed_cli = counts.6;
        status.devices.dynamic = counts.2;
        status.services.ndp_monitor.addrs_tracked = counts.5;
        status.services.ndp_monitor.state = ServiceState::Online;
        status.services.ndp_monitor.uptime_secs = self.uptime_secs;
    }
}
