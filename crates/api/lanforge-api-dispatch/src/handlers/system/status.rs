use crate::ClientContext;
use lanforge_api::api::{
    Capabilities, Compression, DbStatus, DevicesStats, Encoding, NetworkStatus, ResourcesStatus,
    Response, ServiceBannersResponse, StatusResponse,
};
use lanforge_types::device::Origin;
use lanforge_types::network::firewall::{FirewallPolicy, FirewallStatus};
use lanforge_types::system::ServiceId;
use std::fs::metadata;
use std::time::{SystemTime, UNIX_EPOCH};

impl ClientContext {
    /// Generates a full `StatusResponse` by gathering data from the configuration
    /// and the active device table.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_status(&self) -> Response {
        let devices = self.ctx.with_state(|state| {
            let now = SystemTime::now();
            let mut stats = DevicesStats {
                total: state.devices.len(),
                ..DevicesStats::default()
            };
            for dev in state.devices.values() {
                if now
                    .duration_since(dev.last_seen)
                    .unwrap_or_default()
                    .as_secs()
                    < 300
                {
                    stats.online += 1;
                }
                if dev.is_static() {
                    stats.static_toml += 1;
                } else {
                    stats.dynamic += 1;
                }
                if dev.origin == Origin::Static {
                    stats.managed_cli += 1;
                }
            }
            stats
        });
        let status = StatusResponse {
            uptime_secs: self.uptime_secs,
            version: self.ctx.build().to_string(),
            db: self.gather_db_status(),
            network: self.gather_network_status().await,
            resources: Self::gather_resource_status(),
            devices,
            capabilities: Self::gather_capabilities(),
            server_caps: self.ctx.server_capabilities(),
            service_banners: self.service_banners().await,
            config_issues: self.ctx.config_issues(),
        };
        Response::Status(Box::new(status))
    }

    pub async fn handle_service_banners(&self) -> Response {
        Response::ServiceBanners(ServiceBannersResponse {
            banners: self.service_banners().await,
        })
    }

    pub async fn handle_pppoe_status(&self) -> Response {
        let pppoe_status = self.ctx.pppoe_status();
        let mut status = pppoe_status.map_or_else(
            || {
                Box::new(lanforge_types::system::PppoeStatusResponse {
                    enabled: self
                        .ctx
                        .get_status()
                        .map(|s| s.pppoe_enabled)
                        .unwrap_or(false),
                    state: lanforge_types::system::PppoeSessionState::Disconnected,
                    ..Default::default()
                })
            },
            |p| Box::new((*p).clone()),
        );
        if status.auth.is_none() {
            status.auth = self.ctx.get_pppoe_config().map(|cfg| cfg.auth);
        }

        // The session's own age: the service stays up (degraded) across reconnects.
        if status.state == lanforge_types::system::PppoeSessionState::Connected {
            status.uptime_secs = status.connected_at.map(|t| t.elapsed().as_secs());
        }

        Response::PppoeStatus(status)
    }

    pub async fn handle_ra_status(&self) -> Response {
        let ra_status = self.ctx.ra_status();
        let status = ra_status.map_or_else(
            || {
                let target_ifindex = self.ctx.target_ifindex().unwrap_or(0);
                let if_ips = self.ctx.get_interface_state(target_ifindex);
                let cfg = self.ctx.get_ra_server_config();
                Box::new(lanforge_types::system::RaStatusResponse {
                    enabled: self.ctx.get_status().map(|s| s.ra_enabled).unwrap_or(false),
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
                    min_interval_secs: cfg
                        .min_interval_secs
                        .unwrap_or_else(|| (cfg.max_interval_secs / 3).max(3)),
                    router_lifetime_secs: cfg.lifetime_secs.unwrap_or(cfg.max_interval_secs * 3),
                    mtu: cfg.mtu,
                    uptime_secs: Some(self.uptime_secs),
                    ..Default::default()
                })
            },
            |r| Box::new((*r).clone()),
        );
        Response::RaStatus(status)
    }

    pub async fn handle_traffic_status(&self) -> Response {
        let traffic_status = self.ctx.traffic_status();
        let status = traffic_status.map_or_else(
            || {
                let cfg = self.ctx.get_traffic_config().unwrap_or_default();
                let service_state = self.ctx.get_service_state(ServiceId::Traffic);
                Box::new(lanforge_types::system::TrafficStatusResponse {
                    service_state,
                    tuning_applied: false,
                    tuned_interfaces: cfg.tuning.interfaces.clone(),
                    effective_cpu_mask: cfg.tuning.cpu_mask.clone(),
                    sqm_active: false,
                    wan_interface: None,
                    ingress_device: None,
                    download_mbps: cfg.sqm.download_mbps,
                    upload_mbps: cfg.sqm.upload_mbps,
                    overhead: cfg.sqm.overhead,
                    diffserv: cfg.sqm.diffserv,
                    flow_offload_suppressed: cfg.sqm.enabled,
                })
            },
            |t| Box::new((*t).clone()),
        );
        Response::TrafficStatus(status)
    }

    pub async fn handle_traffic_telemetry(&self) -> Response {
        let telemetry = self.ctx.traffic_telemetry().map_or_else(
            || {
                let traffic_st = self.ctx.traffic_status();
                let (w, ingress_device) = traffic_st.as_ref().map_or((None, None), |status| {
                    (status.wan_interface.clone(), status.ingress_device.clone())
                });
                let fallback_wan = w.or_else(|| {
                    self.ctx
                        .pppoe_status()
                        .as_ref()
                        .and_then(|p| p.interface.clone())
                });
                let wan_iface =
                    fallback_wan.or_else(|| self.ctx.get_pppoe_config().map(|p| p.wan_iface));

                lanforge_types::network::traffic::TrafficTelemetryResponse {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    wan_interface: wan_iface,
                    ingress_device,
                    interfaces: Vec::new(),
                    sqm: None,
                    conntrack: None,
                    history: Vec::new(),
                }
            },
            |t| (*t).clone(),
        );

        Response::TrafficTelemetry(Box::new(telemetry))
    }

    pub async fn handle_firewall_status(&self) -> Response {
        let cfg = self.ctx.get_firewall_config().unwrap_or_default();
        let dynamic_ports = self.ctx.registered_service_ports();
        let internal_zone = cfg.zones.iter().find(|z| z.name == "internal");
        let lan_ifaces = internal_zone.map_or_else(Vec::new, |z| z.interfaces.clone());
        let external_zone = cfg
            .zones
            .iter()
            .find(|z| z.name == "external" || z.name == "wan");
        let pppoe_wan = self
            .ctx
            .pppoe_status()
            .as_ref()
            .and_then(|p| p.interface.clone().or_else(|| p.wan_iface.clone()));
        let active_wan = external_zone
            .and_then(|z| z.interfaces.first().cloned())
            .or(pppoe_wan)
            .or_else(|| self.ctx.get_pppoe_config().map(|p| p.wan_iface));
        #[allow(clippy::cast_possible_truncation)]
        let open_ports_count = (cfg.zones.iter().map(|z| z.open_ports.len()).sum::<usize>()
            + dynamic_ports.len()) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let rules_count =
            open_ports_count + (cfg.port_forwards.len() + cfg.forwardings.len()) as u32;

        let sqm_enabled = self
            .ctx
            .get_traffic_config()
            .map(|c| c.sqm.enabled)
            .unwrap_or(false);

        let status = FirewallStatus {
            mode: cfg.mode,
            table: cfg.table_name,
            active_wan,
            lan_ifaces,
            last_applied_secs_ago: None,
            open_ports_count,
            rules_count,
            enabled: cfg.enabled,
            flow_offload_active: cfg.flow_offload && !sqm_enabled,
            flow_offload_suspended: cfg.flow_offload && sqm_enabled,
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
        let last_flush_ts = self
            .ctx
            .db_metrics()
            .last_flush_ts
            .load(std::sync::atomic::Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if last_flush_ts > 0 && now >= last_flush_ts {
            db.last_flush_secs_ago = now - last_flush_ts;
        } else if let Some(last_flush) = self.ctx.last_db_flush() {
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
            self.ctx.with_state(|state| {
                if let Some(if_ips) = state.interfaces.interface_ips.get(&ifindex) {
                    if let Some((ip, prefix)) = if_ips.v4 {
                        net.lan_ipv4 = Some(ip);
                        net.lan_ipv4_cidr = Some(prefix);
                    }
                    net.gua = if_ips.gua;
                    net.ula = if_ips.ula;
                    net.lan_ipv6 = if_ips.link_local;
                }
            });
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

    #[must_use]
    pub fn server_capabilities(&self) -> lanforge_types::system::ServerCapabilities {
        self.ctx.server_capabilities()
    }
}
