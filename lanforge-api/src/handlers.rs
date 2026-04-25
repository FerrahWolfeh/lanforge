//! Response handlers for the UDS control interface.
//!
//! Implementation of `ClientContext` methods that build the detailed
//! JSON responses for `Status`, `Devices`, and `HostList` commands.

use std::fs::metadata;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::device::{IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_db::engine::{LeaseDb, LeaseHistoryEntry};

use crate::api::{
    DbStatus, DeviceEntry, DevicesMeta, DevicesResponse, DevicesStats, DnsQueryResponse,
    DnsStatsResponse, HostConfigEntry, HostsResponse, Ipv6Entry, LeaseInfo, NetworkStatus,
    ResourcesStatus, Response, ServiceStatusInfo, ServicesStatus, SimpleSuccess, StatusResponse,
    WhoisResponse,
};
use crate::server::ClientContext;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn format_iso8601(time: SystemTime) -> String {
    let dt: DateTime<Utc> = time.into();
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn get_v6_kind(addr: &Ipv6Addr) -> &'static str {
    if addr.is_loopback() || addr.is_unspecified() {
        return "Internal";
    }
    let segments = addr.segments();
    if (segments[0] & 0xfe00) == 0xfc00 {
        return "ULA";
    }
    if (segments[0] & 0xffc0) == 0xfe80 {
        return "LinkLocal";
    }
    "GUA"
}

// ---------------------------------------------------------------------------
// ClientContext handlers
// ---------------------------------------------------------------------------

impl ClientContext {
    /// Generates a full `StatusResponse` by gathering data from the configuration
    /// and the active device table.
    pub(crate) async fn handle_status(&self) -> Response {
        let devices = self.ctx.all_devices();

        let mut status = StatusResponse {
            uptime_secs: self.uptime_secs,
            version: env!("CARGO_PKG_VERSION").to_string(),
            services: ServicesStatus::default(),
            db: DbStatus::default(),
            network: NetworkStatus::default(),
            resources: ResourcesStatus::default(),
            devices: DevicesStats::default(),
            capabilities: crate::api::Capabilities {
                encodings: vec![crate::api::Encoding::Json, crate::api::Encoding::Bincode],
                compression: {
                    let mut c = vec![crate::api::Compression::None];
                    #[cfg(feature = "zstd")]
                    c.push(crate::api::Compression::Zstd);
                    c
                },
            },
        };

        // DB stats
        status.db.path.clone_from(&self.cfg.db_path);
        if let Ok(meta) = metadata(&self.cfg.db_path) {
            status.db.size_bytes = meta.len();
        }
        if let Some(last_flush) = self.ctx.last_db_flush() {
            status.db.last_flush_secs_ago = last_flush.elapsed().unwrap_or_default().as_secs();
        }

        // Resources (RSS/VMS)
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let mut parts = statm.split_whitespace();
            if let (Some(vms_pages), Some(rss_pages)) = (parts.next(), parts.next()) {
                let page_size = 4096; // Traditional conservative page size
                status.resources.memory_vms_bytes =
                    vms_pages.parse::<u64>().unwrap_or(0) * page_size;
                status.resources.memory_rss_bytes =
                    rss_pages.parse::<u64>().unwrap_or(0) * page_size;
            }
        }

        // Network
        status.network.lan_iface.clone_from(&self.cfg.lan_iface);
        if let Some(ifindex) = self.ctx.target_ifindex() {
            let state = self.ctx.read();
            if let Some(if_ips) = state.interface_ips.get(&ifindex) {
                if let Some((ip, prefix)) = if_ips.v4 {
                    status.network.lan_ipv4 = Some(ip.to_string());
                    status.network.lan_ipv4_cidr = Some(format!("{}/{}", ip, prefix));
                }
                status.network.gua = if_ips.gua.map(|ip| ip.to_string());
                status.network.ula = if_ips.ula.map(|ip| ip.to_string());
                status.network.lan_ipv6 = if_ips.link_local.map(|ip| ip.to_string());
            }
        }
        // Fallback to config if state is missing prefix info
        if status.network.gua.is_none() {
            status.network.gua.clone_from(&self.current_gua);
        }
        if status.network.ula.is_none() {
            status.network.ula.clone_from(&self.cfg.ula_prefix);
        }

        // Services -> RA
        status.services.ra.state = if self.cfg.ra_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.ra.uptime_secs = self.uptime_secs;
        status.services.ra.gua.clone_from(&self.current_gua);
        status.services.ra.ula.clone_from(&status.network.ula);

        // Devices + Leases
        let dev_ct = devices.len();
        let mut online_ct = 0;
        let mut static_toml = 0;
        let mut dynamic = 0;

        let mut v4_dynamic_count = 0;
        let mut v6_dynamic_count = 0;
        let mut slaac_addrs = 0;

        for dev in &devices {
            let is_online = dev.last_seen.elapsed().unwrap_or_default().as_secs() < 300;
            if is_online {
                online_ct += 1;
            }

            if dev.is_static() {
                static_toml += 1;
            } else {
                dynamic += 1;
                if dev.v4.ip().is_some() {
                    v4_dynamic_count += 1;
                }
                if dev.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_))) {
                    v6_dynamic_count += 1;
                }
            }

            slaac_addrs += dev
                .v6
                .iter()
                .filter(|s| matches!(s, IPv6State::Slaac { .. }))
                .count();
        }

        status.services.dhcp_v4.leases_active = v4_dynamic_count as usize;
        status.services.dhcp_v4.state = if self.cfg.dhcp_v4_enabled {
            "active"
        } else {
            "inactive"
        }
        .to_string();
        status.services.dhcp_v4.pool_free =
            self.cfg
                .dhcp_v4_range_size
                .saturating_sub(v4_dynamic_count as u32) as usize;

        status.services.dhcp_v6.leases_active = v6_dynamic_count as usize;
        status.services.dhcp_v6.state = if self.cfg.dhcp_v6_enabled {
            "active"
        } else {
            "inactive"
        }
        .to_string();
        status.services.dhcp_v6.pool_free = self
            .cfg
            .dhcp_v6_pool_size
            .map(|total| total.saturating_sub(v6_dynamic_count as u64) as usize)
            .unwrap_or(9999);
        status.services.dhcp_v6.ula = self.cfg.ula_prefix.clone();
        status.services.dhcp_v6.gua = self.current_gua.clone();
        status.services.dhcp_v6.uptime_secs = self.uptime_secs;

        // Services -> DNS
        status.services.dns.state = if self.cfg.dns_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.dns.uptime_secs = self.uptime_secs;
        status
            .services
            .dns
            .upstream
            .clone_from(&self.cfg.dns_upstream);

        // --- Core Services ---
        status.services.db_worker.state = "online".to_string();
        status.services.mdns_prober.state = "active".to_string();
        status.services.iface_monitor.state = "online".to_string();
        status.services.control_api.state = "online".to_string();
        if self.cfg.http_listen.is_some() {
            status.services.http_api = Some(ServiceStatusInfo {
                state: "online".to_string(),
            });
        }

        status.devices.total = dev_ct;
        status.devices.online = online_ct;
        status.devices.static_toml = static_toml;
        status.devices.managed_cli = devices.iter().filter(|d| d.origin == Origin::Cli).count();
        status.devices.dynamic = dynamic;
        status.services.ndp_monitor.addrs_tracked = slaac_addrs;
        status.services.ndp_monitor.state = "online".to_string();
        status.services.ndp_monitor.uptime_secs = self.uptime_secs;

        Response::Status(Box::new(status))
    }

    /// Generates a `DevicesResponse`, optionally filtering by a search string.
    ///
    /// The filter is matched against hostnames, MAC addresses, and IP addresses.
    /// Generates a `DevicesResponse`, optionally filtering by search string, vendor, or method.
    pub(crate) async fn handle_devices(
        &self,
        filter: Option<String>,
        _vendor: Option<String>,
        method: Option<String>,
    ) -> Response {
        let devices = self.ctx.all_devices();

        let mut api_devices = Vec::new();
        let mut online = 0;

        for dev in &devices {
            let matches_filter = filter.as_ref().is_none_or(|f| {
                let f_lower = f.to_lowercase();
                dev.hostname.name.to_lowercase().contains(&f_lower)
                    || dev.mac.to_string().to_lowercase().contains(&f_lower)
                    || dev
                        .v4
                        .ip()
                        .map(|ip| ip.to_string())
                        .is_some_and(|s| s.contains(&f_lower))
                    || dev.v6.iter().any(|s| {
                        s.ip()
                            .map(|ip| ip.to_string())
                            .is_some_and(|s| s.contains(&f_lower))
                    })
            });

            let matches_method = method.as_ref().is_none_or(|m| {
                let m_lower = m.to_lowercase();
                dev.learning_method()
                    .to_string()
                    .to_lowercase()
                    .contains(&m_lower)
            });

            if !matches_filter || !matches_method {
                continue;
            }

            let is_online = dev.is_online();
            if is_online {
                online += 1;
            }

            let gua_prefix = self
                .current_gua
                .as_ref()
                .and_then(|s| s.parse::<Ipv6Addr>().ok());
            let ula_prefix = self
                .cfg
                .ula_prefix
                .as_ref()
                .and_then(|s| s.parse::<Ipv6Addr>().ok());

            api_devices.push(DeviceEntry {
                mac: dev.mac.to_string(),
                hostname: dev.display_hostname().to_string(),
                origin: dev.origin.as_str().to_string(),
                online: is_online,
                last_seen: format_iso8601(dev.last_seen),
                learning_method: dev.learning_method().to_string(),
                duid: dev.duid.as_ref().map(|d: &Duid| d.to_string()),
                display_v4: dev.display_v4(),
                display_v6: dev.display_v6(gua_prefix, ula_prefix),
                v4: match &dev.v4 {
                    IPv4State::Static(ip) => Some(LeaseInfo {
                        ip: ip.to_string(),
                        expires: "Static".to_string(),
                        reserved: true,
                    }),
                    IPv4State::Dynamic(v) => Some(LeaseInfo {
                        ip: v.ip.to_string(),
                        expires: format_iso8601(v.expires),
                        reserved: dev.is_static(),
                    }),
                    IPv4State::None => None,
                },
                seen_v4: dev.seen_v4.iter().map(|(ip, _)| ip.to_string()).collect(),
                v6: dev.primary_v6(gua_prefix, ula_prefix).map(|ip| {
                    let state = dev.v6.iter().find(|s| {
                        s.ip_with_prefix(gua_prefix) == Some(ip)
                            || s.ip_with_prefix(ula_prefix) == Some(ip)
                    });
                    LeaseInfo {
                        ip: ip.to_string(),
                        expires: state
                            .and_then(|s| match s {
                                IPv6State::Dynamic(l) => Some(format_iso8601(l.expires)),
                                IPv6State::Static(_) => Some("Static".to_string()),
                                _ => None,
                            })
                            .unwrap_or_else(|| "—".to_string()),
                        reserved: state.is_some_and(|s| matches!(s, IPv6State::Static(_)))
                            || dev.is_static(),
                    }
                }),
                ipv6_addrs: {
                    let mut list = Vec::new();
                    for state in &dev.v6 {
                        if let Some(ip) = state.ip_with_prefix(None) {
                            list.push(Ipv6Entry {
                                addr: ip.to_string(),
                                kind: get_v6_kind(&ip).to_string(),
                            });
                        } else if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_)) = state {
                            if let Some(ip) = ula_prefix.and_then(|p| state.ip_with_prefix(Some(p)))
                            {
                                list.push(Ipv6Entry {
                                    addr: ip.to_string(),
                                    kind: "ULA (Static)".to_string(),
                                });
                            }
                            if let Some(ip) = gua_prefix.and_then(|p| state.ip_with_prefix(Some(p)))
                            {
                                list.push(Ipv6Entry {
                                    addr: ip.to_string(),
                                    kind: "GUA (Static)".to_string(),
                                });
                            }
                        }
                    }
                    list
                },
            });
        }

        Response::Devices(DevicesResponse {
            devices: api_devices,
            meta: DevicesMeta {
                total: devices.len(),
                online,
                last_scan_secs_ago: self.last_scan_secs_ago,
            },
        })
    }

    /// Generates a `HostsResponse` containing all manually configured host entries.
    ///
    /// Devices with `Origin::Dynamic` are excluded from this list.
    pub(crate) async fn handle_hosts(&self) -> Response {
        let devices = self.ctx.all_devices();
        let mut hosts = Vec::new();

        for dev in &devices {
            if dev.origin == Origin::Dynamic {
                continue;
            }

            hosts.push(HostConfigEntry {
                mac: dev.mac.to_string(),
                hostname: dev.hostname.name.clone(),
                v4_fixed: match &dev.v4 {
                    IPv4State::Static(ip) => Some(ip.to_string()),
                    _ => None,
                },
                v6_suffix: dev.v6.iter().find_map(|s| {
                    if let IPv6State::Static(suffix) = s {
                        Some(suffix.to_string())
                    } else {
                        None
                    }
                }),
                origin: dev.origin.as_str().to_string(),
            });
        }

        Response::Hosts(HostsResponse { hosts })
    }

    /// Triggers a Wake-on-LAN magic packet.
    pub(crate) async fn handle_wol(&self, target: String) -> Response {
        let mac = if let Some(m) = MacAddr::parse(&target) {
            m
        } else {
            // Search by hostname
            let devices = self.ctx.all_devices();
            let found = devices
                .iter()
                .find(|d| d.hostname.name.to_lowercase() == target.to_lowercase());
            match found {
                Some(d) => d.mac,
                None => {
                    return Response::Error {
                        error: format!("Target '{target}' not found (not a MAC or known Hostname)"),
                    };
                }
            }
        };

        // Get the device's main IPv4 for use as a hint (directed broadcast/unicast)
        let ip_hint = self.ctx.get_device(&mac).and_then(|d| d.v4.ip());

        // Emit WoL event
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::WolTriggered { mac, ip_hint });

        Response::Success(SimpleSuccess {
            message: format!("Wake-on-LAN magic packet queued for {mac}"),
        })
    }

    /// Gathers detailed information and history for a device.
    pub(crate) async fn handle_whois(&self, target: String) -> Response {
        let device = if let Some(m) = MacAddr::parse(&target) {
            self.ctx.get_device(&m)
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            self.ctx
                .get_mac_by_ip(ip)
                .and_then(|m| self.ctx.get_device(&m))
        } else {
            self.ctx
                .all_devices()
                .into_iter()
                .find(|d| d.hostname.name.to_lowercase() == target.to_lowercase())
        };

        if let Some(dev) = device {
            let mac = dev.mac;

            // Fetch history from DB
            let history: Vec<LeaseHistoryEntry> =
                if let Ok(db) = LeaseDb::open(&self.cfg.db_url).await {
                    db.get_lease_history(mac).await.unwrap_or_default()
                } else {
                    Vec::new()
                };

            // Build DeviceEntry (reusing implementation from handle_devices)
            let gua_prefix = self
                .current_gua
                .as_ref()
                .and_then(|s| s.parse::<Ipv6Addr>().ok());
            let ula_prefix = self
                .cfg
                .ula_prefix
                .as_ref()
                .and_then(|s| s.parse::<Ipv6Addr>().ok());

            let entry = DeviceEntry {
                mac: dev.mac.to_string(),
                hostname: dev.display_hostname().to_string(),
                origin: dev.origin.as_str().to_string(),
                online: dev.is_online(),
                last_seen: format_iso8601(dev.last_seen),
                learning_method: dev.learning_method().to_string(),
                duid: dev.duid.as_ref().map(|d: &Duid| d.to_string()),
                display_v4: dev.display_v4(),
                display_v6: dev.display_v6(gua_prefix, ula_prefix),
                v4: match &dev.v4 {
                    IPv4State::Static(ip) => Some(LeaseInfo {
                        ip: ip.to_string(),
                        expires: "Static".to_string(),
                        reserved: true,
                    }),
                    IPv4State::Dynamic(v) => Some(LeaseInfo {
                        ip: v.ip.to_string(),
                        expires: format_iso8601(v.expires),
                        reserved: dev.is_static(),
                    }),
                    IPv4State::None => None,
                },
                seen_v4: dev.seen_v4.iter().map(|(ip, _)| ip.to_string()).collect(),
                v6: dev
                    .primary_v6(gua_prefix, ula_prefix)
                    .map(|ip: Ipv6Addr| LeaseInfo {
                        ip: ip.to_string(),
                        expires: "Lease".to_string(),
                        reserved: dev.is_static(),
                    }),
                ipv6_addrs: {
                    dev.v6
                        .iter()
                        .filter_map(|s: &IPv6State| {
                            s.ip_with_prefix(None).map(|ip: Ipv6Addr| Ipv6Entry {
                                addr: ip.to_string(),
                                kind: get_v6_kind(&ip).to_string(),
                            })
                        })
                        .collect()
                },
            };

            Response::Whois(Box::new(WhoisResponse { entry, history }))
        } else {
            Response::Error {
                error: format!("Device '{target}' not found"),
            }
        }
    }

    /// Snapshot of DNS resolver statistics.
    pub(crate) async fn handle_dns_stats(&self) -> Response {
        use lanforge_dns::stats::DnsStats;

        if let Some(stats_any) = self.ctx.get_dns_stats()
            && let Some(stats) = stats_any.downcast_ref::<DnsStats>()
        {
            return Response::DnsStats(DnsStatsResponse {
                total_requests: stats.requests_total.load(Ordering::Relaxed),
                cache_hits: stats.cache_hits.load(Ordering::Relaxed),
                cache_misses: stats.cache_misses.load(Ordering::Relaxed),
                upstream_errors: stats.upstream_errors.load(Ordering::Relaxed),
                auth_queries: stats.auth_queries.load(Ordering::Relaxed),
                recursions: stats.recursions.load(Ordering::Relaxed),
            });
        }

        Response::DnsStats(DnsStatsResponse {
            total_requests: 0,
            cache_hits: 0,
            cache_misses: 0,
            upstream_errors: 0,
            auth_queries: 0,
            recursions: 0,
        })
    }

    /// DNS diagnostic query.
    pub(crate) async fn handle_dns_query(
        &self,
        _name: String,
        _record_type: Option<String>,
    ) -> Response {
        // This would probably send a msg to DnsService or use a shared client
        Response::DnsQuery(DnsQueryResponse {
            records: Vec::new(),
            latency_ms: 0,
            authoritative: false,
        })
    }

    /// Fully dumps the main in-memory state.
    pub(crate) async fn handle_context_dump(&self) -> Response {
        let state = self.ctx.read().clone();
        Response::ContextDump(Box::new(state))
    }

    /// Completely resets and re-seeds the database.
    pub(crate) async fn handle_db_reset(&self) -> Response {
        let _ = self.ctx.bus().publish(LanforgeEvent::DbReset);
        Response::Success(SimpleSuccess {
            message: "Database reset requested. Simulating cold start...".to_string(),
        })
    }
}
