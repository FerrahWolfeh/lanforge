//! Response handlers for the UDS control interface.
//!
//! Implementation of `ClientContext` methods that build the detailed
//! JSON responses for `Status`, `Devices`, and `HostList` commands.
#![allow(clippy::unused_async)]

use std::fs::metadata;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use lanforge_core::bus::{
    DeviceEvent, DnsEvent, LanforgeEvent, NetworkEvent, StorageEvent, SystemEvent,
};
use lanforge_core::context::state::{CliHostUpdate, DeviceUpdate, FieldUpdate, LeaseTarget};
use lanforge_core::device::{IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::utils::auth::hash_password;
use lanforge_db::engine::{LeaseDb, LeaseHistoryEntry};
use lanforge_db::log_engine::LogDb;
use std::str::FromStr;

use crate::api::{
    Capabilities, DbStatus, DeviceEntry, DevicesMeta, DevicesResponse, DevicesStats, DhcpPoolEntry,
    DhcpPoolsResponse, DnsCacheEntry, DnsCacheResponse, DnsQueryResponse, DnsStatsResponse,
    Encoding, HostConfigEntry, HostsResponse, Ipv6Entry, LeaseEntry, LeaseInfo, LeaseKind,
    LeasesResponse, NetworkStatus, ResourcesStatus, Response, ServicesStatus, SimpleSuccess,
    StatusResponse, TopologyEntry, TopologyResponse, WhoisResponse,
};

// Moved to lanforge-http

use crate::server::ClientContext;
use hickory_proto::rr::{Name, RecordType};
use lanforge_core::bus::dns::DnsRecordEntry;
use lanforge_dns::resolver::LocalResolver;
use lanforge_dns::server::DnsContext;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn format_iso8601(time: SystemTime) -> String {
    let dt: DateTime<Utc> = time.into();
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn get_v6_kind(state: &IPv6State, prefix: Option<Ipv6Addr>) -> String {
    let ip = state.ip_with_prefix(prefix);
    let bits_kind = ip.map_or("Unknown", |addr| {
        let segments = addr.segments();
        if (segments[0] & 0xfe00) == 0xfc00 {
            "ULA"
        } else if (segments[0] & 0xffc0) == 0xfe80 {
            "LinkLocal"
        } else {
            "GUA"
        }
    });

    match state {
        IPv6State::Static(..) => format!("{bits_kind} (Static)"),
        IPv6State::Dynamic(..) => format!("{bits_kind} (DHCP)"),
        IPv6State::Slaac(..) => format!("{bits_kind} (SLAAC)"),
        IPv6State::LinkLocal(..) => "LinkLocal".to_string(),
        IPv6State::Discovery(..) => format!("{bits_kind} (Discovered)"),
    }
}

// ---------------------------------------------------------------------------
// ClientContext handlers
// ---------------------------------------------------------------------------

impl ClientContext {
    /// Generates a full `StatusResponse` by gathering data from the configuration
    /// and the active device table.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
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
            capabilities: Capabilities {
                encodings: vec![Encoding::Json, Encoding::Bincode],
                compression: {
                    #[cfg(feature = "zstd")]
                    {
                        use crate::api::Compression;
                        vec![Compression::None, Compression::Zstd]
                    }
                    #[cfg(not(feature = "zstd"))]
                    {
                        use crate::api::Compression;
                        vec![Compression::None]
                    }
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
            if let Some(if_ips) = state.interfaces.interface_ips.get(&ifindex) {
                if let Some((ip, prefix)) = if_ips.v4 {
                    status.network.lan_ipv4 = Some(ip.to_string());
                    status.network.lan_ipv4_cidr = Some(format!("{ip}/{prefix}"));
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
                .filter(|s| {
                    matches!(
                        s,
                        IPv6State::Slaac(..) | IPv6State::Discovery(..) | IPv6State::LinkLocal(..)
                    )
                })
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
        status.services.dhcp_v6.pool_free = self.cfg.dhcp_v6_pool_size.map_or(9999, |total| {
            total.saturating_sub(v6_dynamic_count as u64) as usize
        });
        status.services.dhcp_v6.ula.clone_from(&self.cfg.ula_prefix);
        status.services.dhcp_v6.gua.clone_from(&self.current_gua);
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
        if self.cfg.http_enabled {
            status.services.http_api = Some(crate::api::ServiceStatusInfo {
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
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
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
                class: dev.class.as_str().to_string(),
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
                        expires: state.map_or_else(
                            || "—".to_string(),
                            |s| match s {
                                IPv6State::Dynamic(l) => format_iso8601(l.expires),
                                IPv6State::Static(_, _) => "Static".to_string(),
                                IPv6State::Slaac(_, _)
                                | IPv6State::LinkLocal(_, _)
                                | IPv6State::Discovery(_, _) => "—".to_string(),
                            },
                        ),
                        reserved: state.is_some_and(|s| matches!(s, IPv6State::Static(_, _)))
                            || dev.is_static(),
                    }
                }),
                ipv6_addrs: {
                    let mut list = Vec::new();
                    for state in &dev.v6 {
                        if let Some(ip) = state.ip_with_prefix(None) {
                            list.push(Ipv6Entry {
                                addr: ip.to_string(),
                                kind: get_v6_kind(state, None),
                            });
                        } else if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_), _) = state {
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
                    if let IPv6State::Static(suffix, _) = s {
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
            .publish(LanforgeEvent::Network(NetworkEvent::WolTriggered {
                mac,
                ip_hint,
            }));

        Response::Success(SimpleSuccess {
            message: format!("Wake-on-LAN magic packet queued for {mac}"),
        })
    }

    /// Gathers detailed information and history for a device.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) async fn handle_whois(&self, target: String) -> Response {
        let device = MacAddr::parse(&target).map_or_else(
            || {
                target.parse::<IpAddr>().map_or_else(
                    |_| {
                        self.ctx
                            .all_devices()
                            .into_iter()
                            .find(|d| d.hostname.name.to_lowercase() == target.to_lowercase())
                    },
                    |ip| {
                        self.ctx
                            .get_mac_by_ip(ip)
                            .and_then(|m| self.ctx.get_device(&m))
                    },
                )
            },
            |m| self.ctx.get_device(&m),
        );

        if let Some(dev) = device {
            let mac = dev.mac;

            // Fetch history from DB
            let history: Vec<LeaseHistoryEntry> =
                if let Ok(db) = LeaseDb::open(&self.cfg.database).await {
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
                class: dev.class.as_str().to_string(),
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
                                kind: get_v6_kind(s, None),
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
                #[cfg(feature = "adblock")]
                blocked_queries: stats.blocked_queries.load(Ordering::Relaxed),
                #[cfg(not(feature = "adblock"))]
                blocked_queries: 0,
            });
        }

        Response::DnsStats(DnsStatsResponse {
            total_requests: 0,
            cache_hits: 0,
            cache_misses: 0,
            upstream_errors: 0,
            auth_queries: 0,
            recursions: 0,
            blocked_queries: 0,
        })
    }

    /// Toggles the DNS adblocker.
    #[cfg(feature = "adblock")]
    pub(crate) async fn handle_dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockToggle {
                enabled,
                duration_secs,
            }));
        Response::Success(SimpleSuccess {
            message: if enabled {
                "DNS Adblock enabled".to_string()
            } else if let Some(d) = duration_secs {
                format!("DNS Adblock disabled for {} seconds", d)
            } else {
                "DNS Adblock disabled permanently".to_string()
            },
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub(crate) async fn handle_dns_adblock_set(
        &self,
        _enabled: bool,
        _duration_secs: Option<u64>,
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    /// Triggers a reload of DNS blocklists.
    #[cfg(feature = "adblock")]
    pub(crate) async fn handle_dns_adblock_reload(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockReload));
        Response::Success(SimpleSuccess {
            message: "DNS Adblock reload requested".to_string(),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub(crate) async fn handle_dns_adblock_reload(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    /// DNS diagnostic query.
    pub(crate) async fn handle_dns_query(
        &self,
        name: String,
        record_type: Option<String>,
    ) -> Response {
        let Some(dns_ctx_any) = self.ctx.get_dns_context() else {
            return Response::Error {
                error: "DNS engine not ready or disabled".into(),
            };
        };

        let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>() else {
            return Response::Error {
                error: "Invalid DNS context".into(),
            };
        };

        let start = Instant::now();
        let rtype = record_type
            .and_then(|s| RecordType::from_str(&s).ok())
            .unwrap_or(RecordType::A);

        let resolver = LocalResolver::new(&dns_ctx.cfg, &dns_ctx.ctx);
        let results = if rtype == RecordType::PTR {
            Name::from_str(&name).map_or_else(
                |_| Vec::new(),
                |ptr_name| {
                    resolver
                        .resolve_ptr(&ptr_name)
                        .ok()
                        .flatten()
                        .map(|(h, d)| {
                            vec![DnsRecordEntry {
                                name: name.clone(),
                                kind: "PTR".to_string(),
                                data: format!("{h}.{d}"),
                                ttl: dns_ctx.cfg.ttl,
                            }]
                        })
                        .unwrap_or_default()
                },
            )
        } else {
            resolver
                .resolve_ip(&name, rtype)
                .map(|ips| {
                    ips.iter()
                        .map(|ip| DnsRecordEntry {
                            name: name.clone(),
                            kind: rtype.to_string(),
                            data: ip.to_string(),
                            ttl: dns_ctx.cfg.ttl,
                        })
                        .collect()
                })
                .unwrap_or_default()
        };

        Response::DnsQuery(DnsQueryResponse {
            records: results,
            latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            authoritative: true, // Local resolver is always authoritative for local names
        })
    }

    /// Fully dumps the main in-memory state.
    pub(crate) async fn handle_context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> Response {
        let mut state = self.ctx.read().clone();

        if only_devices {
            state.static_entries.clear();
            state.discovery.ndp_cache.clear();
            state.discovery.orphaned_v6.clear();
            state.interfaces.interface_ips.clear();
        } else if only_orphans {
            state.devices.clear();
            state.static_entries.clear();
            state.discovery.ndp_cache.clear();
            state.interfaces.interface_ips.clear();
        }

        Response::ContextDump(Box::new(state))
    }

    /// Completely resets and re-seeds the database.
    pub(crate) async fn handle_db_reset(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbReset));
        Response::Success(SimpleSuccess {
            message: "Database reset requested. Simulating cold start...".to_string(),
        })
    }

    /// Aggregates all active dynamic leases (v4, v6, and prefixes).
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) async fn handle_leases(&self, _count_only: bool) -> Response {
        let devices = self.ctx.all_devices();
        let mut api_leases = Vec::new();
        let now = SystemTime::now();

        for dev in &devices {
            let hostname = dev.display_hostname().to_string();
            let mac = dev.mac.to_string();

            // DHCPv4
            if let IPv4State::Dynamic(lease) = &dev.v4 {
                api_leases.push(LeaseEntry {
                    mac: mac.clone(),
                    hostname: hostname.clone(),
                    address: lease.ip.to_string(),
                    kind: LeaseKind::V4,
                    expires: format_iso8601(lease.expires),
                    remaining_secs: lease
                        .expires
                        .duration_since(now)
                        .map_or(0, |d| d.as_secs().cast_signed()),
                });
            }

            // DHCPv6 IA_NA
            for v6 in &dev.v6 {
                if let IPv6State::Dynamic(lease) = v6 {
                    api_leases.push(LeaseEntry {
                        mac: mac.clone(),
                        hostname: hostname.clone(),
                        address: lease.ip.to_string(),
                        kind: LeaseKind::V6,
                        expires: format_iso8601(lease.expires),
                        remaining_secs: lease
                            .expires
                            .duration_since(now)
                            .map_or(0, |d| d.as_secs().cast_signed()),
                    });
                }
            }

            // DHCPv6 IA_PD (Prefix Delegation)
            for prefix in &dev.v6_prefixes {
                api_leases.push(LeaseEntry {
                    mac: mac.clone(),
                    hostname: hostname.clone(),
                    address: format!("{}/{}", prefix.prefix, prefix.len),
                    kind: LeaseKind::V6Prefix,
                    expires: format_iso8601(prefix.expires),
                    remaining_secs: prefix
                        .expires
                        .duration_since(now)
                        .map_or(0, |d| d.as_secs().cast_signed()),
                });
            }
        }

        Response::Leases(LeasesResponse { leases: api_leases })
    }

    /// Renews a lease (`ForceRenew`).
    pub(crate) async fn handle_lease_renew(
        &self,
        mac_str: String,
        target: Option<LeaseTarget>,
    ) -> Response {
        let mac = match MacAddr::from_str(&mac_str) {
            Ok(m) => m,
            Err(e) => {
                return Response::Error { error: e };
            }
        };

        let target = target.unwrap_or(LeaseTarget::V4);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Device(DeviceEvent::LeaseRenew {
                mac,
                target: target.clone(),
            }));

        Response::Success(SimpleSuccess {
            message: format!("Lease renew requested for {mac} ({target})"),
        })
    }

    /// Releases a lease manually.
    pub(crate) async fn handle_lease_release(
        &self,
        mac_str: String,
        target: Option<LeaseTarget>,
    ) -> Response {
        let mac = match MacAddr::from_str(&mac_str) {
            Ok(m) => m,
            Err(e) => {
                return Response::Error { error: e };
            }
        };

        let target = target.unwrap_or(LeaseTarget::V4);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Device(DeviceEvent::LeaseRelease {
                mac,
                target: target.clone(),
            }));

        Response::Success(SimpleSuccess {
            message: format!("Lease release requested for {mac} ({target})"),
        })
    }

    /// Fetches the current topology of the network.
    pub(crate) async fn handle_topology(&self) -> Response {
        let devices = self.ctx.all_devices();
        let mut entries = Vec::new();

        for dev in &devices {
            if let Some(topo) = &dev.topology {
                entries.push(TopologyEntry {
                    mac: dev.mac.to_string(),
                    hostname: dev.display_hostname().to_string(),
                    parent_mac: topo.parent_mac.map(|m| m.to_string()),
                    port: topo.port.clone(),
                    local_ifindex: topo.local_ifindex,
                    last_updated: format_iso8601(topo.last_updated),
                });
            }
        }

        Response::Topology(TopologyResponse { entries })
    }

    pub(crate) async fn handle_scan(&self) -> Response {
        let last_scan = self.ctx.last_scan_secs_ago();
        let cooldown = 60;

        if last_scan < cooldown {
            return Response::Error {
                error: format!(
                    "Scan on cooldown. Please wait {} more seconds.",
                    cooldown - last_scan
                ),
            };
        }

        self.ctx.record_scan();

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Network(NetworkEvent::ScanRequested));
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Network(NetworkEvent::NeighborScanRequested));

        Response::Success(SimpleSuccess {
            message: "Active network scans triggered (ARP Storm + NDP/SLAAC Discovery)".to_string(),
        })
    }

    /// Adds or updates a static host entry.
    pub(crate) async fn handle_host_add(
        &self,
        mac: Option<String>,
        hostname: Option<String>,
        v4: Option<String>,
        v6_suffix: Option<String>,
    ) -> Response {
        mac.as_deref().and_then(MacAddr::parse).map_or_else(
            || Response::Error {
                error: "Invalid or missing MAC".to_string(),
            },
            |m| {
                let _ = self.ctx.apply(DeviceUpdate::CliHostUpdated {
                    mac: m,
                    update: CliHostUpdate {
                        hostname: hostname.map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                        duid: FieldUpdate::NoChange,
                        v4_static: v4
                            .as_deref()
                            .and_then(|s| s.parse().ok())
                            .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                        v6_suffix: v6_suffix
                            .as_deref()
                            .and_then(Ipv6AddrOrSuffix::parse)
                            .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                        origin: Origin::Cli,
                        boot_file: FieldUpdate::NoChange,
                    },
                });
                Response::Success(SimpleSuccess {
                    message: "Host added/updated".to_string(),
                })
            },
        )
    }

    /// Updates a specific field of a host entry.
    pub(crate) async fn handle_host_set(
        &self,
        mac: String,
        field: String,
        value: String,
    ) -> Response {
        MacAddr::parse(&mac).map_or_else(
            || Response::Error {
                error: "Invalid MAC".to_string(),
            },
            |mac_addr| {
                let mut hn = FieldUpdate::NoChange;
                let mut v4s = FieldUpdate::NoChange;
                let mut v6s = FieldUpdate::NoChange;
                let mut bfs = FieldUpdate::NoChange;

                let err_msg = match field.as_str() {
                    "hostname" => {
                        hn = FieldUpdate::Set(value);
                        None
                    }
                    "v4" | "ipv4" => {
                        if value.is_empty() {
                            v4s = FieldUpdate::Clear;
                            None
                        } else if let Ok(ip) = value.parse() {
                            v4s = FieldUpdate::Set(ip);
                            None
                        } else {
                            Some("Invalid IPv4")
                        }
                    }
                    "v6_suffix" | "v6" => {
                        if value.is_empty() {
                            v6s = FieldUpdate::Clear;
                            None
                        } else if let Some(suf) = Ipv6AddrOrSuffix::parse(&value) {
                            v6s = FieldUpdate::Set(suf);
                            None
                        } else {
                            Some("Invalid IPv6 interface ID (suffix) or address")
                        }
                    }
                    "boot_file" | "boot" => {
                        if value.is_empty() {
                            bfs = FieldUpdate::Clear;
                        } else {
                            bfs = FieldUpdate::Set(value);
                        }
                        None
                    }
                    _ => Some("Unknown field"),
                };

                err_msg.map_or_else(
                    || {
                        let _ = self.ctx.apply(DeviceUpdate::CliHostUpdated {
                            mac: mac_addr,
                            update: CliHostUpdate {
                                hostname: hn,
                                duid: FieldUpdate::NoChange,
                                v4_static: v4s,
                                v6_suffix: v6s,
                                origin: Origin::Cli,
                                boot_file: bfs,
                            },
                        });
                        Response::Success(SimpleSuccess {
                            message: format!("Host {mac} updated"),
                        })
                    },
                    |e| Response::Error {
                        error: e.to_string(),
                    },
                )
            },
        )
    }

    /// Removes a host entry.
    pub(crate) async fn handle_host_remove(&self, mac: String) -> Response {
        MacAddr::parse(&mac).map_or_else(
            || Response::Error {
                error: "Invalid MAC".to_string(),
            },
            |mac_addr| {
                let _ = self.ctx.apply(DeviceUpdate::HostRemoved { mac: mac_addr });
                Response::Success(SimpleSuccess {
                    message: format!("Host {mac} removed"),
                })
            },
        )
    }

    /// Prunes 'zombie' entries from the database.
    pub(crate) async fn handle_db_prune(&self) -> Response {
        let _ = self.ctx.apply(DeviceUpdate::PruneZombies);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbPrune));
        Response::Success(SimpleSuccess {
            message: "Pruning triggered".to_string(),
        })
    }

    /// Forcefully purges a device from memory and database.
    pub(crate) async fn handle_purge(&self, mac: String) -> Response {
        MacAddr::parse(&mac).map_or_else(
            || Response::Error {
                error: "Invalid MAC".to_string(),
            },
            |mac_addr| {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Device(DeviceEvent::Purged { mac: mac_addr }));
                Response::Success(SimpleSuccess {
                    message: format!("Device {mac} purged"),
                })
            },
        )
    }

    /// Dummy handler for watch (streaming is handled in server.rs)
    pub(crate) async fn handle_watch(&self) -> Response {
        Response::Success(SimpleSuccess {
            message: "Starting watch stream...".to_string(),
        })
    }

    /// Dummy handler for log (streaming is handled in server.rs)
    pub(crate) async fn handle_log(&self, _follow: bool, n: Option<usize>) -> Response {
        let n_lines = n.unwrap_or(100);
        let history_len = if let Ok(db) = LogDb::open(&self.cfg.log_db_url).await {
            db.get_history(n_lines).await.map_or(0, |h| h.len())
        } else {
            0
        };

        Response::Success(SimpleSuccess {
            message: format!("Starting event stream ({history_len} historical)..."),
        })
    }

    /// Sets the API password by hashing it and publishing an update event.
    pub(crate) async fn handle_config_set_password(&self, password: String) -> Response {
        let password_hash = hash_password(&password);

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ConfigUpdate {
                password_hash,
            }));

        Response::Success(SimpleSuccess {
            message:
                "API password updated successfully. Changes will be persisted to lanforge.toml."
                    .to_string(),
        })
    }

    /// Request the daemon to reload its configuration from disk.
    pub(crate) async fn handle_reload(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
        Response::Success(SimpleSuccess {
            message: "Reload signal sent successfully".to_string(),
        })
    }

    /// Gracefully shut down the daemon.
    pub(crate) async fn handle_shutdown(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::Shutdown));
        Response::Success(SimpleSuccess {
            message: "Shutting down gracefully".to_string(),
        })
    }

    /// Perform a VACUUM operation on the underlying SQLite database.
    pub(crate) async fn handle_db_vacuum(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbVacuum));
        Response::Success(SimpleSuccess {
            message: "Vacuum triggered".to_string(),
        })
    }

    /// Clear all transient system logs.
    pub(crate) async fn handle_db_log_clean(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbLogClean));
        Response::Success(SimpleSuccess {
            message: "Log cleanup triggered".to_string(),
        })
    }
    pub(crate) async fn handle_dhcp_pools(&self) -> Response {
        let state = self.ctx.read();
        let mut v4_pools = Vec::new();
        let mut v6_pools = Vec::new();

        if let Some(ref pool) = state.interfaces.v4_pool {
            v4_pools.push(DhcpPoolEntry {
                subnet: pool.subnet.clone(),
                total: pool.total_addresses(),
                used: pool.used_addresses(),
                available: pool.available_addresses(),
                utilization_percent: pool.utilization_percent(),
            });
        }

        for (iaid, pool) in &state.interfaces.v6_pools {
            v6_pools.push(DhcpPoolEntry {
                subnet: format!("IAID: {iaid} ({})", pool.subnet),
                total: pool.total_addresses(),
                used: pool.used_addresses(),
                available: pool.available_addresses(),
                utilization_percent: pool.utilization_percent(),
            });
        }

        Response::DhcpPools(DhcpPoolsResponse { v4_pools, v6_pools })
    }

    pub(crate) async fn handle_dns_cache_flush(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
        Response::Success(SimpleSuccess {
            message: "DNS cache flush signal sent".to_string(),
        })
    }

    pub(crate) async fn handle_dns_cache_dump(&self) -> Response {
        let Some(dns_ctx_any) = self.ctx.get_dns_context() else {
            return Response::Error {
                error: "DNS engine not ready or disabled".into(),
            };
        };

        let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>() else {
            return Response::Error {
                error: "Invalid DNS context".into(),
            };
        };

        let mut entries = Vec::new();
        for upstream in &dns_ctx.upstreams {
            let dump = upstream.cache.dump();
            for (name, kind, data, expires_in_secs) in dump {
                entries.push(DnsCacheEntry {
                    name,
                    kind,
                    data,
                    expires_in_secs,
                });
            }
        }

        Response::DnsCache(DnsCacheResponse { entries })
    }
}
