//! Response handlers para o controle UDS.
//!
//! Implementa os métodos de `ClientContext` que constroem as respostas
//! para os comandos `Status`, `Devices` e `HostList`.

use std::net::Ipv6Addr;

use lanforge_core::device::{IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin};

use crate::api;
use crate::api::Response;
use crate::server::ClientContext;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn format_iso8601(time: std::time::SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = time.into();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
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
    pub(crate) async fn handle_status(&self) -> Response {
        let table_guard = self.table.read();

        let mut status = api::StatusResponse {
            uptime_secs: self.uptime_secs,
            version: env!("CARGO_PKG_VERSION").to_string(),
            services: api::ServicesStatus::default(),
            db: api::DbStatus::default(),
            network: api::NetworkStatus::default(),
            devices: api::DevicesStats::default(),
        };

        // Network
        status.network.lan_iface.clone_from(&self.cfg.lan_iface);
        status.network.gua.clone_from(&self.current_gua);
        status.network.ula.clone_from(&self.cfg.ula_prefix);

        // Services -> RA
        status.services.ra.state = if self.cfg.ra_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.ra.uptime_secs = self.uptime_secs;
        status.services.ra.gua.clone_from(&self.current_gua);
        status.services.ra.ula.clone_from(&status.network.ula);

        // Services -> DHCPv4
        status.services.dhcp_v4.state = if self.cfg.dhcp_v4_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.dhcp_v4.uptime_secs = self.uptime_secs;

        // Services -> DHCPv6
        status.services.dhcp_v6.state = if self.cfg.dhcp_v6_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
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

        // Services -> SLAAC
        status.services.slaac.state = "online".to_string();
        status.services.slaac.uptime_secs = self.uptime_secs;
        status.services.slaac.last_scan_secs_ago = self.last_scan_secs_ago;

        // Database
        status.db.path.clone_from(&self.cfg.db_path);
        status.db.size_bytes = std::fs::metadata(&self.cfg.db_path)
            .map(|m| m.len())
            .unwrap_or(0);
        status.db.last_flush_secs_ago = 0;

        // Devices + Leases
        let dev_ct = table_guard.devices().count();
        let mut online_ct = 0;
        let mut static_toml = 0;
        let mut dynamic = 0;

        let mut v4_active = 0;
        let mut v6_active = 0;
        let mut slaac_addrs = 0;

        for dev in table_guard.devices() {
            let is_online = dev.last_seen.elapsed().unwrap_or_default().as_secs() < 300;
            if is_online {
                online_ct += 1;
            }

            if dev.is_static() {
                static_toml += 1;
            } else {
                dynamic += 1;
            }

            if dev.v4.ip().is_some() {
                v4_active += 1;
            }
            if dev
                .v6
                .iter()
                .any(|s| matches!(s, IPv6State::Dynamic(_) | IPv6State::Static(_)))
            {
                v6_active += 1;
            }
            slaac_addrs += dev
                .v6
                .iter()
                .filter(|s| matches!(s, IPv6State::Slaac(_)))
                .count();
        }

        status.devices.total = dev_ct;
        status.devices.online = online_ct;
        status.devices.static_toml = static_toml;
        status.devices.managed_cli = table_guard
            .devices()
            .filter(|d| d.origin == Origin::Cli)
            .count();

        drop(table_guard);

        status.devices.dynamic = dynamic;

        status.services.dhcp_v4.leases_active = v4_active;
        status.services.dhcp_v6.leases_active = v6_active;
        status.services.slaac.addrs_tracked = slaac_addrs;

        status.services.dhcp_v4.pool_free = 143;
        status.services.dhcp_v6.pool_free = 247;

        Response::Status(Box::new(status))
    }

    pub(crate) async fn handle_devices(&self, filter: Option<String>) -> Response {
        let table_guard = self.table.read();

        let mut api_devices = Vec::new();
        let mut online = 0;

        for dev in table_guard.devices() {
            let matches_filter = filter.as_ref().is_none_or(|f| {
                let f_lower = f.to_lowercase();
                dev.hostname.to_lowercase().contains(&f_lower)
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

            if !matches_filter {
                continue;
            }

            let is_online = dev.is_online();
            if is_online {
                online += 1;
            }

            api_devices.push(api::DeviceEntry {
                mac: dev.mac.to_string(),
                hostname: dev.display_hostname().to_string(),
                origin: dev.origin.as_str().to_string(),
                online: is_online,
                last_seen: format_iso8601(dev.last_seen),
                duid: dev.duid.as_ref().map(|d| hex::encode(d.as_bytes())),
                display_v4: dev.display_v4(),
                display_v6: dev.display_v6(),
                v4: match &dev.v4 {
                    IPv4State::Static(ip) => Some(api::LeaseInfo {
                        ip: ip.to_string(),
                        expires: "Static".to_string(),
                        reserved: true,
                    }),
                    IPv4State::Dynamic(v) => Some(api::LeaseInfo {
                        ip: v.ip.to_string(),
                        expires: format_iso8601(v.expires),
                        reserved: dev.is_static(),
                    }),
                    IPv4State::None => None,
                },
                seen_v4: dev.seen_v4.iter().map(|ip| ip.to_string()).collect(),
                v6: dev.v6.iter().find_map(|s| match s {
                    IPv6State::Dynamic(v) => Some(api::LeaseInfo {
                        ip: v.ip.to_string(),
                        expires: format_iso8601(v.expires),
                        reserved: dev.is_static(),
                    }),
                    IPv6State::Static(Ipv6AddrOrSuffix::Full(ip)) => Some(api::LeaseInfo {
                        ip: ip.to_string(),
                        expires: "Static".to_string(),
                        reserved: true,
                    }),
                    _ => None,
                }),
                ipv6_addrs: {
                    let mut list = Vec::new();
                    for state in &dev.v6 {
                        if let IPv6State::Slaac(ip) = state {
                            list.push(api::Ipv6Entry {
                                addr: ip.to_string(),
                                kind: get_v6_kind(ip).to_string(),
                            });
                        }
                    }
                    list
                },
            });
        }

        Response::Devices(api::DevicesResponse {
            devices: api_devices,
            meta: api::DevicesMeta {
                total: table_guard.devices().count(),
                online,
                last_scan_secs_ago: self.last_scan_secs_ago,
            },
        })
    }

    pub(crate) async fn handle_hosts(&self) -> Response {
        let table_guard = self.table.read();
        let mut hosts = Vec::new();

        for dev in table_guard.devices() {
            if dev.origin == Origin::Dynamic {
                continue;
            }

            hosts.push(api::HostConfigEntry {
                mac: dev.mac.to_string(),
                hostname: dev.hostname.clone(),
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

        Response::Hosts(api::HostsResponse { hosts })
    }
}
