use super::{format_iso8601, get_v6_kind};
use crate::api::{
    DeviceEntry, DevicesMeta, DevicesResponse, HostConfigEntry, HostsResponse, Ipv6Entry,
    LeaseInfo, Response, SimpleSuccess, TopologyEntry, TopologyResponse, WhoisResponse,
};
use crate::server::ClientContext;
use lanforge_core::types::{
    CliHostUpdate, DeviceUpdate, Duid, FieldUpdate, IPv4State, IPv6State, LanforgeEvent, MacAddr,
    NetworkEvent, Origin,
};
use lanforge_db::engine::LeaseHistoryEntry;
use std::net::{IpAddr, Ipv6Addr};

impl ClientContext {
    /// Generates a `DevicesResponse`, optionally filtering by a search string.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_devices(
        &self,
        filter: Option<String>,
        _vendor: Option<String>,
        method: Option<String>,
        _format: Option<String>,
    ) -> Response {
        let devices = self.ctx.all_devices();
        let mut api_devices = Vec::new();
        let mut online = 0;

        let gua_prefix = self
            .current_gua
            .as_ref()
            .and_then(|s| s.parse::<Ipv6Addr>().ok());
        let ula_prefix = self
            .cfg
            .ula_prefix
            .as_ref()
            .and_then(|s| s.parse::<Ipv6Addr>().ok());

        for dev in &devices {
            if !Self::device_matches_filter(dev, filter.as_ref(), method.as_ref()) {
                continue;
            }

            let is_online = dev.is_online();
            if is_online {
                online += 1;
            }

            api_devices.push(Self::map_device(dev, gua_prefix, ula_prefix));
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
    pub async fn handle_hosts(&self) -> Response {
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

    /// Gathers detailed information and history for a device.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_whois(&self, target: String) -> Response {
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
                self.db.get_lease_history(mac).await.unwrap_or_default();

            // Build DeviceEntry
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

    /// Triggers a Wake-on-LAN magic packet.
    pub async fn handle_wol(&self, target: String) -> Response {
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

    pub async fn handle_host_add(
        &self,
        mac: Option<String>,
        hostname: Option<String>,
        v4: Option<String>,
        v6_suffix: Option<String>,
    ) -> Response {
        let update = DeviceUpdate::CliHostUpdated {
            mac: mac.and_then(|m| MacAddr::parse(&m)).unwrap_or_default(),
            update: CliHostUpdate {
                hostname: hostname.into(),
                duid: FieldUpdate::NoChange,
                v4_static: v4.and_then(|v| v.parse().ok()).into(),
                v6_suffix: v6_suffix.and_then(|v| v.parse().ok()).into(),
                boot_file: FieldUpdate::NoChange,
                origin: Origin::Static,
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            },
        };

        if !self.ctx.apply(update) {
            return Response::Error {
                error: "Failed to apply device update".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: "Host configuration added/updated".to_string(),
        })
    }

    pub async fn handle_host_set(&self, mac: String, field: String, value: String) -> Response {
        let Some(mac_addr) = MacAddr::parse(&mac) else {
            return Response::Error {
                error: format!("Invalid MAC address: {mac}"),
            };
        };

        let update = DeviceUpdate::CliHostUpdated {
            mac: mac_addr,
            update: CliHostUpdate {
                hostname: if field == "hostname" {
                    FieldUpdate::Set(value.clone())
                } else {
                    FieldUpdate::NoChange
                },
                duid: if field == "duid" {
                    value
                        .parse()
                        .map_or(FieldUpdate::NoChange, FieldUpdate::Set)
                } else {
                    FieldUpdate::NoChange
                },
                v4_static: if field == "v4_static" {
                    value
                        .parse()
                        .map_or(FieldUpdate::NoChange, FieldUpdate::Set)
                } else {
                    FieldUpdate::NoChange
                },
                v6_suffix: if field == "v6_suffix" {
                    value
                        .parse()
                        .map_or(FieldUpdate::NoChange, FieldUpdate::Set)
                } else {
                    FieldUpdate::NoChange
                },
                boot_file: if field == "boot_file" {
                    FieldUpdate::Set(value.clone())
                } else {
                    FieldUpdate::NoChange
                },
                class: if field == "class" {
                    value
                        .parse()
                        .map_or(FieldUpdate::NoChange, FieldUpdate::Set)
                } else {
                    FieldUpdate::NoChange
                },
                dns_fallback: if field == "dns_fallback" {
                    FieldUpdate::Set(value)
                } else {
                    FieldUpdate::NoChange
                },
                origin: Origin::Static,
            },
        };

        if !self.ctx.apply(update) {
            return Response::Error {
                error: "Failed to update device".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: "Host field updated".to_string(),
        })
    }

    pub async fn handle_host_remove(&self, mac: String) -> Response {
        let Some(mac_addr) = MacAddr::parse(&mac) else {
            return Response::Error {
                error: format!("Invalid MAC address: {mac}"),
            };
        };

        if !self.ctx.apply(DeviceUpdate::Remove(mac_addr)) {
            return Response::Error {
                error: "Failed to remove device".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: "Host configuration removed".to_string(),
        })
    }

    pub async fn handle_purge(&self, mac: String) -> Response {
        let Some(mac_addr) = MacAddr::parse(&mac) else {
            return Response::Error {
                error: format!("Invalid MAC address: {mac}"),
            };
        };

        // HostRemoved also purges from memory if it's dynamic
        if !self.ctx.apply(DeviceUpdate::Purge(mac_addr)) {
            return Response::Error {
                error: "Failed to purge device".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: format!("Device {mac} purged from memory and database"),
        })
    }

    pub async fn handle_topology(&self) -> Response {
        let mut entries = Vec::new();

        for dev in self.ctx.all_devices() {
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
}
