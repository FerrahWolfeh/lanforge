use crate::ClientContext;
use lanforge_api::api::{HostConfigEntry, HostsResponse, Response, SimpleSuccess};
use lanforge_types::{
    device::{IPv4State, IPv6State, Origin},
    identifiers::MacAddr,
    update::{CliHostUpdate, DeviceUpdate, FieldUpdate},
};

impl ClientContext {
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

    pub async fn handle_host_add(&self, entry: HostConfigEntry) -> Response {
        let mac = match MacAddr::parse(&entry.mac) {
            Some(m) => m,
            None => {
                return Response::Error {
                    error: format!("Invalid MAC: {}", entry.mac),
                };
            }
        };

        let update = DeviceUpdate::CliHostUpdated {
            mac,
            update: CliHostUpdate {
                hostname: entry.hostname.into(),
                duid: FieldUpdate::NoChange,
                v4_static: entry.v4_fixed.and_then(|v| v.parse().ok()).into(),
                v6_suffix: entry.v6_suffix.and_then(|v| v.parse().ok()).into(),
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

    pub async fn handle_host_import(&self, hosts: Vec<HostConfigEntry>) -> Response {
        let mut count = 0;
        for entry in hosts {
            let res = self.handle_host_add(entry).await;
            if let Response::Success(_) = res {
                count += 1;
            }
        }

        Response::Success(SimpleSuccess {
            message: format!("Successfully imported {count} host configurations"),
        })
    }
}
