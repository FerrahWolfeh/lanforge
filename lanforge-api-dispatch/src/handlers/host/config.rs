use crate::ClientContext;
use lanforge_api::api::{HostConfigEntry, HostsResponse, Response, SimpleSuccess};
use lanforge_types::{
    device::{Device, Hostname, HostnameOrigin, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin},
    identifiers::{Duid, MacAddr},
    update::{CliHostUpdate, DeviceUpdate, FieldUpdate},
};
use std::net::Ipv4Addr;
use std::time::SystemTime;

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

        // 1. Prepare device representation
        let mut dev = match self.ctx.get_device(&mac) {
            Some(d) => (*d).clone(),
            None => Device::new(mac),
        };

        dev.hostname = Hostname {
            name: entry.hostname.clone(),
            origin: HostnameOrigin::Static,
        };
        if let Some(v4) = &entry.v4_fixed
            && let Ok(ip) = v4.parse::<Ipv4Addr>()
        {
            dev.v4 = IPv4State::Static(ip);
        }
        if let Some(v6) = &entry.v6_suffix
            && let Some(suf) = Ipv6AddrOrSuffix::parse(v6)
        {
            dev.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
            dev.v6.push(IPv6State::Static(suf, SystemTime::now()));
        }
        dev.origin = Origin::Static;
        dev.managed_at = Some(SystemTime::now());

        // 2. Synchronous database write
        if let Err(e) = self.db.upsert_device(&dev).await {
            return Response::Error {
                error: format!("Database write failed: {e}"),
            };
        }

        // 3. Apply to memory context
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
                error: "Failed to apply device update in memory".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: "Host configuration added/updated".to_string(),
        })
    }

    pub async fn handle_host_set(&self, mac: MacAddr, field: String, value: String) -> Response {
        let dev_arc = match self.ctx.get_device(&mac) {
            Some(d) => d,
            None => {
                return Response::Error {
                    error: format!("Device not found: {mac}"),
                };
            }
        };

        let mut dev = (*dev_arc).clone();

        let mut cli_update = CliHostUpdate {
            hostname: FieldUpdate::NoChange,
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::NoChange,
            boot_file: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            origin: Origin::Static,
        };

        if field == "hostname" {
            dev.hostname = Hostname {
                name: value.clone(),
                origin: HostnameOrigin::Static,
            };
            cli_update.hostname = FieldUpdate::Set(value.clone());
        } else if field == "duid" {
            if let Ok(d) = value.parse::<Duid>() {
                dev.duid = Some(d.clone());
                cli_update.duid = FieldUpdate::Set(d);
            }
        } else if field == "v4_static" {
            if let Ok(ip) = value.parse::<Ipv4Addr>() {
                dev.v4 = IPv4State::Static(ip);
                cli_update.v4_static = FieldUpdate::Set(ip);
            }
        } else if field == "v6_suffix" {
            if let Some(suf) = Ipv6AddrOrSuffix::parse(&value) {
                dev.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
                dev.v6.push(IPv6State::Static(suf, SystemTime::now()));
                cli_update.v6_suffix = FieldUpdate::Set(suf);
            }
        } else if field == "boot_file" {
            if value.is_empty() {
                dev.boot_file = None;
                cli_update.boot_file = FieldUpdate::Clear;
            } else {
                dev.boot_file = Some(value.clone());
                cli_update.boot_file = FieldUpdate::Set(value.clone());
            }
        } else if field == "class" {
            if let Ok(c) = value.parse() {
                dev.class = c;
                cli_update.class = FieldUpdate::Set(c);
            }
        } else if field == "dns_fallback" {
            dev.dns_fallback = value.clone();
            cli_update.dns_fallback = FieldUpdate::Set(value);
        } else {
            return Response::Error {
                error: format!("Unknown field: {field}"),
            };
        }

        dev.origin = Origin::Static;
        dev.managed_at = Some(SystemTime::now());

        // 2. Synchronous database write
        if let Err(e) = self.db.upsert_device(&dev).await {
            return Response::Error {
                error: format!("Database write failed: {e}"),
            };
        }

        // 3. Apply to memory context
        let update = DeviceUpdate::CliHostUpdated {
            mac,
            update: cli_update,
        };

        if !self.ctx.apply(update) {
            return Response::Error {
                error: "Failed to update device in memory".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: "Host field updated".to_string(),
        })
    }

    pub async fn handle_host_remove(&self, mac: MacAddr) -> Response {
        // 1. Synchronous database delete
        if let Err(e) = self.db.remove_device(mac).await {
            return Response::Error {
                error: format!("Database delete failed: {e}"),
            };
        }

        // 2. Apply to memory context
        if !self.ctx.apply(DeviceUpdate::Remove(mac)) {
            return Response::Error {
                error: "Failed to remove device from memory".to_string(),
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
