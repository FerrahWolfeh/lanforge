use crate::ClientContext;
use lanforge_api::api::{HostConfigEntry, HostsResponse, Response, SimpleSuccess};
use lanforge_types::{
    device::{Device, Hostname, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin, StaticHost},
    identifiers::{Duid, MacAddr},
    update::{CliHostUpdate, DeviceUpdate, FieldUpdate},
};
use std::net::Ipv4Addr;

/// The reservation `entry` asks for, keeping the device's name and boot file when it gives
/// none (clients that do not know the boot file, like the WebUI, must not clear it).
fn static_host(entry: &HostConfigEntry, device: Option<&Device>) -> StaticHost {
    let hostname = Hostname::sanitize(&entry.hostname);
    StaticHost {
        mac: entry.mac,
        hostname: if hostname.is_empty() {
            device.map(|d| d.hostname.name.clone()).unwrap_or_default()
        } else {
            hostname
        },
        v4: entry.v4_fixed,
        v6: entry.v6_suffix,
        boot_file: entry
            .boot_file
            .clone()
            .or_else(|| device.and_then(|d| d.boot_file.clone())),
    }
}

/// Puts `host` in `hosts`, replacing the one with its MAC.
fn upsert(hosts: &mut Vec<StaticHost>, host: StaticHost) {
    match hosts.iter_mut().find(|h| h.mac == host.mac) {
        Some(existing) => *existing = host,
        None => hosts.push(host),
    }
}

fn not_saved(e: &str) -> Response {
    tracing::error!("Host configuration not saved: {e}");
    Response::Error {
        error: format!("Host configuration not saved: {e}"),
    }
}

impl ClientContext {
    /// Generates a `HostsResponse` containing all manually configured host entries.
    pub async fn handle_hosts(&self) -> Response {
        let hosts = self.ctx.with_state(|state| {
            state
                .devices
                .values()
                .filter(|dev| dev.origin != Origin::Dynamic)
                .map(|dev| HostConfigEntry {
                    mac: dev.mac,
                    hostname: dev.hostname.name.clone(),
                    v4_fixed: match &dev.v4 {
                        IPv4State::Static(ip) => Some(*ip),
                        _ => None,
                    },
                    v6_suffix: dev.v6.iter().find_map(|s| match s {
                        IPv6State::Static(suf, _) => Some(*suf),
                        _ => None,
                    }),
                    origin: dev.origin,
                    ignore_dns_log: dev.ignore_dns_log,
                    ignored_log_domains: dev.ignored_log_domains.clone(),
                    boot_file: dev.boot_file.clone(),
                })
                .collect()
        });

        Response::Hosts(HostsResponse { hosts })
    }

    /// Reserves `entry` in `[hosts]` (written before it applies); its DNS log settings, WebUI
    /// settings, go to the device only.
    pub async fn handle_host_add(&self, entry: HostConfigEntry) -> Response {
        let mac = entry.mac;
        let host = static_host(&entry, self.ctx.get_device(&mac).as_deref());
        let persisted = match self.change_hosts(|hosts| upsert(hosts, host)) {
            Ok(p) => p,
            Err(e) => return not_saved(&e),
        };
        let _ = self.ctx.apply(DeviceUpdate::IgnoreDnsLogSet {
            mac,
            ignore: entry.ignore_dns_log,
        });
        let _ = self.ctx.apply(DeviceUpdate::IgnoredLogDomainsSet {
            mac,
            domains: entry.ignored_log_domains,
        });

        Response::Success(SimpleSuccess {
            message: persisted.message("Host configuration"),
        })
    }

    pub async fn handle_host_set(&self, mac: MacAddr, field: String, value: String) -> Response {
        let device = self.ctx.get_device(&mac);
        // The reservation this device has, or the one it gets: setting a host field makes it a
        // static host (written to `[hosts]`).
        let mut host = device
            .as_deref()
            .and_then(Device::static_host)
            .unwrap_or_else(|| StaticHost {
                mac,
                hostname: device
                    .as_ref()
                    .map(|d| d.hostname.name.clone())
                    .unwrap_or_default(),
                v4: None,
                v6: None,
                boot_file: device.as_ref().and_then(|d| d.boot_file.clone()),
            });
        let mut device_only = CliHostUpdate {
            hostname: FieldUpdate::NoChange,
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::NoChange,
            boot_file: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            origin: Origin::Static,
        };
        let invalid = |what: &str| Response::Error {
            error: format!("'{value}' is not {what}"),
        };

        match field.as_str() {
            "hostname" => host.hostname = Hostname::sanitize(&value),
            "v4_static" | "v4" | "v4_fixed" => {
                host.v4 = if value.is_empty() {
                    None
                } else if let Ok(ip) = value.parse::<Ipv4Addr>() {
                    Some(ip)
                } else {
                    return invalid("an IPv4 address");
                };
            }
            "v6_suffix" | "v6" => {
                host.v6 = if value.is_empty() {
                    None
                } else if let Some(v6) = Ipv6AddrOrSuffix::parse(&value) {
                    Some(v6)
                } else {
                    return invalid("an IPv6 suffix or address");
                };
            }
            "boot_file" => {
                let file = value.replace('\0', "").trim().to_string();
                host.boot_file = (!file.is_empty()).then_some(file);
            }
            "duid" => {
                device_only.duid = if value.is_empty() {
                    FieldUpdate::Clear
                } else if let Ok(d) = value.parse::<Duid>() {
                    FieldUpdate::Set(d)
                } else {
                    return invalid("a DUID");
                };
            }
            "class" => match value.parse() {
                Ok(c) => device_only.class = FieldUpdate::Set(c),
                Err(_) => return invalid("a device class"),
            },
            "dns_fallback" => device_only.dns_fallback = FieldUpdate::Set(value.clone()),
            "ignore_dns_log" => {
                let ign = value.parse::<bool>().unwrap_or(false);
                let _ = self
                    .ctx
                    .apply(DeviceUpdate::IgnoreDnsLogSet { mac, ignore: ign });
                return Response::Success(SimpleSuccess {
                    message: "Host configuration updated".to_string(),
                });
            }
            "ignored_log_domains" => {
                let domains: Vec<String> = if value.trim().starts_with('[') {
                    serde_json::from_str(&value).unwrap_or_default()
                } else {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToString::to_string)
                        .collect()
                };
                let _ = self
                    .ctx
                    .apply(DeviceUpdate::IgnoredLogDomainsSet { mac, domains });
                return Response::Success(SimpleSuccess {
                    message: "Host configuration updated".to_string(),
                });
            }
            "add_ignored_log_domain" | "remove_ignored_log_domain" => {
                let dom = value.trim().to_ascii_lowercase();
                let mut domains = device
                    .as_ref()
                    .map_or_else(Vec::new, |d| d.ignored_log_domains.clone());
                if field == "add_ignored_log_domain" {
                    if !dom.is_empty() && !domains.iter().any(|d| d.eq_ignore_ascii_case(&dom)) {
                        domains.push(dom);
                    }
                } else {
                    domains.retain(|d| !d.eq_ignore_ascii_case(&dom));
                }
                let _ = self
                    .ctx
                    .apply(DeviceUpdate::IgnoredLogDomainsSet { mac, domains });
                return Response::Success(SimpleSuccess {
                    message: "Host configuration updated".to_string(),
                });
            }
            _ => {
                return Response::Error {
                    error: format!("Unknown field: {field}"),
                };
            }
        }

        let persisted = match self.change_hosts(|hosts| upsert(hosts, host)) {
            Ok(p) => p,
            Err(e) => return not_saved(&e),
        };
        let has_device_only = device_only.duid != FieldUpdate::NoChange
            || device_only.class != FieldUpdate::NoChange
            || device_only.dns_fallback != FieldUpdate::NoChange;
        if has_device_only
            && !self.ctx.apply(DeviceUpdate::CliHostUpdated {
                mac,
                update: Box::new(device_only),
            })
        {
            return Response::Error {
                error: "Failed to update device in memory".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: persisted.message("Host field"),
        })
    }

    /// Removes the host from `[hosts]`: the device stays, as a discovered device again.
    pub async fn handle_host_remove(&self, mac: MacAddr) -> Response {
        match self.change_hosts(|hosts| hosts.retain(|h| h.mac != mac)) {
            Ok(persisted) => Response::Success(SimpleSuccess {
                message: persisted.message("Host configuration"),
            }),
            Err(e) => not_saved(&e),
        }
    }

    pub async fn handle_host_import(&self, hosts: Vec<HostConfigEntry>) -> Response {
        match self.import_hosts(hosts, false) {
            Ok(count) => Response::Success(SimpleSuccess {
                message: format!("Successfully imported {count} host configurations"),
            }),
            Err(e) => not_saved(&e),
        }
    }

    /// Reserves `hosts` in `[hosts]` (all of them in one write, before they apply; `replace`
    /// drops the static hosts they do not list, which become discovered devices again), then
    /// sets their DNS log settings on the devices.
    pub(crate) fn import_hosts(
        &self,
        hosts: Vec<HostConfigEntry>,
        replace: bool,
    ) -> Result<usize, String> {
        let count = hosts.len();
        let devices: Vec<_> = hosts.iter().map(|h| self.ctx.get_device(&h.mac)).collect();
        let wanted: Vec<StaticHost> = hosts
            .iter()
            .zip(&devices)
            .map(|(h, d)| static_host(h, d.as_deref()))
            .collect();
        self.change_hosts(|live| {
            if replace {
                live.clear();
            }
            for host in wanted {
                upsert(live, host);
            }
        })?;
        for h in hosts {
            let _ = self.ctx.apply(DeviceUpdate::IgnoreDnsLogSet {
                mac: h.mac,
                ignore: h.ignore_dns_log,
            });
            let _ = self.ctx.apply(DeviceUpdate::IgnoredLogDomainsSet {
                mac: h.mac,
                domains: h.ignored_log_domains,
            });
        }
        Ok(count)
    }
}
