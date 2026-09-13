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
                })
                .collect()
        });

        Response::Hosts(HostsResponse { hosts })
    }

    pub async fn handle_host_add(&self, entry: HostConfigEntry) -> Response {
        let mac = entry.mac;

        // 1. Prepare device representation
        let mut dev = match self.ctx.get_device(&mac) {
            Some(d) => (*d).clone(),
            None => Device::new(mac),
        };

        let sanitized_hostname = Hostname::sanitize(&entry.hostname);
        if !sanitized_hostname.is_empty() {
            dev.hostname = Hostname {
                name: sanitized_hostname.clone(),
                origin: HostnameOrigin::Static,
            };
        }
        match entry.v4_fixed {
            Some(ip) => dev.v4 = IPv4State::Static(ip),
            None => {
                if matches!(dev.v4, IPv4State::Static(_)) {
                    dev.v4 = IPv4State::None;
                }
            }
        }
        dev.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
        if let Some(suf) = entry.v6_suffix {
            dev.v6.push(IPv6State::Static(suf, SystemTime::now()));
        }
        dev.origin = Origin::Static;
        dev.managed_at = Some(SystemTime::now());
        dev.ignore_dns_log = entry.ignore_dns_log;
        dev.ignored_log_domains = entry.ignored_log_domains.clone();

        // 2. Synchronous database write
        if let Err(e) = self.db.upsert_device(&dev).await {
            return Response::Error {
                error: format!("Database write failed: {e}"),
            };
        }

        // 3. Apply to memory context
        let hostname_update = if sanitized_hostname.is_empty() {
            FieldUpdate::NoChange
        } else {
            FieldUpdate::Set(sanitized_hostname)
        };
        let update = DeviceUpdate::CliHostUpdated {
            mac,
            update: Box::new(CliHostUpdate {
                hostname: hostname_update,
                duid: FieldUpdate::NoChange,
                v4_static: entry.v4_fixed.into(),
                v6_suffix: entry.v6_suffix.into(),
                boot_file: FieldUpdate::NoChange,
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
                origin: Origin::Static,
            }),
        };

        if !self.ctx.apply(update) {
            return Response::Error {
                error: "Failed to apply device update in memory".to_string(),
            };
        }
        let _ = self.ctx.apply(DeviceUpdate::IgnoreDnsLogSet {
            mac,
            ignore: entry.ignore_dns_log,
        });
        let _ = self.ctx.apply(DeviceUpdate::IgnoredLogDomainsSet {
            mac,
            domains: entry.ignored_log_domains,
        });

        Response::Success(SimpleSuccess {
            message: "Host configuration added/updated".to_string(),
        })
    }

    pub async fn handle_host_set(&self, mac: MacAddr, field: String, value: String) -> Response {
        let mut dev = match self.ctx.get_device(&mac) {
            Some(d) => (*d).clone(),
            None => Device::new(mac),
        };

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
            let sanitized = Hostname::sanitize(&value);
            dev.hostname = Hostname {
                name: sanitized.clone(),
                origin: HostnameOrigin::Static,
            };
            cli_update.hostname = FieldUpdate::Set(sanitized);
        } else if field == "duid" {
            if value.is_empty() {
                dev.duid = None;
                cli_update.duid = FieldUpdate::Clear;
            } else if let Ok(d) = value.parse::<Duid>() {
                dev.duid = Some(d.clone());
                cli_update.duid = FieldUpdate::Set(d);
            }
        } else if field == "v4_static" || field == "v4" || field == "v4_fixed" {
            if value.is_empty() {
                if matches!(dev.v4, IPv4State::Static(_)) {
                    dev.v4 = IPv4State::None;
                }
                cli_update.v4_static = FieldUpdate::Clear;
            } else if let Ok(ip) = value.parse::<Ipv4Addr>() {
                dev.v4 = IPv4State::Static(ip);
                cli_update.v4_static = FieldUpdate::Set(ip);
            }
        } else if field == "v6_suffix" || field == "v6" {
            if value.is_empty() {
                dev.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
                cli_update.v6_suffix = FieldUpdate::Clear;
            } else if let Some(suf) = Ipv6AddrOrSuffix::parse(&value) {
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
        } else if field == "ignore_dns_log" {
            let ign = value.parse::<bool>().unwrap_or(false);
            dev.ignore_dns_log = ign;
            dev.origin = Origin::Static;
            dev.managed_at = Some(SystemTime::now());

            if let Err(e) = self.db.upsert_device(&dev).await {
                return Response::Error {
                    error: format!("Database write failed: {e}"),
                };
            }
            let _ = self.ctx.apply(DeviceUpdate::IgnoreDnsLogSet {
                mac,
                ignore: ign,
            });
            return Response::Success(SimpleSuccess {
                message: "Host configuration updated".to_string(),
            });
        } else if field == "ignored_log_domains" {
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
            dev.ignored_log_domains.clone_from(&domains);
            dev.origin = Origin::Static;
            dev.managed_at = Some(SystemTime::now());

            if let Err(e) = self.db.upsert_device(&dev).await {
                return Response::Error {
                    error: format!("Database write failed: {e}"),
                };
            }
            let _ = self.ctx.apply(DeviceUpdate::IgnoredLogDomainsSet {
                mac,
                domains,
            });
            return Response::Success(SimpleSuccess {
                message: "Host configuration updated".to_string(),
            });
        } else if field == "add_ignored_log_domain" {
            let dom = value.trim().to_ascii_lowercase();
            if !dom.is_empty() && !dev.ignored_log_domains.iter().any(|d| d.eq_ignore_ascii_case(&dom)) {
                dev.ignored_log_domains.push(dom);
            }
            dev.origin = Origin::Static;
            dev.managed_at = Some(SystemTime::now());

            if let Err(e) = self.db.upsert_device(&dev).await {
                return Response::Error {
                    error: format!("Database write failed: {e}"),
                };
            }
            let _ = self.ctx.apply(DeviceUpdate::IgnoredLogDomainsSet {
                mac,
                domains: dev.ignored_log_domains.clone(),
            });
            return Response::Success(SimpleSuccess {
                message: "Host configuration updated".to_string(),
            });
        } else if field == "remove_ignored_log_domain" {
            let dom = value.trim().to_ascii_lowercase();
            dev.ignored_log_domains.retain(|d| !d.eq_ignore_ascii_case(&dom));
            dev.origin = Origin::Static;
            dev.managed_at = Some(SystemTime::now());

            if let Err(e) = self.db.upsert_device(&dev).await {
                return Response::Error {
                    error: format!("Database write failed: {e}"),
                };
            }
            let _ = self.ctx.apply(DeviceUpdate::IgnoredLogDomainsSet {
                mac,
                domains: dev.ignored_log_domains.clone(),
            });
            return Response::Success(SimpleSuccess {
                message: "Host configuration updated".to_string(),
            });
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
            update: Box::new(cli_update),
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
        let _ = self.ctx.apply(DeviceUpdate::Remove(mac));

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
