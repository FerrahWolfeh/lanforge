//! Response handlers for the UDS control interface.
#![allow(clippy::unused_async)]

use crate::api::{DeviceEntry, Ipv6Entry, LeaseInfo};
use chrono::{DateTime, SecondsFormat, Utc};
use lanforge_core::types::{Device, IPv6State};
use std::net::Ipv6Addr;
use std::time::SystemTime;

pub mod auth;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod system;

#[must_use]
pub fn format_iso8601(time: SystemTime) -> String {
    let dt: DateTime<Utc> = time.into();
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[must_use]
pub fn get_v6_kind(state: &IPv6State, prefix: Option<Ipv6Addr>) -> String {
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

impl crate::server::ClientContext {
    #[must_use]
    pub fn device_matches_filter(
        dev: &Device,
        filter: Option<&String>,
        method: Option<&String>,
    ) -> bool {
        let matches_filter = filter.is_none_or(|f| {
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

        let matches_method = method.is_none_or(|m| {
            let m_lower = m.to_lowercase();
            dev.learning_method()
                .to_string()
                .to_lowercase()
                .contains(&m_lower)
        });

        matches_filter && matches_method
    }

    #[must_use]
    pub fn map_device(
        dev: &Device,
        gua_prefix: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> DeviceEntry {
        use lanforge_core::types::{Duid, IPv4State};
        let is_online = dev.is_online();
        DeviceEntry {
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
                            _ => "—".to_string(),
                        },
                    ),
                    reserved: state.is_some_and(|s| matches!(s, IPv6State::Static(_, _)))
                        || dev.is_static(),
                }
            }),
            ipv6_addrs: {
                use lanforge_core::types::Ipv6AddrOrSuffix;
                let mut list = Vec::new();
                for state in &dev.v6 {
                    if let Some(ip) = state.ip_with_prefix(None) {
                        list.push(Ipv6Entry {
                            addr: ip.to_string(),
                            kind: get_v6_kind(state, None),
                        });
                    } else if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_), _) = state {
                        if let Some(ip) = ula_prefix.and_then(|p| state.ip_with_prefix(Some(p))) {
                            list.push(Ipv6Entry {
                                addr: ip.to_string(),
                                kind: "ULA (Static)".to_string(),
                            });
                        }
                        if let Some(ip) = gua_prefix.and_then(|p| state.ip_with_prefix(Some(p))) {
                            list.push(Ipv6Entry {
                                addr: ip.to_string(),
                                kind: "GUA (Static)".to_string(),
                            });
                        }
                    }
                }
                list
            },
        }
    }
}
