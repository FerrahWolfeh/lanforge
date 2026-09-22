use crate::{ClientContext, handlers::duration_since_epoch_u64};
use lanforge_api::api::{
    DeviceEntry, DevicesMeta, DevicesResponse, Ipv6Entry, LeaseInfo, Response, TransientHostEntry,
    TransientHostsResponse,
};
use lanforge_types::device::{Device, IPv4State, IPv6State, classify_ipv6};
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
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Response {
        let gua_prefix = self.current_gua;
        let status = self.ctx.get_status().unwrap_or_default();
        let ula_prefix = status.ula_prefix.as_ref().map(|s| s.to_addr());

        let filter_lower = filter.as_deref().map(str::to_lowercase);
        let method_str = method.as_deref();

        let (paginated, total, online) = self.ctx.with_state(|state| {
            let mut matching = Vec::new();
            let mut online_count = 0;

            for dev in state.devices.values() {
                if !Self::device_matches_filter(dev, filter_lower.as_deref(), method_str) {
                    continue;
                }

                if dev.is_online() {
                    online_count += 1;
                }

                matching.push(dev);
            }

            let total = matching.len();
            let start = offset.unwrap_or(0).min(total);
            let end = (start + limit.unwrap_or(total)).min(total);
            let paginated = matching[start..end]
                .iter()
                .map(|dev| self.map_device(dev, gua_prefix, ula_prefix))
                .collect();

            (paginated, total, online_count)
        });

        Response::Devices(DevicesResponse {
            devices: paginated,
            meta: DevicesMeta { total, online },
        })
    }

    fn device_matches_filter(
        dev: &Device,
        filter: Option<&str>,
        method: Option<&str>,
    ) -> bool {
        if let Some(m) = method
            && !dev.origin.as_str().eq_ignore_ascii_case(m)
        {
            return false;
        }
        if let Some(f) = filter {
            if dev.mac.contains_str(f) {
                return true;
            }
            if !f.is_empty()
                && dev
                    .hostname
                    .name
                    .as_bytes()
                    .windows(f.len())
                    .any(|w| w.eq_ignore_ascii_case(f.as_bytes()))
            {
                return true;
            }
            if let Some(ip) = dev.v4.ip() {
                use std::io::Write;
                let mut buf = [0u8; 16];
                let mut slice = &mut buf[..];
                if write!(slice, "{ip}").is_ok() {
                    let written = 16 - slice.len();
                    if let Ok(ip_str) = std::str::from_utf8(&buf[..written])
                        && ip_str.contains(f)
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        true
    }

    pub fn map_device(
        &self,
        dev: &Device,
        gua_prefix: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> DeviceEntry {
        DeviceEntry {
            mac: dev.mac,
            hostname: dev.display_hostname().to_string(),
            origin: dev.origin,
            online: dev.is_online(),
            status: dev.status,
            last_seen: duration_since_epoch_u64(dev.last_seen),
            learning_method: dev.learning_method(),
            class: dev.class,
            iface: dev.iface.clone(),
            vlan_id: dev.vlan_id(),
            ignore_dns_log: dev.ignore_dns_log,
            ignored_log_domains: dev.ignored_log_domains.clone(),
            duid: dev.duid.clone(),
            display_v4: dev.display_v4(),
            display_v6: dev.display_v6(gua_prefix, ula_prefix),
            v4: match &dev.v4 {
                IPv4State::Static(ip) => Some(Box::new(LeaseInfo {
                    ip: IpAddr::V4(*ip),
                    expires: 0,
                    reserved: true,
                })),
                IPv4State::Dynamic(v) => Some(Box::new(LeaseInfo {
                    ip: IpAddr::V4(v.ip),
                    expires: duration_since_epoch_u64(v.expires),
                    reserved: dev.is_static(),
                })),
                IPv4State::None => None,
            },
            seen_v4: dev.seen_v4.iter().map(|(ip, _)| *ip).collect(),
            v6: dev.primary_v6(gua_prefix, ula_prefix).map(|ip| {
                let expires = dev
                    .v6
                    .iter()
                    .find(|s| match s {
                        IPv6State::Static(s, _) => s.matches(ip),
                        _ => s.ip() == Some(ip),
                    })
                    .map_or(0, |state| match state {
                        IPv6State::Dynamic(lease) => duration_since_epoch_u64(lease.expires),
                        _ => 0,
                    });

                Box::new(LeaseInfo {
                    ip: IpAddr::V6(ip),
                    expires,
                    reserved: dev.is_static(),
                })
            }),
            ipv6_addrs: {
                dev.v6
                    .iter()
                    .filter_map(|s| {
                        s.ip_with_prefix(gua_prefix).map(|ip| Ipv6Entry {
                            addr: ip,
                            kind: classify_ipv6(&ip),
                        })
                    })
                    .collect()
            },
        }
    }

    pub async fn handle_transient_host_list(&self) -> Response {
        let hosts = self.ctx.all_transient_hosts();
        let api_hosts = hosts
            .into_iter()
            .map(|(ip, host)| TransientHostEntry {
                ip,
                hostname: host.hostname.to_string(),
                origin: host.origin,
                resolved_at: duration_since_epoch_u64(host.resolved_at),
                last_seen: duration_since_epoch_u64(host.last_seen),
            })
            .collect();
        Response::TransientHosts(TransientHostsResponse { hosts: api_hosts })
    }
}
