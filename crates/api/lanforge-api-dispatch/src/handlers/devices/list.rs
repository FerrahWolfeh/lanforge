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
        let devices = self.ctx.all_devices();
        let mut api_devices = Vec::new();
        let mut online = 0;

        let gua_prefix = self.current_gua;
        let status = self.ctx.get_status().unwrap_or_default();
        let ula_prefix = status.ula_prefix.as_ref().map(|s| s.to_addr());

        for dev in &devices {
            if !Self::device_matches_filter(dev, filter.as_ref(), method.as_ref()) {
                continue;
            }

            let is_online = dev.is_online();
            if is_online {
                online += 1;
            }

            api_devices.push(self.map_device(dev, gua_prefix, ula_prefix));
        }

        let total = api_devices.len();
        let start = offset.unwrap_or(0).min(total);
        let end = (start + limit.unwrap_or(total)).min(total);
        let paginated = api_devices[start..end].to_vec();

        Response::Devices(DevicesResponse {
            devices: paginated,
            meta: DevicesMeta { total, online },
        })
    }

    fn device_matches_filter(
        dev: &Device,
        filter: Option<&String>,
        method: Option<&String>,
    ) -> bool {
        if let Some(m) = method
            && dev.origin.as_str().to_lowercase() != m.to_lowercase()
        {
            return false;
        }
        if let Some(f) = filter {
            let f = f.to_lowercase();
            if dev.mac.to_string().to_lowercase().contains(&f)
                || dev.hostname.name.to_lowercase().contains(&f)
                || dev
                    .v4
                    .ip()
                    .map(|ip| ip.to_string())
                    .is_some_and(|s| s.contains(&f))
            {
                return true;
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
            duid: dev.duid.clone(),
            display_v4: dev.display_v4(),
            display_v6: dev.display_v6(gua_prefix, ula_prefix),
            v4: match &dev.v4 {
                IPv4State::Static(ip) => Some(LeaseInfo {
                    ip: IpAddr::V4(*ip),
                    expires: 0,
                    reserved: true,
                }),
                IPv4State::Dynamic(v) => Some(LeaseInfo {
                    ip: IpAddr::V4(v.ip),
                    expires: duration_since_epoch_u64(v.expires),
                    reserved: dev.is_static(),
                }),
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

                LeaseInfo {
                    ip: IpAddr::V6(ip),
                    expires,
                    reserved: dev.is_static(),
                }
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
