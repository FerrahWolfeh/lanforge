use crate::{
    ClientContext,
    handlers::{format_iso8601, get_v6_kind},
};
use lanforge_api::api::{
    DeviceEntry, DevicesMeta, DevicesResponse, Ipv6Entry, LeaseInfo, Response,
};
use lanforge_types::device::{Device, IPv4State};
use std::net::Ipv6Addr;

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
            meta: DevicesMeta {
                total,
                online,
                last_scan_secs_ago: self.last_scan_secs_ago,
            },
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
            mac: dev.mac.to_string(),
            hostname: dev.display_hostname().to_string(),
            origin: dev.origin.as_str().to_string(),
            online: dev.is_online(),
            last_seen: format_iso8601(dev.last_seen),
            learning_method: dev.learning_method().to_string(),
            class: dev.class.as_str().to_string(),
            duid: dev.duid.as_ref().map(std::string::ToString::to_string),
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
            v6: dev.primary_v6(gua_prefix, ula_prefix).map(|ip| LeaseInfo {
                ip: ip.to_string(),
                expires: "Lease".to_string(),
                reserved: dev.is_static(),
            }),
            ipv6_addrs: {
                dev.v6
                    .iter()
                    .filter_map(|s| {
                        s.ip_with_prefix(gua_prefix).map(|ip| Ipv6Entry {
                            addr: ip.to_string(),
                            kind: get_v6_kind(s, gua_prefix.map(|p| p.to_string()).as_deref()),
                        })
                    })
                    .collect()
            },
        }
    }
}
