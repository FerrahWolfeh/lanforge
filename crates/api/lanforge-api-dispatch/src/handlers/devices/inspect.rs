use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess, WhoisResponse};
use lanforge_core::bus::{LanforgeEvent, NetworkEvent};
use lanforge_types::{identifiers::MacAddr, update::DeviceUpdate};
use std::net::IpAddr;

impl ClientContext {
    /// Gathers detailed information and history for a device.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_whois(&self, target: String) -> Response {
        let device = MacAddr::parse(&target).map_or_else(
            || {
                target.parse::<IpAddr>().map_or_else(
                    |_| {
                        self.ctx.with_state(|state| {
                            state
                                .devices
                                .values()
                                .find(|d| d.hostname.name.eq_ignore_ascii_case(&target))
                                .cloned()
                        })
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
            // Build DeviceEntry
            let gua_prefix = self.current_gua;
            let status = self.ctx.get_status().unwrap_or_default();
            let ula_prefix = status.ula_prefix.as_ref().map(|s| s.to_addr());

            let entry = self.map_device(dev.as_ref(), gua_prefix, ula_prefix);

            Response::Whois(Box::new(WhoisResponse { entry }))
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
            let found_mac = self.ctx.with_state(|state| {
                state
                    .devices
                    .values()
                    .find(|d| d.hostname.name.eq_ignore_ascii_case(&target))
                    .map(|d| d.mac)
            });
            match found_mac {
                Some(m) => m,
                None => {
                    return Response::Error {
                        error: format!("Target '{target}' not found (not a MAC or known Hostname)"),
                    };
                }
            }
        };

        let (iface, ip_hint) = self.ctx.get_device(&mac).map_or_else(
            || {
                let iface = self
                    .ctx
                    .get_status()
                    .map(|s| s.lan_iface)
                    .unwrap_or_default();
                (iface, None)
            },
            |d| {
                let iface = d.identity.iface.clone().unwrap_or_else(|| {
                    self.ctx
                        .get_status()
                        .map(|s| s.lan_iface)
                        .unwrap_or_default()
                });
                let ip_hint = d.v4.ip();
                (iface, ip_hint)
            },
        );

        let directed_broadcast = self.ctx.with_config(|cfg| {
            cfg.dhcp_v4_pools.first().and_then(|pool| {
                pool.subnet_mask.map(|mask| {
                    let ip_u32 = u32::from(pool.range_start);
                    let mask_u32 = u32::from(mask);
                    let broadcast = ip_u32 | !mask_u32;
                    std::net::Ipv4Addr::from(broadcast)
                })
            })
        });

        if let Err(e) =
            lanforge_transport::send_wol_magic_packet(mac, &iface, directed_broadcast, ip_hint)
        {
            return Response::Error {
                error: format!("Failed to send Wake-on-LAN packet: {e}"),
            };
        }

        // Emit WoL event for subscribers / audit
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Network(NetworkEvent::WolTriggered {
                mac,
                ip_hint,
            }));

        Response::Success(SimpleSuccess {
            message: format!("Wake-on-LAN magic packet sent to {mac}"),
        })
    }

    pub async fn handle_purge(&self, mac: MacAddr) -> Response {
        // HostRemoved also purges from memory if it's dynamic
        if !self.ctx.apply(DeviceUpdate::HostRemoved { mac }) {
            return Response::Error {
                error: "Failed to purge device".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: format!("Device {mac} purged from memory and database"),
        })
    }
}
