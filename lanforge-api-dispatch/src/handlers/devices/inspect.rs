use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess, WhoisResponse};
use lanforge_core::bus::{LanforgeEvent, NetworkEvent};
use lanforge_db::engine::LeaseHistoryEntry;
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
            let gua_prefix = self.current_gua;
            let status = self.ctx.get_status().unwrap_or_default();
            let ula_prefix = status.ula_prefix.as_ref().map(|s| s.to_addr());

            let entry = self.map_device(dev.as_ref(), gua_prefix, ula_prefix);

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

    pub async fn handle_purge(&self, mac: MacAddr) -> Response {
        // HostRemoved also purges from memory if it's dynamic
        if !self.ctx.apply(DeviceUpdate::Purge(mac)) {
            return Response::Error {
                error: "Failed to purge device".to_string(),
            };
        }

        Response::Success(SimpleSuccess {
            message: format!("Device {mac} purged from memory and database"),
        })
    }
}
