use std::net::{IpAddr, Ipv4Addr};

use crate::ClientContext;
use lanforge_api::api::{
    DhcpOptionsResponse, DhcpPoolsConfigResponse, DhcpReconcileResponse, InvalidatedLeaseInfo,
    Response, SimpleSuccess,
};
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_types::device::IPv4State;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::update::{DeviceUpdate, LeaseTarget};

impl ClientContext {
    pub async fn handle_get_dhcp_options(&self) -> Response {
        let options = self.ctx.get_dhcp_options();
        Response::DhcpOptions(Box::new(DhcpOptionsResponse { options }))
    }

    pub async fn handle_update_dhcp_options(&self, options: DhcpOptionsConfig) -> Response {
        if let Err(e) = self.db.save_dhcp_options(&options).await {
            return Response::Error {
                error: format!("Failed to save DHCP options to database: {e}"),
            };
        }
        self.ctx.update_dhcp_options(options);
        if self.db.is_in_memory() {
            let _ = self.flush_static_config_to_toml().await;
        }
        Response::Success(SimpleSuccess {
            message: "DHCP & TFTP options updated successfully".to_string(),
        })
    }

    pub async fn handle_get_dhcp_pools_config(&self) -> Response {
        let v4_pools = self.ctx.get_dhcp_v4_pools();
        let v6_pools = self.ctx.get_dhcp_v6_pools();

        let state = self.ctx.read();
        let mut active_ula_prefix = None;
        let mut active_gua_prefix = None;

        for pool in state.interfaces.v6_pools.values() {
            if let Some(IpAddr::V6(addr)) = pool.prefix {
                let len = pool.prefix_len.unwrap_or(64);
                let formatted = format!("{addr}/{len}");
                if (addr.segments()[0] & 0xfe00) == 0xfc00 {
                    active_ula_prefix = Some(formatted);
                } else if (addr.segments()[0] & 0xe000) == 0x2000 {
                    active_gua_prefix = Some(formatted);
                }
            }
        }
        drop(state);

        Response::DhcpPoolsConfig(DhcpPoolsConfigResponse {
            v4_pools,
            v6_pools,
            active_ula_prefix,
            active_gua_prefix,
        })
    }

    pub async fn handle_update_dhcp_pools_config(
        &self,
        v4_pools: Vec<Dhcpv4Pool>,
        v6_pools: Vec<Dhcpv6Pool>,
    ) -> Response {
        if let Err(e) = self.db.save_dhcp_v4_pools(&v4_pools).await {
            return Response::Error {
                error: format!("Failed to save DHCPv4 pools to database: {e}"),
            };
        }
        if let Err(e) = self.db.save_dhcp_v6_pools(&v6_pools).await {
            return Response::Error {
                error: format!("Failed to save DHCPv6 pools to database: {e}"),
            };
        }
        self.ctx.update_dhcp_v4_pools(v4_pools);
        self.ctx.update_dhcp_v6_pools(v6_pools);
        if self.db.is_in_memory() {
            let _ = self.flush_static_config_to_toml().await;
        }
        Response::Success(SimpleSuccess {
            message: "DHCP pools configuration updated successfully".to_string(),
        })
    }

    pub async fn handle_dhcp_reconcile(&self) -> Response {
        let pools = self.ctx.get_dhcp_v4_pools();
        let options = self.ctx.get_dhcp_options();
        let server_mask = options
            .v4
            .subnet_mask
            .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
        let server_router = options.v4.router;

        let mut invalidated = Vec::new();
        let mut valid_count = 0;
        let mut static_count = 0;

        let devices = self.ctx.with_state(|state| {
            state.devices.values().cloned().collect::<Vec<_>>()
        });

        for dev in devices {
            match &dev.v4 {
                IPv4State::Static(_) => {
                    // Static reservations are NEVER invalidated or touched
                    static_count += 1;
                }
                IPv4State::Dynamic(lease) => {
                    let in_pool = pools
                        .iter()
                        .find(|p| lease.ip >= p.range_start && lease.ip <= p.range_end);
                    let is_valid = if let Some(p) = in_pool {
                        let mask = p.subnet_mask.unwrap_or(server_mask);
                        let router = p.router.or(server_router);
                        if let Some(r) = router {
                            (u32::from(lease.ip) & u32::from(mask))
                                == (u32::from(r) & u32::from(mask))
                        } else {
                            true
                        }
                    } else {
                        false
                    };

                    if is_valid {
                        valid_count += 1;
                    } else {
                        let reason = if in_pool.is_none() {
                            format!("IP {} is outside configured dynamic pools", lease.ip)
                        } else {
                            format!(
                                "IP {} does not match subnet mask {server_mask} or gateway {server_router:?}",
                                lease.ip
                            )
                        };

                        // Invalidate stale lease in State and DB
                        let _ = self.ctx.apply(DeviceUpdate::LeaseReleased {
                            mac: dev.mac,
                            target: LeaseTarget::V4,
                        });

                        invalidated.push(InvalidatedLeaseInfo {
                            mac: dev.mac,
                            ip: lease.ip,
                            hostname: if dev.hostname.name.is_empty() {
                                None
                            } else {
                                Some(dev.hostname.name.clone())
                            },
                            reason,
                        });
                    }
                }
                IPv4State::None => {}
            }
        }

        // Notify DHCP service to reload and ensure transports/pools are fully synced
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed));

        Response::DhcpReconcile(DhcpReconcileResponse {
            invalidated_v4_leases: invalidated,
            valid_v4_leases: valid_count,
            preserved_static_leases: static_count,
        })
    }
}
