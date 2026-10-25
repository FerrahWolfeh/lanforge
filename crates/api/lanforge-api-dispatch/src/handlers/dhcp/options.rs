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
        self.ctx.update_dhcp_options(options);
        Response::Success(SimpleSuccess {
            message: "DHCP & TFTP options updated successfully".to_string(),
        })
    }

    pub async fn handle_get_dhcp_pools_config(&self) -> Response {
        let v4_pools = self.ctx.get_dhcp_v4_pools();
        let v6_pools = self.ctx.get_dhcp_v6_pools();

        let (active_ula_prefix, active_gua_prefix) = {
            let mut ula = None;
            let mut gua = None;
            for pool in self.ctx.dhcp_v6_pool_stats().values() {
                if let Some(IpAddr::V6(addr)) = pool.prefix {
                    let len = pool.prefix_len.unwrap_or(64);
                    let formatted = format!("{addr}/{len}");
                    if (addr.segments()[0] & 0xfe00) == 0xfc00 {
                        ula = Some(formatted);
                    } else if (addr.segments()[0] & 0xe000) == 0x2000 {
                        gua = Some(formatted);
                    }
                }
            }
            (ula, gua)
        };

        Response::DhcpPoolsConfig(Box::new(DhcpPoolsConfigResponse {
            v4_pools,
            v6_pools,
            active_ula_prefix,
            active_gua_prefix,
        }))
    }

    pub async fn handle_update_dhcp_pools_config(
        &self,
        v4_pools: Vec<Dhcpv4Pool>,
        v6_pools: Vec<Dhcpv6Pool>,
    ) -> Response {
        let patch = lanforge_core::context::ConfigPatch::new()
            .with_dhcp_v4_pools(v4_pools)
            .with_dhcp_v6_pools(v6_pools);
        let _ = self.ctx.apply_config(patch);
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

        let (valid_count, static_count, to_invalidate) = self.ctx.with_state(|state| {
            let mut valid_count = 0;
            let mut static_count = 0;
            let mut to_invalidate = Vec::new();

            for dev in state.devices.values() {
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

                            let hostname = if dev.hostname.name.is_empty() {
                                None
                            } else {
                                Some(dev.hostname.name.clone())
                            };

                            to_invalidate.push((dev.mac, lease.ip, hostname, reason));
                        }
                    }
                    IPv4State::Discovery(..) | IPv4State::None => {}
                }
            }
            (valid_count, static_count, to_invalidate)
        });

        let mut invalidated = Vec::with_capacity(to_invalidate.len());
        for (mac, ip, hostname, reason) in to_invalidate {
            let _ = self.ctx.apply(DeviceUpdate::LeaseReleased {
                mac,
                target: LeaseTarget::V4,
            });

            invalidated.push(InvalidatedLeaseInfo {
                mac,
                ip,
                hostname,
                reason,
            });
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
