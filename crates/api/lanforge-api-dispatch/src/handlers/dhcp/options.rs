use std::net::IpAddr;

use crate::ClientContext;
use lanforge_api::api::{DhcpOptionsResponse, DhcpPoolsConfigResponse, Response, SimpleSuccess};
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};

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
        Response::Success(SimpleSuccess {
            message: "DHCP pools configuration updated successfully".to_string(),
        })
    }
}
