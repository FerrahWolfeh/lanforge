use crate::{ClientContext, handlers::duration_since_epoch_u64};
use lanforge_api::api::{
    DhcpPoolEntry, DhcpPoolType, DhcpPoolsResponse, LeaseEntry, LeaseKind, LeasesResponse,
    Response, SimpleSuccess,
};
use lanforge_core::bus::{LanforgeEvent, NetworkEvent};
use lanforge_types::{
    device::{IPv4State, IPv6State},
    identifiers::MacAddr,
    update::LeaseTarget,
};
use std::{net::IpAddr, time::SystemTime};

impl ClientContext {
    pub async fn handle_lease_renew(&self, mac: MacAddr, target: Option<LeaseTarget>) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Network(NetworkEvent::LeaseRenewRequested {
                mac,
                target,
            }));

        Response::Success(SimpleSuccess {
            message: format!("Lease renewal requested for {mac}"),
        })
    }

    pub async fn handle_lease_release(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> Response {
        let _ = self.ctx.bus().publish(LanforgeEvent::Network(
            NetworkEvent::LeaseReleaseRequested { mac, target },
        ));

        Response::Success(SimpleSuccess {
            message: format!("Lease release requested for {mac}"),
        })
    }

    pub async fn handle_dhcp_pools(&self) -> Response {
        let (v4_pools, v6_pools) = self.ctx.with_state(|state| {
            let mut v4_pools = Vec::new();
            let mut v6_pools = Vec::with_capacity(state.interfaces.v6_pools.len());

            if let Some(pool) = &state.interfaces.v4_pool {
                v4_pools.push(DhcpPoolEntry {
                    pool_type: DhcpPoolType::V4,
                    range_start: pool.range_start,
                    range_end: pool.range_end,
                    prefix: pool.prefix,
                    prefix_len: pool.prefix_len,
                    total: pool.total,
                    used: pool.used,
                    available: pool.available,
                    utilization_percent: pool.utilization_percent,
                });
            }

            for pool in state.interfaces.v6_pools.values() {
                v6_pools.push(DhcpPoolEntry {
                    pool_type: DhcpPoolType::V6,
                    range_start: pool.range_start,
                    range_end: pool.range_end,
                    prefix: pool.prefix,
                    prefix_len: pool.prefix_len,
                    total: pool.total,
                    used: pool.used,
                    available: pool.available,
                    utilization_percent: pool.utilization_percent,
                });
            }
            (v4_pools, v6_pools)
        });

        Response::DhcpPools(DhcpPoolsResponse { v4_pools, v6_pools })
    }

    pub async fn handle_leases(&self, _count: bool) -> Response {
        let now = SystemTime::now();
        let leases = self.ctx.with_state(|state| {
            let mut list = Vec::new();
            for dev in state.devices.values() {
                if let IPv4State::Dynamic(lease) = &dev.v4 {
                    list.push(LeaseEntry {
                        mac: dev.mac,
                        hostname: dev.display_hostname().to_string(),
                        address: IpAddr::V4(lease.ip),
                        kind: LeaseKind::V4,
                        expires: duration_since_epoch_u64(lease.expires),
                        remaining_secs: lease
                            .expires
                            .duration_since(now)
                            .map_or(0, |d| d.as_secs()),
                    });
                }
                for v6_state in &dev.v6 {
                    if let IPv6State::Dynamic(lease) = v6_state {
                        list.push(LeaseEntry {
                            mac: dev.mac,
                            hostname: dev.display_hostname().to_string(),
                            address: IpAddr::V6(lease.ip),
                            kind: LeaseKind::V6,
                            expires: duration_since_epoch_u64(lease.expires),
                            remaining_secs: lease
                                .expires
                                .duration_since(now)
                                .map_or(0, |d| d.as_secs()),
                        });
                    }
                }
            }
            list
        });

        Response::Leases(LeasesResponse { leases })
    }
}
