use crate::ClientContext;
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
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

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
        let state = self.ctx.read();
        let mut v4_pools = Vec::new();
        let mut v6_pools = Vec::new();

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
        drop(state);

        Response::DhcpPools(DhcpPoolsResponse { v4_pools, v6_pools })
    }

    pub async fn handle_leases(&self, _count: bool) -> Response {
        let devices = self.ctx.all_devices();
        let mut leases = Vec::new();

        for dev in &devices {
            if let IPv4State::Dynamic(lease) = &dev.v4 {
                leases.push(LeaseEntry {
                    mac: dev.mac,
                    hostname: dev.display_hostname().to_string(),
                    address: IpAddr::V4(lease.ip),
                    kind: LeaseKind::V4,
                    expires: lease
                        .expires
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                    remaining_secs: lease
                        .expires
                        .duration_since(SystemTime::now())
                        .map_or(0, |d| d.as_secs()),
                });
            }
            for v6_state in &dev.v6 {
                if let IPv6State::Dynamic(lease) = v6_state {
                    leases.push(LeaseEntry {
                        mac: dev.mac,
                        hostname: dev.display_hostname().to_string(),
                        address: IpAddr::V6(lease.ip),
                        kind: LeaseKind::V6,
                        expires: lease
                            .expires
                            .duration_since(UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs()),
                        remaining_secs: lease
                            .expires
                            .duration_since(SystemTime::now())
                            .map_or(0, |d| d.as_secs()),
                    });
                }
            }
            for lease in &dev.v6_prefixes {
                leases.push(LeaseEntry {
                    mac: dev.mac,
                    hostname: dev.display_hostname().to_string(),
                    address: IpAddr::V6(lease.prefix),
                    kind: LeaseKind::V6Prefix,
                    expires: lease
                        .expires
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                    remaining_secs: lease
                        .expires
                        .duration_since(SystemTime::now())
                        .map_or(0, |d| d.as_secs()),
                });
            }
        }

        Response::Leases(LeasesResponse { leases })
    }
}
