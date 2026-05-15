use super::super::format_iso8601;
use crate::ClientContext;
use lanforge_api::api::{
    DhcpPoolEntry, DhcpPoolsResponse, LeaseEntry, LeaseKind, LeasesResponse, Response,
    SimpleSuccess,
};
use lanforge_core::bus::{LanforgeEvent, NetworkEvent};
use lanforge_types::{
    device::{IPv4State, IPv6State},
    identifiers::MacAddr,
    update::LeaseTarget,
};
use std::time::SystemTime;

impl ClientContext {
    pub async fn handle_lease_renew(&self, mac: String, target: Option<LeaseTarget>) -> Response {
        let Some(mac_addr) = MacAddr::parse(&mac) else {
            return Response::Error {
                error: format!("Invalid MAC address: {mac}"),
            };
        };

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Network(NetworkEvent::LeaseRenewRequested {
                mac: mac_addr,
                target,
            }));

        Response::Success(SimpleSuccess {
            message: format!("Lease renewal requested for {mac}"),
        })
    }

    pub async fn handle_lease_release(&self, mac: String, target: Option<LeaseTarget>) -> Response {
        let Some(mac_addr) = MacAddr::parse(&mac) else {
            return Response::Error {
                error: format!("Invalid MAC address: {mac}"),
            };
        };

        let _ = self.ctx.bus().publish(LanforgeEvent::Network(
            NetworkEvent::LeaseReleaseRequested {
                mac: mac_addr,
                target,
            },
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
                subnet: pool.subnet.clone(),
                total: pool.total,
                used: pool.used,
                available: pool.available,
                utilization_percent: pool.utilization_percent,
            });
        }

        for pool in state.interfaces.v6_pools.values() {
            v6_pools.push(DhcpPoolEntry {
                subnet: pool.subnet.clone(),
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
                    mac: dev.mac.to_string(),
                    hostname: dev.display_hostname().to_string(),
                    address: lease.ip.to_string(),
                    kind: LeaseKind::V4,
                    expires: format_iso8601(lease.expires),
                    remaining_secs: lease
                        .expires
                        .duration_since(SystemTime::now())
                        .map_or(0, |d| d.as_secs() as i64),
                });
            }
            for v6_state in &dev.v6 {
                if let IPv6State::Dynamic(lease) = v6_state {
                    leases.push(LeaseEntry {
                        mac: dev.mac.to_string(),
                        hostname: dev.display_hostname().to_string(),
                        address: lease.ip.to_string(),
                        kind: LeaseKind::V6,
                        expires: format_iso8601(lease.expires),
                        remaining_secs: lease
                            .expires
                            .duration_since(SystemTime::now())
                            .map_or(0, |d| d.as_secs() as i64),
                    });
                }
            }
        }

        Response::Leases(LeasesResponse { leases })
    }
}
