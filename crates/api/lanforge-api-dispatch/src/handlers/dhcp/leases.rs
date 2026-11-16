use crate::ClientContext;
use lanforge_api::api::{
    DhcpPoolEntry, DhcpPoolType, DhcpPoolsResponse, LeaseEntry, LeaseKind, LeasesResponse,
    Response, SimpleSuccess,
};
use lanforge_core::bus::{LanforgeEvent, NetworkEvent};
use lanforge_types::{
    device::{IPv4State, IPv6State, state::system_time_to_epoch_u32},
    identifiers::MacAddr,
    update::{DeviceUpdate, LeaseTarget},
};
use std::{net::IpAddr, time::SystemTime};

impl ClientContext {
    /// Whether the device has a dynamic lease the target names (`None`: any lease);
    /// `Err` when no device has that MAC.
    fn has_lease(&self, mac: MacAddr, target: Option<&LeaseTarget>) -> Result<bool, Response> {
        let Some(dev) = self.ctx.get_device(&mac) else {
            return Err(Response::NotFound {
                error: format!("no device with MAC {mac}"),
            });
        };
        let v4 = dev.v4.is_dynamic();
        let v6 = dev.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_)));
        let pd = !dev.v6_prefixes.is_empty();
        Ok(match target {
            Some(LeaseTarget::V4) => v4,
            Some(LeaseTarget::V6 { .. }) => v6,
            Some(LeaseTarget::V6Prefix { .. }) => pd,
            None => v4 || v6 || pd,
        })
    }

    pub async fn handle_lease_renew(&self, mac: MacAddr, target: Option<LeaseTarget>) -> Response {
        // Only DHCPv4 can be asked to renew (FORCERENEW); DHCPv6 Reconfigure is not implemented.
        if let Some(v6 @ (LeaseTarget::V6 { .. } | LeaseTarget::V6Prefix { .. })) = &target {
            return Response::Rejected {
                error: format!("renewing a {v6} lease is not supported: DHCPv6 has no renew path"),
            };
        }
        match self.has_lease(mac, target.as_ref()) {
            Err(not_found) => return not_found,
            Ok(false) => {
                return Response::NotFound {
                    error: format!("no DHCPv4 lease for {mac}"),
                };
            }
            Ok(true) => {}
        }
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
        // Only the DHCPv4 service reacts to the bus request; DHCPv6 leases are dropped here.
        if let Some(v6 @ (LeaseTarget::V6 { .. } | LeaseTarget::V6Prefix { .. })) = &target {
            if !self.ctx.apply(DeviceUpdate::LeaseReleased {
                mac,
                target: v6.clone(),
            }) {
                return Response::NotFound {
                    error: format!("no {v6} lease for {mac}"),
                };
            }
        } else {
            match self.has_lease(mac, target.as_ref()) {
                Err(not_found) => return not_found,
                Ok(false) => {
                    return Response::NotFound {
                        error: format!("no lease for {mac}"),
                    };
                }
                Ok(true) => {}
            }
        }
        let _ = self.ctx.bus().publish(LanforgeEvent::Network(
            NetworkEvent::LeaseReleaseRequested { mac, target },
        ));

        Response::Success(SimpleSuccess {
            message: format!("Lease release requested for {mac}"),
        })
    }

    pub async fn handle_dhcp_pools(&self) -> Response {
        let mut v4_pools = Vec::new();
        if let Some(pool) = self.ctx.dhcp_v4_pool_stats() {
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

        let v6_stats = self.ctx.dhcp_v6_pool_stats();
        let mut v6_pools = Vec::with_capacity(v6_stats.len());
        for pool in v6_stats.values() {
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

        Response::DhcpPools(DhcpPoolsResponse { v4_pools, v6_pools })
    }

    pub async fn handle_leases(&self) -> Response {
        let now = SystemTime::now();
        let now_epoch = system_time_to_epoch_u32(now);
        let leases = self.ctx.with_state(|state| {
            let mut list = Vec::new();
            for dev in state.devices.values() {
                if let IPv4State::Dynamic(lease) = &dev.v4 {
                    list.push(LeaseEntry {
                        mac: dev.mac,
                        hostname: dev.display_hostname().to_string(),
                        address: IpAddr::V4(lease.ip),
                        kind: LeaseKind::V4,
                        expires: u64::from(lease.expires),
                        remaining_secs: u64::from(lease.expires.saturating_sub(now_epoch)),
                        iaid: None,
                    });
                }
                for v6_state in &dev.v6 {
                    if let IPv6State::Dynamic(lease) = v6_state {
                        list.push(LeaseEntry {
                            mac: dev.mac,
                            hostname: dev.display_hostname().to_string(),
                            address: IpAddr::V6(lease.ip),
                            kind: LeaseKind::V6,
                            expires: u64::from(lease.expires),
                            remaining_secs: u64::from(lease.expires.saturating_sub(now_epoch)),
                            iaid: Some(lease.iaid),
                        });
                    }
                }
                for lease in &dev.v6_prefixes {
                    list.push(LeaseEntry {
                        mac: dev.mac,
                        hostname: dev.display_hostname().to_string(),
                        address: IpAddr::V6(lease.prefix),
                        kind: LeaseKind::V6Prefix,
                        expires: u64::from(lease.expires),
                        remaining_secs: u64::from(lease.expires.saturating_sub(now_epoch)),
                        iaid: Some(lease.iaid),
                    });
                }
            }
            list
        });

        Response::Leases(LeasesResponse { leases })
    }
}
