use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use lanforge_types::device::{DeviceStatus, IPv4State, IPv6State};
use lanforge_types::network::dns::{DnsRequest, DnsResponse};
use lanforge_types::network::snapshot::{WanState, mask_ipv6};
use lanforge_types::system::{PppoeSessionState, ServiceBanner, ServiceId};

use crate::ClientContext;

impl ClientContext {
    /// Every service's lifecycle banner with a one-line summary of its live data. The summary
    /// is built here, from what the serving instances publish through the context; a service
    /// with nothing live to report gets `None`, never a placeholder.
    pub async fn service_banners(&self) -> Vec<ServiceBanner> {
        let mut banners = self.ctx.service_banners();
        for banner in &mut banners {
            // A stopped, dormant or failed service shows why (`detail`), not its last numbers.
            if banner.state.is_serving() {
                banner.summary = self.service_summary(banner.id).await;
            }
        }
        banners
    }

    async fn service_summary(&self, id: ServiceId) -> Option<String> {
        match id {
            ServiceId::Dhcp4 => {
                let leases = self.ctx.with_state(|s| {
                    s.devices
                        .values()
                        .filter(|d| matches!(d.v4, IPv4State::Dynamic(_)))
                        .count()
                });
                let word = if leases == 1 { "lease" } else { "leases" };
                Some(match self.ctx.dhcp_v4_pool_stats() {
                    Some(pool) => format!("{leases} active {word} · {} free", pool.available),
                    None => format!("{leases} active {word}"),
                })
            }
            ServiceId::Dhcp6 => {
                let clients = self.ctx.with_state(|s| {
                    s.devices
                        .values()
                        .filter(|d| d.v6.iter().any(|v| matches!(v, IPv6State::Dynamic(_))))
                        .count()
                });
                Some(format!(
                    "{clients} {} with leases",
                    if clients == 1 { "client" } else { "clients" }
                ))
            }
            ServiceId::Dns => {
                let handle = self.ctx.dns_handle()?;
                let Ok(DnsResponse::Stats(stats)) = handle.send_request(DnsRequest::Stats).await
                else {
                    return None;
                };
                let lookups = stats.cache_hits + stats.cache_misses;
                Some(match (stats.cache_hits * 100).checked_div(lookups) {
                    Some(rate) => format!("{} cached · {rate}% hit", stats.cache_entries),
                    None => format!("{} cached", stats.cache_entries),
                })
            }
            ServiceId::Pppoe => {
                let pppoe = self.ctx.pppoe_status()?;
                Some(match (pppoe.state, pppoe.local_ip, &pppoe.interface) {
                    (PppoeSessionState::Connected, Some(ip), Some(iface)) => {
                        format!("{ip} on {iface}")
                    }
                    (state, ..) if pppoe.reconnect_attempts > 0 => {
                        format!("{state:?} · {} retries so far", pppoe.reconnect_attempts)
                    }
                    (state, ..) => format!("{state:?}"),
                })
            }
            ServiceId::Ra => {
                let iface = self.ctx.get_interface_state(self.ctx.target_ifindex()?);
                iface
                    .gua
                    .or(iface.ula)
                    .map(|addr| format!("announcing {}/64", mask_ipv6(addr, 64)))
            }
            ServiceId::Wan => {
                let wan = self.ctx.wan_snapshot();
                Some(match (wan.state, wan.ifname) {
                    (WanState::Up, Some(ifname)) => format!("up on {ifname}"),
                    (WanState::Up, None) => "up".to_string(),
                    (WanState::Down, _) => "down".to_string(),
                })
            }
            ServiceId::Interfaces => {
                let links = self.ctx.interfaces_snapshot().links.len();
                Some(format!(
                    "{links} {}",
                    if links == 1 { "link" } else { "links" }
                ))
            }
            ServiceId::Discovery => {
                let (online, total) = self.ctx.with_state(|s| {
                    let online = s
                        .devices
                        .values()
                        .filter(|d| d.status == DeviceStatus::Online)
                        .count();
                    (online, s.devices.len())
                });
                Some(format!("{online} of {total} devices online"))
            }
            ServiceId::Uds => {
                let clients = self.ctx.active_clients().load(Ordering::Relaxed);
                Some(format!("{clients} connected"))
            }
            ServiceId::Db => {
                let metrics = self.ctx.db_metrics();
                if metrics.last_error.load(Ordering::Relaxed) {
                    return Some("last flush failed".to_string());
                }
                let last = metrics.last_flush_ts.load(Ordering::Relaxed);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                (last > 0).then(|| format!("flushed {}s ago", now.saturating_sub(last)))
            }
            ServiceId::Nft
            | ServiceId::Traffic
            | ServiceId::Tftp
            | ServiceId::Mdns
            | ServiceId::Http => None,
        }
    }
}
