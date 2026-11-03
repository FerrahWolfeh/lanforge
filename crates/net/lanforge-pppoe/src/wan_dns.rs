//! The ISP's IPv6 resolvers, from the Router Advertisements on the `PPPoE` link (RDNSS, RFC 8106).
//!
//! IPCP hands over the IPv4 resolvers at session setup; IPv6 ones arrive later, in RAs, each with
//! a lifetime. While the session is up the RAs are read passively (the kernel or networkd still
//! configure the link from their own copy) and the servers kept until their lifetime runs out.
//! Every change rewrites the session's `dns_servers` (IPCP IPv4 first, then these) and publishes
//! `PppoeEvent::DnsServersChanged`, so DNS re-derives its ISP upstreams.

use lanforge_core::bus::{LanforgeEvent, PppoeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_transport::Icmp6Transport;
use lanforge_types::system::PppoeStatusResponse;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, info, warn};

const ND_ROUTER_ADVERT: u8 = 134;
/// `ICMPv6` header (4) + hop limit, flags, router lifetime (4) + reachable and retrans timers (8).
const RA_OPTIONS_OFFSET: usize = 16;
const OPT_RDNSS: u8 = 25;
/// Resolvers kept at once; an RA naming more is cut here.
const MAX_SERVERS: usize = 4;

/// The ISP's IPv6 resolvers with their expiry (`None` = infinite lifetime).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Rdnss {
    servers: Vec<(Ipv6Addr, Option<Instant>)>,
}

impl Rdnss {
    /// Applies one received `ICMPv6` message; `true` when the server set changed. Anything but a
    /// well-formed RA from a link-local router (RFC 4861 §6.1.2) is ignored.
    pub fn apply_ra(&mut self, msg: &[u8], src: &Ipv6Addr, now: Instant) -> bool {
        if msg.len() < RA_OPTIONS_OFFSET
            || msg[0] != ND_ROUTER_ADVERT
            || msg[1] != 0
            || !src.is_unicast_link_local()
        {
            return false;
        }
        let before: Vec<Ipv6Addr> = self.addrs().collect();
        let mut pos = RA_OPTIONS_OFFSET;
        while pos + 2 <= msg.len() {
            let len = usize::from(msg[pos + 1]) * 8;
            if len == 0 || pos + len > msg.len() {
                break; // RFC 4861 §4.6: a zero length is invalid; stop at a truncated option
            }
            if msg[pos] == OPT_RDNSS && len >= 24 {
                self.apply_rdnss(&msg[pos..pos + len], now);
            }
            pos += len;
        }
        self.addrs().ne(before)
    }

    fn apply_rdnss(&mut self, opt: &[u8], now: Instant) {
        let lifetime = u32::from_be_bytes([opt[4], opt[5], opt[6], opt[7]]);
        let expiry = match lifetime {
            u32::MAX => None,
            secs => Some(now + Duration::from_secs(u64::from(secs))),
        };
        let (addrs, _) = opt[8..].as_chunks::<16>();
        for octets in addrs {
            let addr = Ipv6Addr::from(*octets);
            // A link-local resolver needs a scope DNS cannot carry; multicast/unspecified are junk.
            if addr.is_unicast_link_local() || addr.is_multicast() || addr.is_unspecified() {
                continue;
            }
            let known = self.servers.iter().position(|(a, _)| *a == addr);
            match (known, lifetime) {
                (Some(i), 0) => {
                    self.servers.remove(i);
                }
                (Some(i), _) => self.servers[i].1 = expiry,
                (None, 0) => {}
                (None, _) if self.servers.len() < MAX_SERVERS => self.servers.push((addr, expiry)),
                (None, _) => {}
            }
        }
    }

    /// Drops the servers whose lifetime ended by `now`; `true` when one went.
    pub fn expire(&mut self, now: Instant) -> bool {
        let before = self.servers.len();
        self.servers.retain(|(_, exp)| exp.is_none_or(|e| e > now));
        self.servers.len() != before
    }

    pub fn next_expiry(&self) -> Option<Instant> {
        self.servers.iter().filter_map(|(_, e)| *e).min()
    }

    pub fn addrs(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.servers.iter().map(|(a, _)| *a)
    }
}

/// Follows the RAs on the session's link until the listener fails; the caller drops it with the
/// session. The servers it added are gone with the session status itself.
pub async fn follow_wan_rdnss(ctx: &LanforgeContext, ra: &Icmp6Transport) {
    let mut rdnss = Rdnss::default();
    let mut buf = [0u8; 1500];
    loop {
        let changed = tokio::select! {
            res = ra.recv(&mut buf) => match res {
                Ok((n, src)) => rdnss.apply_ra(&buf[..n], src.ip(), Instant::now()),
                Err(e) => {
                    warn!(error = %e, "WAN RA listener failed; ISP IPv6 resolvers no longer followed");
                    return;
                }
            },
            () = sleep_until(rdnss.next_expiry().unwrap_or_else(Instant::now)),
                if rdnss.next_expiry().is_some() => rdnss.expire(Instant::now()),
        };
        if changed {
            publish(ctx, &rdnss);
        }
    }
}

fn publish(ctx: &LanforgeContext, rdnss: &Rdnss) {
    let Some(current) = ctx.pppoe_status() else {
        debug!("ISP IPv6 resolvers changed with no session status; ignored");
        return;
    };
    let servers: Vec<IpAddr> = current
        .dns_servers
        .iter()
        .copied()
        .filter(IpAddr::is_ipv4)
        .chain(rdnss.addrs().map(IpAddr::V6))
        .collect();
    info!(servers = ?servers, "ISP DNS servers changed (IPv6 from RA RDNSS)");
    ctx.set_pppoe_status(Some(PppoeStatusResponse {
        dns_servers: servers.clone(),
        ..(*current).clone()
    }));
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Pppoe(PppoeEvent::DnsServersChanged {
            servers,
        }));
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const DNS1: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
    const DNS2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x53);

    /// An RA with one RDNSS option listing `servers` for `lifetime` seconds, after an MTU option.
    fn ra(lifetime: u32, servers: &[Ipv6Addr]) -> Vec<u8> {
        let mut m = vec![
            ND_ROUTER_ADVERT,
            0,
            0,
            0,
            64,
            0,
            0x07,
            0x08,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        m.extend_from_slice(&[5, 1, 0, 0, 0, 0, 0x05, 0xd4]); // MTU 1492
        let len = u8::try_from(1 + 2 * servers.len()).unwrap();
        m.extend_from_slice(&[OPT_RDNSS, len, 0, 0]);
        m.extend_from_slice(&lifetime.to_be_bytes());
        for s in servers {
            m.extend_from_slice(&s.octets());
        }
        m
    }

    #[test]
    fn servers_come_with_an_ra_and_leave_with_their_lifetime() {
        let t0 = Instant::now();
        let mut r = Rdnss::default();
        assert!(r.apply_ra(&ra(600, &[DNS1, DNS2]), &ROUTER, t0));
        assert_eq!(r.addrs().collect::<Vec<_>>(), vec![DNS1, DNS2]);
        assert!(
            !r.apply_ra(&ra(600, &[DNS1, DNS2]), &ROUTER, t0),
            "a refresh changes nothing"
        );

        // DNS2 is not renewed: it expires at t0 + 600, DNS1 (renewed) lives on.
        let t1 = t0 + Duration::from_secs(300);
        assert!(!r.apply_ra(&ra(600, &[DNS1]), &ROUTER, t1));
        assert_eq!(r.next_expiry(), Some(t0 + Duration::from_secs(600)));
        assert!(!r.expire(t0 + Duration::from_secs(599)));
        assert!(r.expire(t0 + Duration::from_secs(600)));
        assert_eq!(r.addrs().collect::<Vec<_>>(), vec![DNS1]);

        // Lifetime 0 withdraws a server at once.
        assert!(r.apply_ra(&ra(0, &[DNS1]), &ROUTER, t1));
        assert_eq!(r.addrs().count(), 0);
        assert_eq!(r.next_expiry(), None);
    }

    #[test]
    fn infinite_lifetime_never_expires() {
        let t0 = Instant::now();
        let mut r = Rdnss::default();
        assert!(r.apply_ra(&ra(u32::MAX, &[DNS1]), &ROUTER, t0));
        assert_eq!(r.next_expiry(), None);
        assert!(!r.expire(t0 + Duration::from_hours(10 * 365 * 24)));
    }

    #[test]
    fn junk_is_ignored() {
        let t0 = Instant::now();
        let mut r = Rdnss::default();
        let global_src = DNS2;
        assert!(
            !r.apply_ra(&ra(600, &[DNS1]), &global_src, t0),
            "RA not from link-local"
        );
        let mut rs = ra(600, &[DNS1]);
        rs[0] = 133;
        assert!(!r.apply_ra(&rs, &ROUTER, t0), "not an RA");
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x53);
        assert!(
            !r.apply_ra(&ra(600, &[ll]), &ROUTER, t0),
            "link-local resolver unusable"
        );
        let mut truncated = ra(600, &[DNS1]);
        truncated.truncate(truncated.len() - 4);
        assert!(!r.apply_ra(&truncated, &ROUTER, t0), "truncated option");
        let mut zero_len = ra(600, &[DNS1]);
        zero_len[17] = 0; // the MTU option's length
        assert!(
            !r.apply_ra(&zero_len, &ROUTER, t0),
            "zero-length option ends parsing"
        );
        let many: Vec<Ipv6Addr> = (1..=6)
            .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i))
            .collect();
        assert!(r.apply_ra(&ra(600, &many), &ROUTER, t0));
        assert_eq!(r.addrs().count(), MAX_SERVERS);
    }
}
