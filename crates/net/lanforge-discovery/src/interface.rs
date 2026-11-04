//! Interface address discovery and monitoring helpers.

use futures::stream::TryStreamExt;
use lanforge_core::context::LanforgeContext;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::{DeviceUpdate, InterfaceState};
use rtnetlink::Handle;
use rtnetlink::packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use rtnetlink::packet_route::link::LinkAttribute;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::NetworkError;

/// Queries the kernel for all IP addresses (IPv4, Link-Local, GUA, ULA) and MAC address
/// for the specified interface index, applying the resulting state to the context.
///
/// When an interface holds several addresses of one class, the best one is kept (see
/// [`address_rank`]): during a renumbering the OS keeps the withdrawn GUA as deprecated next to
/// the new one, and only the new one may be advertised or leased.
pub async fn refresh_interface(
    handle: &Handle,
    ifindex: u32,
    ctx: &LanforgeContext,
) -> Result<InterfaceState, NetworkError> {
    let mut stream = handle
        .address()
        .get()
        .set_link_index_filter(ifindex)
        .execute();

    let mut picked = Picked::default();
    while let Some(msg) = stream.try_next().await? {
        picked.consider(&msg);
    }
    let mut state = picked.into_state();

    // Fetch MAC address via rtnetlink link query
    let mut link_stream = handle.link().get().match_index(ifindex).execute();
    if let Some(msg) = link_stream.try_next().await? {
        for attr in &msg.attributes {
            if let LinkAttribute::Address(addr_bytes) = attr {
                state.mac = MacAddr::from_slice(addr_bytes);
                break;
            }
        }
    }

    // Update global context table
    let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
        ifindex,
        state: Box::new(state.clone()),
    });

    Ok(state)
}

/// How fit an address is to be the interface's address of its class; lower is better,
/// `None` = unusable (failed DAD).
///
/// In order of weight: not deprecated (a withdrawn prefix), not temporary (privacy address;
/// same bit as `IFA_F_SECONDARY`, which for IPv4 marks a secondary address), DAD finished,
/// configured with no lifetime (a fixed address, the recommended setup) over a dynamic one.
fn address_rank(flags: AddressFlags) -> Option<u8> {
    if flags.contains(AddressFlags::Dadfailed) {
        return None;
    }
    let has = |flag| u8::from(flags.contains(flag));
    Some(
        has(AddressFlags::Deprecated) << 3
            | has(AddressFlags::Secondary) << 2
            | has(AddressFlags::Tentative) << 1
            | u8::from(!flags.contains(AddressFlags::Permanent)),
    )
}

/// The best address seen so far for one class, with its rank.
struct Candidate<T> {
    rank: u8,
    addr: T,
}

/// Keeps `addr` when it ranks strictly better than the current one: on a tie the first in dump
/// order wins (the kernel lists the newest address first).
fn keep<T>(slot: &mut Option<Candidate<T>>, rank: u8, addr: T) -> bool {
    if slot.as_ref().is_some_and(|c| c.rank <= rank) {
        return false;
    }
    *slot = Some(Candidate { rank, addr });
    true
}

/// Per-class pick over one address dump.
#[derive(Default)]
struct Picked {
    v4: Option<Candidate<(Ipv4Addr, u8)>>,
    link_local: Option<Candidate<Ipv6Addr>>,
    gua: Option<Candidate<Ipv6Addr>>,
    ula: Option<Candidate<Ipv6Addr>>,
    /// (preferred, valid) of the picked GUA.
    gua_lifetimes: (u32, u32),
}

impl Picked {
    fn consider(&mut self, msg: &AddressMessage) {
        // The header carries the low 8 flag bits; `IFA_FLAGS`, when present, carries all of them.
        let mut flags = AddressFlags::from_bits_retain(u32::from(msg.header.flags.bits()));
        let mut addr = None;
        let mut lifetimes = (0, 0);
        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Address(ip) => addr = Some(*ip),
                AddressAttribute::Flags(f) => flags |= *f,
                AddressAttribute::CacheInfo(info) => {
                    lifetimes = (info.ifa_preferred, info.ifa_valid);
                }
                _ => {}
            }
        }
        let (Some(addr), Some(rank)) = (addr, address_rank(flags)) else {
            return;
        };
        match addr {
            IpAddr::V4(v4) => {
                keep(&mut self.v4, rank, (v4, msg.header.prefix_len));
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                if o[0] == 0xFE && (o[1] & 0xC0) == 0x80 {
                    keep(&mut self.link_local, rank, v6);
                } else if (0x20..=0x3F).contains(&o[0]) {
                    // Lifetimes belong to the picked GUA only (link-local/ULA/IPv4 lifetimes
                    // must not leak into the advertised GUA lifetimes).
                    if keep(&mut self.gua, rank, v6) {
                        self.gua_lifetimes = lifetimes;
                    }
                } else if o[0] == 0xFD {
                    keep(&mut self.ula, rank, v6);
                }
            }
        }
    }

    fn into_state(self) -> InterfaceState {
        let gua = self.gua.map(|c| c.addr);
        let (gua_preferred, gua_valid) = if gua.is_some() {
            self.gua_lifetimes
        } else {
            (0, 0)
        };
        InterfaceState {
            v4: self.v4.map(|c| c.addr),
            link_local: self.link_local.map(|c| c.addr),
            gua,
            ula: self.ula.map(|c| c.addr),
            gua_preferred,
            gua_valid,
            mac: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_route::address::{AddressHeaderFlags, CacheInfo};

    fn msg(ip: &str, flags: AddressFlags, lifetimes: (u32, u32)) -> AddressMessage {
        let mut m = AddressMessage::default();
        m.header.prefix_len = 64;
        // Like the kernel: low bits in the header, all bits in IFA_FLAGS.
        m.header.flags = AddressHeaderFlags::from_bits_retain(flags.bits().to_le_bytes()[0]);
        m.attributes
            .push(AddressAttribute::Address(ip.parse().unwrap()));
        m.attributes.push(AddressAttribute::Flags(flags));
        let mut info = CacheInfo::default();
        info.ifa_preferred = lifetimes.0;
        info.ifa_valid = lifetimes.1;
        m.attributes.push(AddressAttribute::CacheInfo(info));
        m
    }

    fn pick(msgs: &[AddressMessage]) -> InterfaceState {
        let mut p = Picked::default();
        for m in msgs {
            p.consider(m);
        }
        p.into_state()
    }

    /// A PD renumbering as networkd leaves it: the kernel dumps the new GUA first and the
    /// withdrawn one (deprecated) after it. The new one must be picked, with its own lifetimes.
    #[test]
    fn renumbering_picks_new_gua_over_deprecated_one() {
        let state = pick(&[
            msg("2001:db8:2::1", AddressFlags::empty(), (3600, 7200)),
            msg("2001:db8:1::1", AddressFlags::Deprecated, (0, 5000)),
        ]);
        assert_eq!(state.gua, Some("2001:db8:2::1".parse().unwrap()));
        assert_eq!((state.gua_preferred, state.gua_valid), (3600, 7200));

        // Same with the opposite dump order.
        let state = pick(&[
            msg("2001:db8:1::1", AddressFlags::Deprecated, (0, 5000)),
            msg("2001:db8:2::1", AddressFlags::empty(), (3600, 7200)),
        ]);
        assert_eq!(state.gua, Some("2001:db8:2::1".parse().unwrap()));
        assert_eq!((state.gua_preferred, state.gua_valid), (3600, 7200));
    }

    #[test]
    fn fixed_and_stable_addresses_win() {
        let state = pick(&[
            // Privacy (temporary) address, newest, dumped first.
            msg("2001:db8:1::abcd", AddressFlags::Secondary, (1800, 3600)),
            // Dynamic stable address.
            msg("2001:db8:1::2", AddressFlags::empty(), (3600, 7200)),
            // Fixed ULA after a dynamic one; failed-DAD ULA ignored.
            msg("fd00::bad", AddressFlags::Dadfailed, (0, 0)),
            msg("fd00::2", AddressFlags::empty(), (3600, 7200)),
            msg("fd00::1", AddressFlags::Permanent, (u32::MAX, u32::MAX)),
            // IPv4 primary first, secondary after it (kernel order).
            msg("10.0.0.1", AddressFlags::Permanent, (u32::MAX, u32::MAX)),
            msg(
                "10.0.0.2",
                AddressFlags::Permanent | AddressFlags::Secondary,
                (u32::MAX, u32::MAX),
            ),
        ]);
        assert_eq!(state.gua, Some("2001:db8:1::2".parse().unwrap()));
        assert_eq!((state.gua_preferred, state.gua_valid), (3600, 7200));
        assert_eq!(state.ula, Some("fd00::1".parse().unwrap()));
        assert_eq!(state.v4, Some(("10.0.0.1".parse().unwrap(), 64)));
    }

    #[test]
    fn only_unusable_addresses_leave_the_class_empty() {
        let state = pick(&[msg("2001:db8:1::1", AddressFlags::Dadfailed, (0, 0))]);
        assert_eq!(state.gua, None);
        assert_eq!((state.gua_preferred, state.gua_valid), (0, 0));
    }

    /// The real entry point against a real kernel. Needs a network namespace:
    /// `unshare -rn sh -c 'ip link set lo up && <test binary> --ignored refresh_interface_kernel'`.
    #[tokio::test]
    #[ignore = "needs a network namespace (unshare -rn)"]
    async fn refresh_interface_kernel_renumbering() {
        use lanforge_core::bus::EventBus;
        use lanforge_core::context::state::State;
        use std::process::Command;
        use std::sync::Arc;

        let sh = |cmd: &str| {
            let ok = Command::new("sh")
                .args(["-c", cmd])
                .status()
                .unwrap()
                .success();
            assert!(ok, "{cmd}");
        };
        sh("ip link add d0 type dummy && ip link set d0 up");
        sh("ip -6 addr add 2001:db8:1::1/64 dev d0 nodad valid_lft 7200 preferred_lft 3600");
        sh("ip -6 addr add fd00::1/64 dev d0 nodad");
        sh("ip -6 addr add 2001:db8:2::1/64 dev d0 nodad valid_lft 7200 preferred_lft 3600");
        // The old prefix is withdrawn: deprecated, still valid.
        sh("ip -6 addr change 2001:db8:1::1/64 dev d0 valid_lft 5000 preferred_lft 0");
        sh("ip addr add 10.0.0.1/24 dev d0 && ip addr add 10.0.0.2/24 dev d0");

        let (conn, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(conn);
        let link = handle.link().get().match_name(String::from("d0")).execute();
        let ifindex = Box::pin(link)
            .try_next()
            .await
            .unwrap()
            .unwrap()
            .header
            .index;
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);

        let state = refresh_interface(&handle, ifindex, &ctx).await.unwrap();
        assert_eq!(state.gua, Some("2001:db8:2::1".parse().unwrap()));
        assert!(
            state.gua_preferred > 3000,
            "lifetimes of the new GUA: {state:?}"
        );
        assert_eq!(state.ula, Some("fd00::1".parse().unwrap()));
        assert_eq!(state.v4, Some(("10.0.0.1".parse().unwrap(), 24)));
        assert_eq!(ctx.get_interface_state(ifindex).gua, state.gua);
    }
}
