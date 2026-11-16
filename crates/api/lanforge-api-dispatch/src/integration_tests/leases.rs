//! DHCP lease listing and release through the API handlers.

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, SystemTime};

use crate::ClientContext;
use lanforge_api::api::{LeaseEntry, LeaseKind, Response};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::update::{DeviceUpdate, LeaseTarget, V6LeaseUpdate, V6PrefixUpdate};

fn client() -> ClientContext {
    ClientContext {
        current_gua: None,
        uptime_secs: 100,
        ctx: LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None),
        active_clients: Arc::new(AtomicUsize::new(1)),
    }
}

async fn listing(c: &ClientContext) -> Vec<LeaseEntry> {
    match c.handle_leases().await {
        Response::Leases(l) => l.leases,
        _ => panic!("expected Response::Leases"),
    }
}

fn target_of(l: &LeaseEntry) -> LeaseTarget {
    let iaid = l.iaid.expect("a DHCPv6 lease carries its iaid");
    match l.kind {
        LeaseKind::V4 => LeaseTarget::V4,
        LeaseKind::V6 => LeaseTarget::V6 { iaid },
        LeaseKind::V6Prefix => LeaseTarget::V6Prefix { iaid },
    }
}

#[tokio::test]
async fn v6_leases_list_their_iaid_and_release_by_it() {
    let c = client();
    let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let duid = Duid::new(vec![0, 3, 0, 1, 0, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let expires = SystemTime::now() + Duration::from_secs(3600);
    let na: Ipv6Addr = "2001:db8:1::10".parse().unwrap();
    let pd: Ipv6Addr = "2001:db8:2::".parse().unwrap();
    let _ = c
        .ctx
        .apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 7,
            ips: [na].into_iter().collect(),
            expires,
        })));
    let _ = c
        .ctx
        .apply(DeviceUpdate::V6PrefixAssigned(Box::new(V6PrefixUpdate {
            mac: Some(mac),
            duid,
            iaid: 9,
            prefix: pd,
            len: 64,
            expires,
        })));

    let leases = listing(&c).await;
    let na_entry = leases.iter().find(|l| l.kind == LeaseKind::V6).unwrap();
    let pd_entry = leases
        .iter()
        .find(|l| l.kind == LeaseKind::V6Prefix)
        .unwrap();
    assert_eq!(na_entry.iaid, Some(7));
    assert_eq!(pd_entry.iaid, Some(9));

    // What the WebUI used to send (iaid 0) matches nothing: it must not report success, and the
    // iaid-7 lease must stay.
    let res = c
        .handle_lease_release(mac, Some(LeaseTarget::V6 { iaid: 0 }))
        .await;
    assert!(matches!(res, Response::NotFound { .. }), "got {res:?}");
    assert_eq!(listing(&c).await.len(), 2);

    for l in [na_entry, pd_entry] {
        let res = c.handle_lease_release(mac, Some(target_of(l))).await;
        assert!(matches!(res, Response::Success(_)), "got {res:?}");
    }
    assert!(listing(&c).await.is_empty());
}
