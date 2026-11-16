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

#[tokio::test]
async fn renew_and_release_of_an_unknown_mac_are_not_found() {
    let c = client();
    let mac = MacAddr::parse("00:11:22:33:44:99").unwrap();
    let mut rx = c.ctx.bus().subscribe();
    for target in [None, Some(LeaseTarget::V4)] {
        let res = c.handle_lease_renew(mac, target.clone()).await;
        assert!(matches!(res, Response::NotFound { .. }), "renew: {res:?}");
        let res = c.handle_lease_release(mac, target).await;
        assert!(matches!(res, Response::NotFound { .. }), "release: {res:?}");
    }
    assert!(rx.try_recv().is_err(), "nothing to act on: no bus event");
}

#[tokio::test]
async fn renew_and_release_of_a_device_without_a_v4_lease_are_not_found() {
    let c = client();
    let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let duid = Duid::new(vec![0, 3, 0, 1, 0, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let _ = c
        .ctx
        .apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
            mac: Some(mac),
            duid,
            iaid: 7,
            ips: ["2001:db8:1::10".parse::<Ipv6Addr>().unwrap()]
                .into_iter()
                .collect(),
            expires: SystemTime::now() + Duration::from_secs(3600),
        })));
    let res = c.handle_lease_renew(mac, Some(LeaseTarget::V4)).await;
    assert!(matches!(res, Response::NotFound { .. }), "renew: {res:?}");
    let res = c.handle_lease_release(mac, Some(LeaseTarget::V4)).await;
    assert!(matches!(res, Response::NotFound { .. }), "release: {res:?}");
}

#[tokio::test]
async fn renewing_a_v4_lease_publishes_the_request() {
    let c = client();
    let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let _ = c.ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.1.100".parse().unwrap(),
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    let mut rx = c.ctx.bus().subscribe();
    let res = c.handle_lease_renew(mac, None).await;
    assert!(matches!(res, Response::Success(_)), "got {res:?}");
    assert!(rx.recv().await.is_ok());
}

#[tokio::test]
async fn renewing_a_v6_lease_is_rejected() {
    let c = client();
    let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    for target in [
        LeaseTarget::V6 { iaid: 7 },
        LeaseTarget::V6Prefix { iaid: 9 },
    ] {
        let res = c.handle_lease_renew(mac, Some(target)).await;
        assert!(matches!(res, Response::Rejected { .. }), "got {res:?}");
    }
}
