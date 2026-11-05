#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions and setup"
)]
#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
//! `apply_static_hosts`: the device table follows `[hosts]`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::device::{
    HostnameOrigin, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin, StaticHost,
};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate, V6LeaseUpdate};

fn ctx() -> LanforgeContext {
    LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None)
}

fn host(mac: &str, name: &str, v4: &str) -> StaticHost {
    StaticHost {
        mac: MacAddr::parse(mac).unwrap(),
        hostname: name.into(),
        v4: Some(v4.parse().unwrap()),
        v6: Ipv6AddrOrSuffix::parse("::501"),
        boot_file: Some("pxelinux.0".into()),
    }
}

#[test]
fn listed_hosts_are_reserved_exactly() {
    let ctx = ctx();
    let hosts = vec![
        host("04:d9:f5:0a:25:94", "solarium", "192.168.0.128"),
        host("bc:fc:e7:8a:a9:73", "archie", "192.168.0.2"),
    ];
    assert!(ctx.apply_static_hosts(&hosts).is_empty());
    let mut live = ctx.static_hosts();
    live.sort_by_key(|h| h.hostname.clone());
    let mut want = hosts.clone();
    want.sort_by_key(|h| h.hostname.clone());
    assert_eq!(live, want);

    // A changed field is applied; an unchanged host is left alone.
    let mut changed = hosts.clone();
    changed[0].v4 = Some("192.168.0.129".parse().unwrap());
    changed[0].boot_file = None;
    let _ = ctx.apply_static_hosts(&changed);
    let dev = ctx.get_device(&changed[0].mac).unwrap();
    assert_eq!(dev.v4, IPv4State::Static("192.168.0.129".parse().unwrap()));
    assert_eq!(dev.boot_file, None);
}

/// A host left out of `[hosts]` is a discovered device again: no reservation, a name DHCP
/// may replace, its dynamic lease and history kept.
#[test]
fn a_host_left_out_becomes_a_discovered_device_again() {
    let ctx = ctx();
    let solarium = host("04:d9:f5:0a:25:94", "solarium", "192.168.0.128");
    let _ = ctx.apply_static_hosts(std::slice::from_ref(&solarium));
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: Some(solarium.mac),
        duid: lanforge_types::identifiers::Duid::new(vec![1, 2, 3]),
        iaid: 7,
        ips: std::iter::once("fd97:f00d:cafe:3731::77".parse().unwrap()).collect(),
        expires: SystemTime::now() + Duration::from_hours(1),
    })));

    let _ = ctx.apply_static_hosts(&[]);

    let dev = ctx.get_device(&solarium.mac).expect("the device stays");
    assert_eq!(dev.origin, Origin::Dynamic);
    assert!(!matches!(dev.v4, IPv4State::Static(_)));
    assert!(!dev.v6.iter().any(|s| matches!(s, IPv6State::Static(..))));
    assert!(
        dev.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_))),
        "lease kept"
    );
    assert_eq!(dev.boot_file, None);
    assert_eq!(dev.hostname.name, "solarium");
    assert_ne!(dev.hostname.origin, HostnameOrigin::Static);
    assert!(ctx.static_hosts().is_empty());
}

#[test]
fn the_router_itself_is_not_made_a_static_host() {
    let ctx = ctx();
    let router = host("84:47:09:85:d2:12", "pixie", "192.168.3.1");
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: router.mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::Set("pixie".into()),
            duid: FieldUpdate::NoChange,
            v4_static: router.v4.into(),
            v6_suffix: FieldUpdate::NoChange,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
            origin: Origin::System,
        }),
    });
    let issues = ctx.apply_static_hosts(std::slice::from_ref(&router));
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(ctx.get_device(&router.mac).unwrap().origin, Origin::System);
}
