#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
//! Service banners: lifecycle from the supervisor, summary from live context data.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::snapshot::{WanSnapshot, WanState};
use lanforge_types::system::{
    DormantReason, PppoeSessionState, PppoeStatusResponse, ServiceId, ServiceState, StateDetail,
};
use lanforge_types::update::DeviceUpdate;

/// The summaries read what the serving instances publish now (the old banners read a
/// registration-time instance: "0 cache entries", WAN "Down (-)" on a live box), and a service
/// that is not serving (TFTP here) shows why instead of a made-up default or stale numbers.
#[tokio::test]
async fn summaries_show_live_data_and_nothing_else() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    for (id, name) in [
        (ServiceId::Dhcp4, "DHCPv4 Server"),
        (ServiceId::Pppoe, "PPPoE Client"),
        (ServiceId::Wan, "WAN"),
        (ServiceId::Tftp, "TFTP Server"),
    ] {
        ctx.register_service(id, name);
        ctx.set_service_state(id, ServiceState::Online);
    }
    ctx.set_service_state(ServiceId::Tftp, ServiceState::Inactive);
    ctx.set_service_detail(
        ServiceId::Tftp,
        Some(StateDetail::Dormant(DormantReason::disabled(
            "tftp.enabled",
        ))),
    );
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac: MacAddr([2, 0, 0, 0, 0, 1]),
        ip: "192.168.1.20".parse().unwrap(),
        expires: SystemTime::now() + Duration::from_hours(1),
    });
    ctx.set_pppoe_status(Some(PppoeStatusResponse {
        state: PppoeSessionState::Connected,
        local_ip: Some("203.0.113.7".parse().unwrap()),
        interface: Some("ppp0".to_string()),
        ..Default::default()
    }));
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifname: Some("ppp0".to_string()),
        ..Default::default()
    });

    let banners = ClientContext::new(ctx).service_banners().await;
    let summary = |id: ServiceId| {
        banners
            .iter()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("{id:?} has a banner"))
            .summary
            .clone()
    };
    assert_eq!(summary(ServiceId::Dhcp4).as_deref(), Some("1 active lease"));
    assert_eq!(
        summary(ServiceId::Pppoe).as_deref(),
        Some("203.0.113.7 on ppp0")
    );
    assert_eq!(summary(ServiceId::Wan).as_deref(), Some("up on ppp0"));
    assert_eq!(
        summary(ServiceId::Tftp).as_deref(),
        Some("dormant: disabled (tftp.enabled)"),
        "not serving: the reason, not stale numbers"
    );
    assert_eq!(banners.len(), 4, "only registered services have a banner");
}

/// The `PPPoE` uptime is the session's: the service stays up (degraded) across reconnects, so its
/// own uptime would keep counting from the first session.
#[tokio::test]
async fn pppoe_uptime_is_the_session_age() {
    use lanforge_api::api::Response;

    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.set_service_state(ServiceId::Pppoe, ServiceState::Online);
    ctx.set_pppoe_status(Some(PppoeStatusResponse {
        state: PppoeSessionState::Connected,
        connected_at: std::time::Instant::now().checked_sub(Duration::from_secs(5)),
        ..Default::default()
    }));

    let Response::PppoeStatus(status) = ClientContext::new(ctx).handle_pppoe_status().await else {
        panic!("pppoe status");
    };
    assert_eq!(status.uptime_secs, Some(5));
}

/// A `PPPoE` session that is not up reads in words ("`WaitingForCarrier`" was the Debug output).
#[tokio::test]
async fn pppoe_summary_names_the_state_in_words() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.register_service(ServiceId::Pppoe, "PPPoE Client");
    ctx.set_service_state(ServiceId::Pppoe, ServiceState::Online);
    ctx.set_pppoe_status(Some(PppoeStatusResponse {
        state: PppoeSessionState::WaitingForCarrier,
        reconnect_attempts: 3,
        ..Default::default()
    }));

    let banners = ClientContext::new(ctx).service_banners().await;
    assert_eq!(
        banners[0].summary.as_deref(),
        Some("waiting for carrier · 3 retries so far")
    );
}

/// A stopped firewall says what it left in the kernel: "stopped by admin" alone does not tell
/// a closed WAN (lockdown) from no lanforge table at all.
#[tokio::test]
async fn stopped_firewall_says_what_it_left() {
    use lanforge_types::network::firewall::FirewallStopAction;

    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.register_service(ServiceId::Nft, "Firewall");
    ctx.set_service_state(ServiceId::Nft, ServiceState::Inactive);
    ctx.set_service_detail(ServiceId::Nft, Some(StateDetail::AdminStopped));
    let client = ClientContext::new(ctx.clone());
    let summary = |banners: Vec<lanforge_types::system::ServiceBanner>| {
        banners
            .into_iter()
            .find(|b| b.id == ServiceId::Nft)
            .and_then(|b| b.summary)
    };

    ctx.set_firewall_left(Some(FirewallStopAction::Lockdown));
    assert_eq!(
        summary(client.service_banners().await).as_deref(),
        Some("stopped by admin · WAN locked down")
    );
    ctx.set_firewall_left(Some(FirewallStopAction::Remove));
    assert_eq!(
        summary(client.service_banners().await).as_deref(),
        Some("stopped by admin · table removed, WAN not filtered by lanforge")
    );
}
