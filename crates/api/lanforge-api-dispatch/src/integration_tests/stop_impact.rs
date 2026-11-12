//! D-20 stop impact: the dry-run lists the serving services that `Require` the target.

use std::sync::Arc;

use crate::ClientContext;
use lanforge_api::api::{Response, StopOutcome};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{Edge, LossPolicy};
use lanforge_types::system::{ServiceId, ServiceState};

static DEGRADES: &[Edge] = &[Edge::requires(ServiceId::Interfaces, LossPolicy::Degrade)];
static CONTINUES: &[Edge] = &[
    Edge::requires(ServiceId::Interfaces, LossPolicy::Continue),
    Edge::wants(ServiceId::Wan),
];
static PAUSES: &[Edge] = &[Edge::requires(ServiceId::Interfaces, LossPolicy::Pause)];
static WANTS_ONLY: &[Edge] = &[
    Edge::wants(ServiceId::Interfaces),
    Edge::after(ServiceId::Db),
];

fn ctx() -> LanforgeContext {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    for (id, name, deps, state) in [
        (
            ServiceId::Interfaces,
            "Interfaces",
            &[][..],
            ServiceState::Online,
        ),
        (
            ServiceId::Dhcp4,
            "DHCPv4 Server",
            DEGRADES,
            ServiceState::Online,
        ),
        (
            ServiceId::Ra,
            "Router Advertisements",
            CONTINUES,
            ServiceState::Degraded,
        ),
        (ServiceId::Traffic, "Traffic", PAUSES, ServiceState::Online),
        // Dormant: nothing to affect.
        (
            ServiceId::Tftp,
            "TFTP Server",
            DEGRADES,
            ServiceState::Inactive,
        ),
        // Only Wants/After: losing it changes nothing in DNS.
        (ServiceId::Dns, "DNS", WANTS_ONLY, ServiceState::Online),
    ] {
        ctx.register_service(id, name, deps, None);
        ctx.set_service_state(id, state);
    }
    ctx
}

#[tokio::test]
async fn stop_impact_lists_serving_dependents_that_require_the_service() {
    let client = ClientContext::new(ctx());
    let Response::ServiceStopImpact(impact) =
        client.handle_service_stop_impact("interfaces".into()).await
    else {
        panic!("expected a stop impact");
    };
    assert_eq!(impact.id, ServiceId::Interfaces);
    let got: Vec<(ServiceId, StopOutcome)> =
        impact.affected.iter().map(|e| (e.id, e.outcome)).collect();
    let mut want = vec![
        (ServiceId::Dhcp4, StopOutcome::Degraded),
        (ServiceId::Ra, StopOutcome::KeepsRunning),
        (ServiceId::Traffic, StopOutcome::Paused),
    ];
    want.sort_by_key(|(id, _)| id.as_str());
    assert_eq!(got, want);
    assert!(impact.affected.iter().any(|e| e.name == "DHCPv4 Server"));
}

#[tokio::test]
async fn stop_impact_of_a_leaf_is_empty_and_bad_ids_are_rejected() {
    let client = ClientContext::new(ctx());
    let Response::ServiceStopImpact(impact) = client.handle_service_stop_impact("dns".into()).await
    else {
        panic!("expected a stop impact");
    };
    assert!(impact.affected.is_empty());

    assert!(matches!(
        client
            .handle_service_stop_impact("no-such-service".into())
            .await,
        Response::Rejected { .. }
    ));
}

/// Stopping `PPPoE` takes the internet down although nothing `Requires` it: the warning its
/// service declares comes with the dry-run while it serves, and not when it is not running.
#[tokio::test]
async fn stop_impact_carries_the_service_warning_while_it_serves() {
    const WARNING: &str = "the internet goes down";
    let ctx = ctx();
    ctx.register_service(ServiceId::Pppoe, "PPPoE Client", &[], Some(WARNING));
    ctx.set_service_state(ServiceId::Pppoe, ServiceState::Online);
    let client = ClientContext::new(ctx.clone());
    let Response::ServiceStopImpact(impact) =
        client.handle_service_stop_impact("pppoe".into()).await
    else {
        panic!("expected a stop impact");
    };
    assert!(impact.affected.is_empty());
    assert_eq!(impact.warning.as_deref(), Some(WARNING));

    ctx.set_service_state(ServiceId::Pppoe, ServiceState::Inactive);
    let Response::ServiceStopImpact(impact) =
        client.handle_service_stop_impact("pppoe".into()).await
    else {
        panic!("expected a stop impact");
    };
    assert_eq!(impact.warning, None);
}
