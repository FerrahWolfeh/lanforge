//! Sockets the kernel keeps refusing degrade a service under the real supervisor
//! (`Degraded(TransportErrors)`), and only then; a socket on a missing interface retries when
//! the interface appears (backlog §1.3). The clock is paused: each
//! `advance` is one 10 s health window.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::registry::ServiceRegistry;
use crate::supervisor::GraphSupervisor;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, Condition, LanforgeService, RestartPolicy, RuntimeClass, ServiceCommand,
    ServiceHandle, ServiceSpec,
};
use lanforge_types::network::bind::{BindError, BindErrorKind};
use lanforge_types::network::snapshot::{InterfaceSnapshot, LinkInfo, TransportMetrics};
use lanforge_types::system::{DegradedReason, ServiceId, ServiceState, StateDetail};
use smallvec::SmallVec;
use tokio::task::yield_now;
use tokio::time::advance;

const WINDOW: Duration = Duration::from_secs(10);

/// A service that registers one socket's counters and reports `report` once it serves.
struct Sockets {
    metrics: Arc<TransportMetrics>,
    report: Option<DegradedReason>,
}

impl LanforgeService for Sockets {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: ServiceId::Dns,
            display_name: "dns",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_millis(5),
                max_backoff: Duration::from_millis(20),
                max_retries: 3,
                healthy_uptime: Duration::from_millis(50),
            },
            shutdown_timeout: Duration::from_millis(100),
            deps: &[],
            condition: Condition::ALWAYS,
        }
    }
}

impl AsyncService for Sockets {
    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        ctx.set_service_transports(ServiceId::Dns, vec![Arc::clone(&self.metrics)]);
        match self.report.clone() {
            Some(why) => h.degraded(why),
            None => h.ready(),
        }
        loop {
            if matches!(
                h.next_command().await,
                ServiceCommand::Stop | ServiceCommand::Shutdown
            ) {
                return Ok(());
            }
        }
    }
}

/// Starts the counting: the supervisor's first sample comes before the service registered its
/// sockets, so the first full window starts at the next one.
async fn baseline() {
    settle().await;
    advance(WINDOW).await;
    settle().await;
}

/// Lets the runner and the service run everything that is ready, without moving the clock.
async fn settle() {
    for _ in 0..100 {
        yield_now().await;
    }
}

fn status(ctx: &LanforgeContext) -> (ServiceState, Option<StateDetail>) {
    (
        ctx.get_service_state(ServiceId::Dns),
        ctx.get_service_detail(ServiceId::Dns),
    )
}

fn start(
    ctx: &LanforgeContext,
    metrics: &Arc<TransportMetrics>,
    report: Option<DegradedReason>,
) -> GraphSupervisor {
    let mut registry = ServiceRegistry::new();
    let metrics = Arc::clone(metrics);
    registry.register(ctx, move || Sockets {
        metrics: Arc::clone(&metrics),
        report: report.clone(),
    });
    registry.start(ctx).expect("start supervisor")
}

fn errors(metrics: &TransportMetrics, n: usize) {
    for _ in 0..n {
        metrics.record_error();
    }
}

#[tokio::test(start_paused = true)]
async fn failing_sockets_degrade_after_two_windows_and_recover_after_one() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let metrics = Arc::new(TransportMetrics::new());
    let supervisor = start(&ctx, &metrics, None);
    baseline().await;
    assert_eq!(status(&ctx), (ServiceState::Online, None));

    // One bad window is not "sustained".
    errors(&metrics, 20);
    advance(WINDOW).await;
    settle().await;
    assert_eq!(status(&ctx), (ServiceState::Online, None));

    errors(&metrics, 20);
    advance(WINDOW).await;
    settle().await;
    assert_eq!(
        status(&ctx),
        (
            ServiceState::Degraded,
            Some(StateDetail::Degraded(DegradedReason::TransportErrors))
        )
    );

    // Traffic flows again: one healthy window clears it.
    for _ in 0..5 {
        metrics.record_rx(64);
    }
    advance(WINDOW).await;
    settle().await;
    assert_eq!(status(&ctx), (ServiceState::Online, None));

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

#[tokio::test(start_paused = true)]
async fn errors_on_a_busy_socket_and_rate_limited_drops_do_not_degrade() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let metrics = Arc::new(TransportMetrics::new());
    let supervisor = start(&ctx, &metrics, None);
    baseline().await;

    for _ in 0..3 {
        errors(&metrics, 20);
        for _ in 0..100 {
            metrics.record_rx(64);
            metrics.record_drop();
        }
        advance(WINDOW).await;
        settle().await;
    }
    assert_eq!(status(&ctx), (ServiceState::Online, None));

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

/// A service that already says why it is degraded keeps its own reason.
#[tokio::test(start_paused = true)]
async fn the_service_s_own_degraded_reason_is_kept() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let metrics = Arc::new(TransportMetrics::new());
    let supervisor = start(&ctx, &metrics, Some(DegradedReason::UpstreamUnreachable));
    baseline().await;

    for _ in 0..3 {
        errors(&metrics, 20);
        advance(WINDOW).await;
        settle().await;
    }
    assert_eq!(
        status(&ctx),
        (
            ServiceState::Degraded,
            Some(StateDetail::Degraded(DegradedReason::UpstreamUnreachable))
        )
    );

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

/// Fails its first start as a socket on an interface that is not there yet, then serves.
struct LateLink {
    starts: Arc<AtomicU32>,
}

impl LanforgeService for LateLink {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: ServiceId::Dhcp4,
            display_name: "dhcp4",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_secs(3600),
                max_backoff: Duration::from_secs(3600),
                max_retries: 0,
                healthy_uptime: Duration::from_millis(50),
            },
            shutdown_timeout: Duration::from_millis(100),
            deps: &[],
            condition: Condition::ALWAYS,
        }
    }
}

impl AsyncService for LateLink {
    async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        if self.starts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(CoreError::Bind(BindError::new(
                BindErrorKind::NoDevice,
                "0.0.0.0:67%lan0".to_string(),
                io::Error::from_raw_os_error(19),
            )));
        }
        h.ready();
        loop {
            if matches!(
                h.next_command().await,
                ServiceCommand::Stop | ServiceCommand::Shutdown
            ) {
                return Ok(());
            }
        }
    }
}

fn links(names: &[(&str, bool)]) -> InterfaceSnapshot {
    InterfaceSnapshot {
        links: names
            .iter()
            .enumerate()
            .map(|(i, &(name, carrier))| LinkInfo {
                ifindex: u32::try_from(i).unwrap() + 1,
                name: name.to_string(),
                carrier,
                addrs: SmallVec::new(),
            })
            .collect(),
        generation: 1,
    }
}

/// A service whose socket needs an interface that is missing starts as soon as the interface
/// appears, not after its backoff (an hour here); other interface changes do not wake it.
#[tokio::test(start_paused = true)]
async fn a_missing_interface_retries_when_a_link_appears() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    ctx.set_interfaces_snapshot(links(&[("lo", true)]));
    let starts = Arc::new(AtomicU32::new(0));
    let mut registry = ServiceRegistry::new();
    let counter = Arc::clone(&starts);
    registry.register(&ctx, move || LateLink {
        starts: Arc::clone(&counter),
    });
    let supervisor = registry.start(&ctx).expect("start supervisor");
    settle().await;
    assert_eq!(ctx.get_service_state(ServiceId::Dhcp4), ServiceState::Error);
    let detail = ctx
        .get_service_detail(ServiceId::Dhcp4)
        .map(|d| d.to_string());
    assert!(
        detail
            .as_deref()
            .is_some_and(|d| d.contains("no such interface: 0.0.0.0:67%lan0")),
        "{detail:?}"
    );

    // A carrier change on a known link is not a new interface.
    ctx.set_interfaces_snapshot(links(&[("lo", false)]));
    settle().await;
    assert_eq!(starts.load(Ordering::SeqCst), 1);

    ctx.set_interfaces_snapshot(links(&[("lo", false), ("lan0", true)]));
    settle().await;
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    assert_eq!(
        ctx.get_service_state(ServiceId::Dhcp4),
        ServiceState::Online
    );

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}
