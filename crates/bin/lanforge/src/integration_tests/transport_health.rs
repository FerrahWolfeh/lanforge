//! Sockets the kernel keeps refusing degrade a service under the real supervisor
//! (`Degraded(TransportErrors)`), and only then (backlog §1.3). The clock is paused: each
//! `advance` is one 10 s health window.

use std::sync::Arc;
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
use lanforge_types::network::snapshot::TransportMetrics;
use lanforge_types::system::{DegradedReason, ServiceId, ServiceState, StateDetail};
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
