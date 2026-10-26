//! Per-service lifecycle runner task.

use crate::supervisor::RunnerLinks;
use crate::supervisor::backoff::{BackoffDecision, calculate_backoff, is_healthy};
use crate::supervisor::node::{NodeHandle, is_settled};
use futures::future::select_all;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    Activation, AsyncService, DegradedReason, Edge, EdgeKind, LanforgeService, LossPolicy,
    NodeStatus, ServiceCommand, ServiceHandle, ServiceSpec,
};
use lanforge_types::system::{ServiceAction, ServiceId, ServiceState, StateDetail};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep_until;
use tracing::{debug, error, info, warn};

/// Outcome of a wait that can be interrupted by shutdown or an admin request.
enum Wake {
    /// Re-run the lifecycle loop (condition, dependencies, start).
    Retry,
    /// The daemon is shutting down.
    Shutdown,
}

/// Why the supervisor asked a running service to stop.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StopCause {
    Admin,
    Dormant,
}

/// Result of waiting for the dependencies of a node.
enum DepsOutcome {
    Ready,
    /// A required dependency is dormant: this node is dormant too.
    Dormant,
    Interrupted(Wake),
}

/// Runner responsible for the complete lifecycle of one service.
pub struct ServiceRunner<S, F>
where
    S: AsyncService + LanforgeService + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    pub spec: ServiceSpec,
    pub factory: F,
    pub ctx: LanforgeContext,
    pub node: Arc<NodeHandle>,
    pub dep_rxs: HashMap<ServiceId, watch::Receiver<NodeStatus>>,
    pub condition_rx: watch::Receiver<u64>,
    pub control_rx: mpsc::Receiver<ServiceAction>,
    pub shutdown_rx: watch::Receiver<bool>,
    /// Set by an admin `stop`; cleared by `start`/`restart`. Survives restarts of the loop.
    admin_stopped: bool,
}

impl<S, F> ServiceRunner<S, F>
where
    S: AsyncService + LanforgeService + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    /// Creates a runner for `spec` wired to the graph through `links`.
    pub fn new(spec: ServiceSpec, factory: F, ctx: LanforgeContext, links: RunnerLinks) -> Self {
        let shutdown_rx = links.node.shutdown_rx.clone();
        Self {
            spec,
            factory,
            ctx,
            node: links.node,
            dep_rxs: links.dep_rxs,
            condition_rx: links.condition_rx,
            control_rx: links.control_rx,
            shutdown_rx,
            admin_stopped: false,
        }
    }

    fn is_shutting_down(&self) -> bool {
        *self.shutdown_rx.borrow() || !self.ctx.is_running()
    }

    /// Runs the supervised service loop until system shutdown.
    #[allow(clippy::too_many_lines)]
    pub async fn run(mut self) {
        let mut consecutive_failures: u32 = 0;

        loop {
            if self.is_shutting_down() {
                break;
            }

            // 0. Admin stop is sticky until an explicit start/restart (D-20).
            if self.admin_stopped {
                self.node.set_status(
                    &self.ctx,
                    ServiceState::Inactive,
                    Some(StateDetail::AdminStopped),
                );
                match self.wait_while_idle(false).await {
                    Wake::Retry => continue,
                    Wake::Shutdown => break,
                }
            }

            // 1. Condition evaluation. Mark the epoch seen *before* evaluating so a config
            //    change racing with the evaluation still wakes the wait below.
            self.condition_rx.borrow_and_update();
            if let Activation::Dormant(reason) = self.spec.condition.evaluate(&self.ctx) {
                debug!(service = %self.spec.id, reason = ?reason, "Service condition dormant");
                self.node.set_status(
                    &self.ctx,
                    ServiceState::Inactive,
                    Some(StateDetail::Dormant(reason)),
                );
                match self.wait_while_idle(true).await {
                    Wake::Retry => continue,
                    Wake::Shutdown => break,
                }
            }

            // 2. Dependency resolution
            match self.wait_for_dependencies().await {
                DepsOutcome::Ready => {}
                DepsOutcome::Dormant => match self.wait_while_idle(true).await {
                    Wake::Retry => continue,
                    Wake::Shutdown => break,
                },
                DepsOutcome::Interrupted(Wake::Retry) => continue,
                DepsOutcome::Interrupted(Wake::Shutdown) => break,
            }

            // 3. Execution Phase
            self.node
                .set_status(&self.ctx, ServiceState::Starting, None);
            let start_time = Instant::now();

            let (cmd_tx, cmd_rx) = mpsc::channel(32);
            let handle =
                ServiceHandle::with_command_channel(self.spec.id, self.ctx.clone(), cmd_rx);

            let mut service = (self.factory)();

            debug!(service = %self.spec.id, "Initializing service");
            if let Err(init_err) = service.init(&self.ctx).await {
                error!(service = %self.spec.id, error = %init_err, "Service initialization failed");
                consecutive_failures += 1;
                match self.handle_failure(init_err, consecutive_failures).await {
                    Wake::Retry => continue,
                    Wake::Shutdown => break,
                }
            }

            // Listen for readiness events to sync NodeStatus watch channel
            let mut sys_bus = self.ctx.bus().subscribe_system();

            debug!(service = %self.spec.id, "Serving service");
            let mut serve_fut = Box::pin(service.serve(&self.ctx, &handle));

            let mut lost_deps: Vec<(ServiceId, LossPolicy)> = Vec::new();
            let mut loss_overridden = false;
            let mut stop_cause: Option<StopCause> = None;
            let mut stop_deadline: Option<tokio::time::Instant> = None;
            let serve_res = loop {
                tokio::select! {
                    biased;

                    // Shutdown signal
                    _ = self.shutdown_rx.changed() => {
                        if *self.shutdown_rx.borrow() {
                            let _ = cmd_tx.send(ServiceCommand::Shutdown).await;
                            break None;
                        }
                    }

                    // A service that ignores Stop is cancelled after its shutdown timeout.
                    () = sleep_until(stop_deadline.unwrap_or_else(tokio::time::Instant::now)), if stop_deadline.is_some() => {
                        warn!(service = %self.spec.id, "Service did not stop within its shutdown timeout; cancelling");
                        break None;
                    }

                    Some(action) = self.control_rx.recv() => {
                        match action {
                            ServiceAction::Stop => {
                                info!(service = %self.spec.id, "Admin stop requested");
                                self.admin_stopped = true;
                                stop_cause = Some(StopCause::Admin);
                                stop_deadline.get_or_insert_with(|| tokio::time::Instant::now() + self.spec.shutdown_timeout);
                                let _ = cmd_tx.send(ServiceCommand::Stop).await;
                            }
                            ServiceAction::Restart => {
                                // The service decides: bounce in place (PPPoE, firewall) or return
                                // after `request_restart()` so the runner starts it again.
                                info!(service = %self.spec.id, "Admin restart requested");
                                let _ = cmd_tx.send(ServiceCommand::Restart).await;
                            }
                            ServiceAction::Start => {
                                debug!(service = %self.spec.id, "Admin start ignored: service already running");
                            }
                        }
                    }

                    // Live condition re-evaluation (D-3): a disabled service is stopped, others untouched.
                    Ok(()) = self.condition_rx.changed(), if stop_cause.is_none() => {
                        if let Activation::Dormant(reason) = self.spec.condition.evaluate(&self.ctx) {
                            info!(service = %self.spec.id, ?reason, "Condition became dormant; stopping service");
                            stop_cause = Some(StopCause::Dormant);
                            stop_deadline.get_or_insert_with(|| tokio::time::Instant::now() + self.spec.shutdown_timeout);
                            let _ = cmd_tx.send(ServiceCommand::Stop).await;
                        }
                    }

                    // System bus events (e.g., ServiceReady from handle)
                    Ok(event) = sys_bus.recv() => {
                        if let LanforgeEvent::System(SystemEvent::ServiceReady { id }) = event.event
                            && id == self.spec.id
                        {
                            let current_state = self.ctx.get_service_state(self.spec.id);
                            let current_detail = self.ctx.get_service_detail(self.spec.id);
                            self.node.set_status(&self.ctx, current_state, current_detail);
                        }
                    }

                    // Monitor Required dependencies for loss/recovery. Loss never stops or
                    // restarts the service (D-1); it only applies the edge's LossPolicy.
                    Some((target, policy, lost)) = Self::next_dependency_transition(
                        self.spec.deps,
                        &mut self.dep_rxs,
                        &lost_deps,
                    ) => {
                        // Publish the status before notifying the service, so observers never see
                        // a command the status does not reflect yet.
                        let cmd = if lost {
                            warn!(service = %self.spec.id, %target, ?policy, "Required dependency lost");
                            lost_deps.push((target, policy));
                            ServiceCommand::DependencyLost { id: target, policy }
                        } else {
                            info!(service = %self.spec.id, %target, "Required dependency restored");
                            lost_deps.retain(|&(id, _)| id != target);
                            ServiceCommand::DependencyRestored { id: target }
                        };
                        self.apply_loss_status(&lost_deps, &mut loss_overridden);
                        let _ = cmd_tx.send(cmd).await;
                    }

                    // Main service execution outcome
                    res = &mut serve_fut => {
                        break Some(res);
                    }
                }
            };

            drop(serve_fut);
            let uptime = start_time.elapsed();
            let _ = service.on_shutdown();
            let _ = service.cleanup(&self.ctx).await;

            if self.is_shutting_down() {
                break;
            }

            if is_healthy(uptime, &self.spec.restart) {
                consecutive_failures = 0;
            }

            // A supervisor-requested stop wins over whatever the service returned, including a
            // restart it requested earlier and handled in place.
            if stop_cause.is_some() {
                continue;
            }

            match serve_res {
                Some(Ok(())) if handle.is_restart_requested() => {
                    debug!(service = %self.spec.id, "Restart requested, recycling");
                }
                Some(Ok(())) => {
                    info!(service = %self.spec.id, "Service exited cleanly");
                    self.node.set_status(
                        &self.ctx,
                        ServiceState::Inactive,
                        Some(StateDetail::Exited),
                    );
                    if matches!(self.wait_while_idle(true).await, Wake::Shutdown) {
                        break;
                    }
                }
                Some(Err(err)) => {
                    error!(service = %self.spec.id, error = %err, "Service terminated with error");
                    consecutive_failures += 1;
                    if matches!(
                        self.handle_failure(err, consecutive_failures).await,
                        Wake::Shutdown
                    ) {
                        break;
                    }
                }
                // Cancelled outside of shutdown (only via the stop deadline, handled above).
                None => {}
            }
        }

        self.node
            .set_status(&self.ctx, ServiceState::Inactive, None);
    }

    /// Waits while the node is not running: until shutdown, an admin request, or (when
    /// `on_condition`) a condition epoch bump.
    async fn wait_while_idle(&mut self, on_condition: bool) -> Wake {
        loop {
            tokio::select! {
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        return Wake::Shutdown;
                    }
                }
                Ok(()) = self.condition_rx.changed(), if on_condition => return Wake::Retry,
                Some(action) = self.control_rx.recv() => {
                    if let Some(wake) = self.apply_idle_action(action) {
                        return wake;
                    }
                }
            }
        }
    }

    /// Applies an admin request received while the service is not running.
    fn apply_idle_action(&mut self, action: ServiceAction) -> Option<Wake> {
        match action {
            ServiceAction::Stop if self.admin_stopped => None,
            ServiceAction::Stop => {
                info!(service = %self.spec.id, "Admin stop requested while idle");
                self.admin_stopped = true;
                Some(Wake::Retry)
            }
            ServiceAction::Start | ServiceAction::Restart => {
                info!(service = %self.spec.id, ?action, "Admin start requested");
                self.admin_stopped = false;
                Some(Wake::Retry)
            }
        }
    }

    async fn wait_for_dependencies(&mut self) -> DepsOutcome {
        for &edge in self.spec.deps {
            let target = edge.target;
            let Some(mut rx) = self.dep_rxs.get(&target).cloned() else {
                continue;
            };
            loop {
                let status = rx.borrow_and_update().clone();
                let satisfied = match edge.kind {
                    EdgeKind::Requires => {
                        if matches!(status.state, ServiceState::Online | ServiceState::Degraded) {
                            true
                        } else if status.state == ServiceState::Inactive
                            && matches!(
                                status.detail,
                                Some(
                                    StateDetail::Dormant(_)
                                        | StateDetail::DependencyDormant(_)
                                        | StateDetail::AdminStopped
                                )
                            )
                        {
                            // Dormancy propagates transitively through Requires edges.
                            self.node.set_status(
                                &self.ctx,
                                ServiceState::Inactive,
                                Some(StateDetail::DependencyDormant(target)),
                            );
                            return DepsOutcome::Dormant;
                        } else {
                            false
                        }
                    }
                    EdgeKind::After => is_settled(status.state),
                    // Advisory: non-blocking
                    EdgeKind::Wants => true,
                };
                if satisfied {
                    break;
                }

                self.node.set_status(
                    &self.ctx,
                    ServiceState::Starting,
                    Some(StateDetail::WaitingFor(target)),
                );
                tokio::select! {
                    _ = self.shutdown_rx.changed() => {
                        if *self.shutdown_rx.borrow() {
                            return DepsOutcome::Interrupted(Wake::Shutdown);
                        }
                    }
                    res = rx.changed() => {
                        if res.is_err() {
                            return DepsOutcome::Interrupted(Wake::Shutdown);
                        }
                    }
                    Some(action) = self.control_rx.recv() => {
                        if let Some(wake) = self.apply_idle_action(action) {
                            return DepsOutcome::Interrupted(wake);
                        }
                    }
                }
            }
        }

        DepsOutcome::Ready
    }

    /// Waits for the next loss or recovery transition of a `Requires` dependency.
    ///
    /// Returns `(target, policy, lost)`. Never resolves while no required dependency changes
    /// (no polling), and never resolves at all if the service has no required dependencies.
    async fn next_dependency_transition(
        deps: &'static [Edge],
        rxs: &mut HashMap<ServiceId, watch::Receiver<NodeStatus>>,
        lost_deps: &[(ServiceId, LossPolicy)],
    ) -> Option<(ServiceId, LossPolicy, bool)> {
        loop {
            for edge in deps.iter().filter(|e| e.kind == EdgeKind::Requires) {
                let Some(rx) = rxs.get_mut(&edge.target) else {
                    continue;
                };
                let up = matches!(
                    rx.borrow_and_update().state,
                    ServiceState::Online | ServiceState::Degraded
                );
                let was_lost = lost_deps.iter().any(|&(id, _)| id == edge.target);
                if up == was_lost {
                    return Some((edge.target, edge.on_loss, !up));
                }
            }

            let waiters: Vec<_> = deps
                .iter()
                .filter(|e| e.kind == EdgeKind::Requires)
                .filter_map(|e| rxs.get(&e.target).cloned())
                .map(|mut rx| Box::pin(async move { rx.changed().await }))
                .collect();
            if waiters.is_empty() {
                return std::future::pending().await;
            }
            // A closed sender means the dependency's node is gone; nothing more to observe.
            if select_all(waiters).await.0.is_err() {
                return std::future::pending().await;
            }
        }
    }

    /// Recomputes this node's published status from the set of currently lost dependencies.
    ///
    /// `overridden` tracks whether the supervisor (not the service) set the current status, so
    /// clearing the last loss only restores `Online` when the supervisor caused the downgrade.
    fn apply_loss_status(&self, lost_deps: &[(ServiceId, LossPolicy)], overridden: &mut bool) {
        let detail = lost_deps.iter().find_map(|&(target, policy)| match policy {
            LossPolicy::Pause => Some(StateDetail::Paused(target)),
            LossPolicy::Degrade | LossPolicy::Continue => None,
        });
        let detail = detail.or_else(|| {
            lost_deps.iter().find_map(|&(target, policy)| {
                (policy == LossPolicy::Degrade).then(|| {
                    StateDetail::Degraded(DegradedReason::Custom(Cow::Owned(target.to_string())))
                })
            })
        });
        match detail {
            Some(detail) => {
                self.node
                    .set_status(&self.ctx, ServiceState::Degraded, Some(detail));
                *overridden = true;
            }
            None if *overridden => {
                self.node.set_status(&self.ctx, ServiceState::Online, None);
                *overridden = false;
            }
            None => {}
        }
    }

    /// Publishes the failure, then waits for the backoff delay (or, once retries are
    /// exhausted, for a config change or an admin start). An admin start/restart retries now.
    async fn handle_failure(&mut self, err: CoreError, failures: u32) -> Wake {
        let decision = calculate_backoff(&self.spec.restart, failures);
        let (last_error, delay) = match decision {
            BackoffDecision::RetryIn(delay) => {
                warn!(
                    service = %self.spec.id,
                    delay_secs = delay.as_secs(),
                    failures,
                    "Scheduling restart after backoff delay"
                );
                (err.to_string(), Some(delay))
            }
            BackoffDecision::Exhausted => {
                error!(
                    service = %self.spec.id,
                    failures,
                    "Service retry limit exhausted; entering terminal Error state"
                );
                (format!("Retries exhausted: {err}"), None)
            }
        };
        self.node.set_status(
            &self.ctx,
            ServiceState::Error,
            Some(StateDetail::Failed {
                attempts: failures,
                last_error,
            }),
        );

        let backoff = async {
            match delay {
                Some(delay) => tokio::time::sleep(delay).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(backoff);
        loop {
            tokio::select! {
                () = &mut backoff => return Wake::Retry,
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        return Wake::Shutdown;
                    }
                }
                Ok(()) = self.condition_rx.changed() => return Wake::Retry,
                Some(action) = self.control_rx.recv() => {
                    if let Some(wake) = self.apply_idle_action(action) {
                        return wake;
                    }
                }
            }
        }
    }
}
