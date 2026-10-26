//! Per-service lifecycle runner task.

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
use lanforge_types::system::{ServiceId, ServiceState, StateDetail};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Notify, mpsc, watch};
use tracing::{debug, error, info, warn};

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
    pub notify_condition: Arc<Notify>,
    pub shutdown_rx: watch::Receiver<bool>,
}

impl<S, F> ServiceRunner<S, F>
where
    S: AsyncService + LanforgeService + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    /// Runs the supervised service loop until system shutdown.
    #[allow(clippy::too_many_lines)]
    pub async fn run(mut self) {
        let mut consecutive_failures: u32 = 0;

        loop {
            if !self.ctx.is_running() || *self.shutdown_rx.borrow() {
                self.node
                    .set_status(&self.ctx, ServiceState::Inactive, None);
                break;
            }

            // 1. Condition evaluation
            let activation = self.spec.condition.evaluate(&self.ctx);
            if let Activation::Dormant(reason) = activation {
                debug!(service = %self.spec.id, reason = ?reason, "Service condition dormant");
                self.node.set_status(
                    &self.ctx,
                    ServiceState::Inactive,
                    Some(StateDetail::Dormant(reason)),
                );

                // Wait for condition re-evaluation notification or shutdown
                tokio::select! {
                    () = self.notify_condition.notified() => continue,
                    _ = self.shutdown_rx.changed() => {
                        if *self.shutdown_rx.borrow() { break; }
                    }
                }
                continue;
            }

            // 2. Dependency resolution
            match self.wait_for_dependencies().await {
                Ok(true) => {
                    // All dependencies satisfied, proceed to start
                }
                Ok(false) => {
                    // A required dependency is dormant; this service is now dormant
                    // Wait for dependency change or condition notification
                    tokio::select! {
                        () = self.notify_condition.notified() => continue,
                        _ = self.shutdown_rx.changed() => {
                            if *self.shutdown_rx.borrow() { break; }
                        }
                    }
                    continue;
                }
                Err(()) => {
                    // Shutdown requested
                    self.node
                        .set_status(&self.ctx, ServiceState::Inactive, None);
                    break;
                }
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
                self.handle_failure(init_err, consecutive_failures).await;
                continue;
            }

            // Listen for readiness events to sync NodeStatus watch channel
            let mut sys_bus = self.ctx.bus().subscribe_system();

            debug!(service = %self.spec.id, "Serving service");
            let mut serve_fut = Box::pin(service.serve(&self.ctx, &handle));

            let mut lost_deps: Vec<(ServiceId, LossPolicy)> = Vec::new();
            let mut loss_overridden = false;
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

            if *self.shutdown_rx.borrow() || !self.ctx.is_running() {
                self.node
                    .set_status(&self.ctx, ServiceState::Inactive, None);
                break;
            }

            if is_healthy(uptime, &self.spec.restart) {
                consecutive_failures = 0;
            }

            if let Some(res) = serve_res {
                match res {
                    Ok(()) => {
                        if handle.is_restart_requested() {
                            debug!(service = %self.spec.id, "Restart requested, recycling");
                            continue;
                        }
                        info!(service = %self.spec.id, "Service exited cleanly");
                        self.node
                            .set_status(&self.ctx, ServiceState::Inactive, None);
                        // Wait for condition reactivation or shutdown
                        tokio::select! {
                            () = self.notify_condition.notified() => {}
                            _ = self.shutdown_rx.changed() => {
                                if *self.shutdown_rx.borrow() { break; }
                            }
                        }
                    }
                    Err(err) => {
                        error!(service = %self.spec.id, error = %err, "Service terminated with error");
                        consecutive_failures += 1;
                        self.handle_failure(err, consecutive_failures).await;
                    }
                }
            } else {
                break;
            }
        }
    }

    async fn wait_for_dependencies(&mut self) -> Result<bool, ()> {
        for &edge in self.spec.deps {
            match edge.kind {
                lanforge_core::service::EdgeKind::Requires => {
                    let target = edge.target;
                    if let Some(rx) = self.dep_rxs.get_mut(&target) {
                        loop {
                            let status = rx.borrow().clone();
                            if status.state == ServiceState::Online
                                || status.state == ServiceState::Degraded
                            {
                                break;
                            }
                            if status.state == ServiceState::Inactive
                                && matches!(status.detail, Some(StateDetail::Dormant(_)))
                            {
                                // Required dependency is dormant -> propagate dormancy
                                self.node.set_status(
                                    &self.ctx,
                                    ServiceState::Inactive,
                                    Some(StateDetail::DependencyDormant(target)),
                                );
                                return Ok(false);
                            }
                            if *self.shutdown_rx.borrow() {
                                return Err(());
                            }

                            tokio::select! {
                                _ = self.shutdown_rx.changed() => {
                                    if *self.shutdown_rx.borrow() { return Err(()); }
                                }
                                res = rx.changed() => {
                                    if res.is_err() { return Err(()); }
                                }
                            }
                        }
                    }
                }
                lanforge_core::service::EdgeKind::After => {
                    let target = edge.target;
                    if let Some(rx) = self.dep_rxs.get_mut(&target) {
                        loop {
                            let status = rx.borrow().clone();
                            if is_settled(status.state) {
                                break;
                            }
                            if *self.shutdown_rx.borrow() {
                                return Err(());
                            }

                            tokio::select! {
                                _ = self.shutdown_rx.changed() => {
                                    if *self.shutdown_rx.borrow() { return Err(()); }
                                }
                                res = rx.changed() => {
                                    if res.is_err() { return Err(()); }
                                }
                            }
                        }
                    }
                }
                lanforge_core::service::EdgeKind::Wants => {
                    // Advisory: non-blocking
                }
            }
        }

        Ok(true)
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

    async fn handle_failure(&mut self, err: CoreError, failures: u32) {
        let decision = calculate_backoff(&self.spec.restart, failures);
        match decision {
            BackoffDecision::RetryIn(delay) => {
                warn!(
                    service = %self.spec.id,
                    delay_secs = delay.as_secs(),
                    failures,
                    "Scheduling restart after backoff delay"
                );
                self.node.set_status(
                    &self.ctx,
                    ServiceState::Error,
                    Some(StateDetail::Failed {
                        attempts: failures,
                        last_error: err.to_string(),
                    }),
                );
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    _ = self.shutdown_rx.changed() => {}
                    () = self.notify_condition.notified() => {}
                }
            }
            BackoffDecision::Exhausted => {
                error!(
                    service = %self.spec.id,
                    failures,
                    "Service retry limit exhausted; entering terminal Error state"
                );
                self.node.set_status(
                    &self.ctx,
                    ServiceState::Error,
                    Some(StateDetail::Failed {
                        attempts: failures,
                        last_error: format!("Retries exhausted: {err}"),
                    }),
                );
                tokio::select! {
                    _ = self.shutdown_rx.changed() => {}
                    () = self.notify_condition.notified() => {}
                }
            }
        }
    }
}
