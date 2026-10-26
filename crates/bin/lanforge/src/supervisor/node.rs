//! Per-node state management and status broadcasting.

use lanforge_core::context::LanforgeContext;
use lanforge_core::service::NodeStatus;
use lanforge_types::system::{ServiceId, ServiceState, StateDetail};
use std::time::Instant;
use tokio::sync::watch;

/// Manages the state and status channel for a single service node in the graph.
#[derive(Debug)]
pub struct NodeHandle {
    pub id: ServiceId,
    pub tx: watch::Sender<NodeStatus>,
    pub rx: watch::Receiver<NodeStatus>,
    pub shutdown_tx: watch::Sender<bool>,
    pub shutdown_rx: watch::Receiver<bool>,
}

impl NodeHandle {
    /// Creates a new `NodeHandle` in the `Pending` state.
    #[must_use]
    pub fn new(id: ServiceId) -> Self {
        let (tx, rx) = watch::channel(NodeStatus {
            state: ServiceState::Inactive,
            detail: None,
            since: Instant::now(),
            generation: 0,
        });
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            id,
            tx,
            rx,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Returns the current node status.
    #[must_use]
    pub fn current(&self) -> NodeStatus {
        self.rx.borrow().clone()
    }

    /// Sets the node status, updating the watch channel and the global context.
    pub fn set_status(
        &self,
        ctx: &LanforgeContext,
        state: ServiceState,
        detail: Option<StateDetail>,
    ) {
        let current_gen = self.rx.borrow().generation;
        let new_status = NodeStatus {
            state,
            detail: detail.clone(),
            since: Instant::now(),
            generation: current_gen.wrapping_add(1),
        };

        let _ = self.tx.send(new_status);
        ctx.set_service_state(self.id, state);
        // Always overwrite: `None` must clear a stale reason (e.g. Dormant -> Online).
        ctx.set_service_detail(self.id, detail);
    }
}

/// Checks if a service state is considered settled (has reached a terminal or steady state).
#[must_use]
pub const fn is_settled(state: ServiceState) -> bool {
    matches!(
        state,
        ServiceState::Online
            | ServiceState::Degraded
            | ServiceState::Inactive
            | ServiceState::Error
    )
}
