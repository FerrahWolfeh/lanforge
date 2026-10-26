//! Service supervision and lifecycle management.
//!
//! This module defines the traits and types for managing long-running services
//! within the Lanforge system. Services are components that provide identity
//! and respond to external signals from the global event bus.
//!
//! # Service Types
//!
//! | Trait              | Execution Model | Use Case                        |
//! |--------------------|-----------------|---------------------------------|
//! | [`AsyncService`]   | Tokio async task | Network protocols, HTTP APIs    |
//!
//! # Service Lifecycle
//!
//! 1. **Dependencies**: Declares required services via [`AsyncService::dependencies`].
//! 2. **Initialization**: [`init()`](AsyncService::init) binds resources before readiness.
//! 3. **Readiness**: Supervisor signals online and readiness automatically.
//! 4. **Execution**: [`serve()`](AsyncService::serve) runs the main event/packet loop.
//! 5. **Cleanup**: [`cleanup()`](AsyncService::cleanup) performs cooperative teardown.
//!
//! # Example
//!
//! ```rust
//! use lanforge_core::service::{AsyncService, LanforgeService, ServiceId, ServiceSpec, RuntimeClass, RestartPolicy, Condition};
//! use lanforge_core::context::LanforgeContext;
//! use lanforge_core::error::CoreError;
//! use std::time::Duration;
//!
//! struct MyService;
//!
//! impl LanforgeService for MyService {
//!     fn spec(&self) -> ServiceSpec {
//!         ServiceSpec {
//!             id: ServiceId::Db,
//!             display_name: "My Service",
//!             runtime: RuntimeClass::Shared,
//!             restart: RestartPolicy::default(),
//!             shutdown_timeout: Duration::from_secs(3),
//!             deps: &[],
//!             condition: Condition::ALWAYS,
//!         }
//!     }
//! }
//!
//! impl AsyncService for MyService {
//!     async fn serve(&mut self, _ctx: &LanforgeContext, h: &lanforge_core::service::ServiceHandle) -> Result<(), CoreError> {
//!         h.ready();
//!         // Service main loop
//!         Ok(())
//!     }
//! }
//! ```

use crate::bus::{LanforgeEvent, SystemEvent};
use crate::context::LanforgeContext;
use crate::error::CoreError;
use lanforge_types::config::ConfigDomain;
pub use lanforge_types::system::{
    DegradedReason, DormantReason, ServiceBanner, ServiceId, ServiceState, StateDetail,
};
use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Execution runtime environment class for a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeClass {
    /// Runs as a cooperative task on the shared Tokio worker pool.
    Shared,
    /// Runs on a dedicated OS thread and Tokio runtime.
    Dedicated {
        multi_thread: bool,
        worker_threads: Option<u8>,
    },
}

/// Backoff and retry policy for supervised restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartPolicy {
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    pub max_retries: u32, // 0 = infinite
    pub healthy_uptime: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            base_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            max_retries: 0,
            healthy_uptime: Duration::from_secs(30),
        }
    }
}

/// Inter-service dependency edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub target: ServiceId,
    pub kind: EdgeKind,
    pub on_loss: LossPolicy,
}

impl Edge {
    /// Returns the target service identifier of this edge.
    #[must_use]
    pub const fn target(&self) -> ServiceId {
        self.target
    }

    /// Edge indicating that this node must start after the target has settled.
    #[must_use]
    pub const fn after(target: ServiceId) -> Self {
        Self {
            target,
            kind: EdgeKind::After,
            on_loss: LossPolicy::Continue,
        }
    }

    /// Edge indicating that this node watches the target without blocking boot.
    #[must_use]
    pub const fn wants(target: ServiceId) -> Self {
        Self {
            target,
            kind: EdgeKind::Wants,
            on_loss: LossPolicy::Continue,
        }
    }

    /// Edge indicating that this node requires the target to be Online before starting.
    #[must_use]
    pub const fn requires(target: ServiceId, on_loss: LossPolicy) -> Self {
        Self {
            target,
            kind: EdgeKind::Requires,
            on_loss,
        }
    }
}

/// Snapshot value representing the runtime state of a graph node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub state: ServiceState,
    pub detail: Option<StateDetail>,
    pub since: Instant,
    pub generation: u64,
}

impl NodeStatus {
    /// Creates a new initial node status.
    #[must_use]
    pub fn new(state: ServiceState) -> Self {
        Self {
            state,
            detail: None,
            since: Instant::now(),
            generation: 1,
        }
    }

    /// Creates a node status with explicit state, detail, and generation.
    #[must_use]
    pub fn with_detail(state: ServiceState, detail: Option<StateDetail>, generation: u64) -> Self {
        Self {
            state,
            detail,
            since: Instant::now(),
            generation,
        }
    }
}

/// Kind of edge between services in the dependency graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    After,
    Wants,
    Requires,
}

/// Behaviour when a required dependency is lost at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossPolicy {
    Continue,
    Degrade,
    Pause,
    Restart,
}

/// Activation condition state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    Active,
    Dormant(DormantReason),
}

/// Pure activation condition evaluated over live configuration.
#[derive(Clone)]
pub struct Condition {
    pub sections: &'static [ConfigDomain],
    pub eval: fn(&LanforgeContext) -> Activation,
}

impl Condition {
    pub const ALWAYS: Self = Self {
        sections: &[],
        eval: |_| Activation::Active,
    };

    /// Evaluates the activation condition against the provided context.
    #[must_use]
    pub fn evaluate(&self, ctx: &LanforgeContext) -> Activation {
        (self.eval)(ctx)
    }
}

impl std::fmt::Debug for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Condition")
            .field("sections", &self.sections)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Condition {
    fn eq(&self, other: &Self) -> bool {
        self.sections == other.sections && (self.eval as usize == other.eval as usize)
    }
}

impl std::cmp::Eq for Condition {}

/// Declarative service specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub id: ServiceId,
    pub display_name: &'static str,
    pub runtime: RuntimeClass,
    pub restart: RestartPolicy,
    pub shutdown_timeout: Duration,
    pub deps: &'static [Edge],
    pub condition: Condition,
}

/// Supervision specification and lifecycle commands delivered directly to a service handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCommand {
    Stop,
    Start,
    Restart,
    Shutdown,
    DependencyLost { id: ServiceId, policy: LossPolicy },
    DependencyRestored { id: ServiceId },
}

/// Core trait defining a service within the Lanforge system.
pub trait LanforgeService: Send + Sync {
    /// Returns the declarative specification for this service.
    fn spec(&self) -> ServiceSpec;

    /// Returns a one-line description of this service instance for logging.
    fn describe(&self) -> String {
        self.spec().display_name.to_string()
    }

    /// Called when the service is stopping or the daemon is terminating.
    /// Synchronous in-memory cleanup only. Async cleanup must be in [`AsyncService::cleanup`].
    ///
    /// # Errors
    /// Returns a [`CoreError`] if in-memory shutdown operations fail.
    fn on_shutdown(&mut self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// A service that executes within a Tokio asynchronous task.
pub trait AsyncService: LanforgeService {
    /// Returns service-specific key-value statistics and metrics for the status banner.
    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(Cow<'static, str>, String)> {
        Vec::new()
    }

    /// Generates the complete service status banner containing health, uptime, and metrics.
    fn banner(&self, ctx: &LanforgeContext) -> ServiceBanner {
        let spec = self.spec();
        ServiceBanner {
            id: spec.id,
            name: spec.display_name.to_string(),
            state: ctx.get_service_state(spec.id),
            uptime_secs: ctx.get_service_uptime(spec.id),
            stats: self.stats(ctx),
            detail: ctx.get_service_detail(spec.id),
        }
    }

    /// Resource acquisition phase.
    fn init(
        &mut self,
        _ctx: &LanforgeContext,
    ) -> impl Future<Output = Result<(), CoreError>> + Send {
        async { Ok(()) }
    }

    /// Main execution loop. Receives the `ServiceHandle` to signal truthful readiness and handle commands.
    fn serve(
        &mut self,
        ctx: &LanforgeContext,
        h: &ServiceHandle,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    /// Cooperative async cleanup on shutdown.
    fn cleanup(
        &mut self,
        _ctx: &LanforgeContext,
    ) -> impl Future<Output = Result<(), CoreError>> + Send {
        async { Ok(()) }
    }
}

/// A handle provided to services to manage their lifecycle, truthful readiness, and commands.
#[derive(Clone)]
pub struct ServiceHandle {
    id: ServiceId,
    ctx: LanforgeContext,
    signaled: Arc<AtomicBool>,
    restart_requested: Arc<AtomicBool>,
    cmd_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<ServiceCommand>>>,
    _keepalive_tx: Option<tokio::sync::mpsc::Sender<ServiceCommand>>,
}

impl ServiceHandle {
    /// Creates a new service handle.
    #[must_use]
    pub fn new(id: ServiceId, ctx: LanforgeContext) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        Self {
            id,
            ctx,
            signaled: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            cmd_rx: Arc::new(tokio::sync::Mutex::new(rx)),
            _keepalive_tx: Some(tx),
        }
    }

    /// Creates a new service handle with a specific command receiver channel.
    #[must_use]
    pub fn with_command_channel(
        id: ServiceId,
        ctx: LanforgeContext,
        cmd_rx: tokio::sync::mpsc::Receiver<ServiceCommand>,
    ) -> Self {
        Self {
            id,
            ctx,
            signaled: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            cmd_rx: Arc::new(tokio::sync::Mutex::new(cmd_rx)),
            _keepalive_tx: None,
        }
    }

    /// Returns the ID of the service this handle belongs to.
    #[must_use]
    pub const fn id(&self) -> ServiceId {
        self.id
    }

    /// Signals that the service is initialized and actively serving traffic (Starting|Degraded -> Online).
    /// This is idempotent per start generation; multiple calls in the same start will only publish one `ServiceReady` event.
    pub fn ready(&self) {
        if !self.signaled.swap(true, Ordering::SeqCst) {
            self.ctx.set_service_state(self.id, ServiceState::Online);
            self.ctx.set_service_detail(self.id, None);
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::System(SystemEvent::ServiceReady {
                    id: self.id,
                }));
        }
    }

    /// Backward compatibility alias for `ready()`.
    #[inline]
    pub fn signal_ready(&self) {
        self.ready();
    }

    /// Returns true if readiness has been signaled for this generation.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.signaled.load(Ordering::SeqCst)
    }

    /// Marks the service as degraded with a specific reason.
    pub fn degraded(&self, why: DegradedReason) {
        self.ctx.set_service_state(self.id, ServiceState::Degraded);
        self.ctx.set_service_detail(self.id, Some(StateDetail::Degraded(why)));
        if !self.signaled.swap(true, Ordering::SeqCst) {
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::System(SystemEvent::ServiceReady {
                    id: self.id,
                }));
        }
    }

    /// Recovers from a degraded state back to Online.
    pub fn recovered(&self) {
        self.ctx.set_service_state(self.id, ServiceState::Online);
        self.ctx.set_service_detail(self.id, None);
    }

    /// Marks the service as dormant (Inactive) due to a condition and settles it cleanly.
    /// The service should return Ok(()) immediately after calling this.
    pub fn dormant(&self, why: DormantReason) {
        self.ctx.set_service_state(self.id, ServiceState::Inactive);
        self.ctx.set_service_detail(self.id, Some(StateDetail::Dormant(why)));
        if !self.signaled.swap(true, Ordering::SeqCst) {
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::System(SystemEvent::ServiceReady {
                    id: self.id,
                }));
        }
    }

    /// Requests an explicit supervisor restart when `serve()` returns `Ok(())`.
    pub fn request_restart(&self) {
        self.restart_requested.store(true, Ordering::SeqCst);
    }

    /// Returns true if an explicit restart was requested.
    #[must_use]
    pub fn is_restart_requested(&self) -> bool {
        self.restart_requested.load(Ordering::SeqCst)
    }

    /// Receives the next lifecycle command directed to this service.
    /// Returns `ServiceCommand::Shutdown` if the supervisor channel is closed.
    pub async fn next_command(&self) -> ServiceCommand {
        let mut rx = self.cmd_rx.lock().await;
        rx.recv().await.unwrap_or(ServiceCommand::Shutdown)
    }

    /// Convenience runner for services that execute a single main future until stopped.
    ///
    /// # Errors
    /// Returns `CoreError` if the underlying future fails.
    pub async fn run_until_stopped<F, T>(&self, fut: F) -> Result<Option<T>, CoreError>
    where
        F: Future<Output = Result<T, CoreError>>,
    {
        tokio::pin!(fut);
        loop {
            tokio::select! {
                biased;
                cmd = self.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => return Ok(None),
                        ServiceCommand::Restart => {
                            self.request_restart();
                            return Ok(None);
                        }
                        _ => {}
                    }
                }
                res = &mut fut => {
                    return res.map(Some);
                }
            }
        }
    }
}

/// Compatibility alias for `ServiceHandle`.
pub type ServiceControl = ServiceHandle;

/// Trait implemented by decoupled services to provide dynamic status and metrics.
pub trait StatusProvider: Send + Sync {
    /// Returns the service's current banner containing health, uptime, and metrics.
    fn banner(&self, ctx: &LanforgeContext) -> ServiceBanner;
}

impl<T: AsyncService> StatusProvider for T {
    fn banner(&self, ctx: &LanforgeContext) -> ServiceBanner {
        <T as AsyncService>::banner(self, ctx)
    }
}
