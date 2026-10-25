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
//! use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta, ServiceDependency};
//! use lanforge_core::context::LanforgeContext;
//! use lanforge_core::error::CoreError;
//! use std::time::Duration;
//!
//! struct MyService;
//!
//! impl LanforgeService for MyService {
//!     fn meta(&self) -> ServiceMeta {
//!         ServiceMeta {
//!             id: "my-service",
//!             display_name: "My Service",
//!             critical: true,
//!             max_retries: 3,
//!             base_backoff: Duration::from_secs(1),
//!             max_backoff: Duration::from_secs(30),
//!             shutdown_timeout: Duration::from_secs(3),
//!             multi_threaded: false,
//!         }
//!     }
//! }
//!
//! impl AsyncService for MyService {
//!     fn dependencies(&self) -> &'static [ServiceDependency] {
//!         &[ServiceDependency::Database]
//!     }
//!
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
use lanforge_types::system::{
    DegradedReason, DormantReason, ServiceBanner, ServiceState, StateDetail,
};
use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub target: &'static str,
    pub kind: EdgeKind,
    pub on_loss: LossPolicy,
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
}

/// Declarative service specification.
#[derive(Clone)]
pub struct ServiceSpec {
    pub id: &'static str,
    pub display_name: &'static str,
    pub runtime: RuntimeClass,
    pub restart: RestartPolicy,
    pub shutdown_timeout: Duration,
    pub deps: &'static [Edge],
    pub condition: Condition,
}

/// Lifecycle commands delivered directly to a service handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCommand {
    Stop,
    Start,
    Restart,
    Shutdown,
    DependencyLost { id: &'static str, policy: LossPolicy },
    DependencyRestored { id: &'static str },
}

/// Supervision metadata for a service (legacy compatibility struct).
#[derive(Clone)]
pub struct ServiceMeta {
    pub id: &'static str,
    pub display_name: &'static str,
    pub critical: bool,
    pub max_retries: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    pub shutdown_timeout: Duration,
    pub multi_threaded: bool,
}

/// Prerequisites that must be satisfied before a service starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceDependency {
    /// Wait for database worker to be ready (`LanforgeContext::is_db_ready()`).
    Database,
    /// Wait for network interface discovery to complete (`LanforgeContext::is_if_ready()`).
    Interfaces,
    /// Wait for `PPPoE` WAN connection to be up (`LanforgeContext::is_pppoe_ready()`).
    PppoeWan,
    /// Wait for a specific service by ID to be online (`LanforgeContext::get_service_state(id) == ServiceState::Online`).
    Service(&'static str),
}

/// Core trait defining a service within the Lanforge system.
pub trait LanforgeService: Send + Sync {
    /// Returns the declarative specification for this service.
    fn spec(&self) -> ServiceSpec {
        let meta = self.meta();
        ServiceSpec {
            id: meta.id,
            display_name: meta.display_name,
            runtime: if meta.multi_threaded {
                RuntimeClass::Dedicated {
                    multi_thread: true,
                    worker_threads: None,
                }
            } else {
                RuntimeClass::Shared
            },
            restart: RestartPolicy {
                base_backoff: meta.base_backoff,
                max_backoff: meta.max_backoff,
                max_retries: meta.max_retries,
                healthy_uptime: Duration::from_secs(if meta.id == "pppoe" { 60 } else { 30 }),
            },
            shutdown_timeout: meta.shutdown_timeout,
            deps: &[],
            condition: Condition::ALWAYS,
        }
    }

    /// Returns the service's supervision metadata.
    fn meta(&self) -> ServiceMeta {
        let s = self.spec();
        ServiceMeta {
            id: s.id,
            display_name: s.display_name,
            critical: false,
            max_retries: s.restart.max_retries,
            base_backoff: s.restart.base_backoff,
            max_backoff: s.restart.max_backoff,
            shutdown_timeout: s.shutdown_timeout,
            multi_threaded: matches!(
                s.runtime,
                RuntimeClass::Dedicated {
                    multi_thread: true,
                    ..
                }
            ),
        }
    }

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
    /// Declares service prerequisites (legacy).
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[]
    }

    /// Returns service-specific key-value statistics and metrics for the status banner.
    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(Cow<'static, str>, String)> {
        Vec::new()
    }

    /// Generates the complete service status banner containing health, uptime, and metrics.
    fn banner(&self, ctx: &LanforgeContext) -> ServiceBanner {
        let spec = self.spec();
        ServiceBanner {
            id: spec.id.to_string(),
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
    id: &'static str,
    ctx: LanforgeContext,
    signaled: Arc<AtomicBool>,
    restart_requested: Arc<AtomicBool>,
    cmd_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<ServiceCommand>>>,
    _keepalive_tx: Option<tokio::sync::mpsc::Sender<ServiceCommand>>,
}

impl ServiceHandle {
    /// Creates a new service handle with an event bus command bridge (for tests/compat).
    #[must_use]
    pub fn new(id: &'static str, ctx: LanforgeContext) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let mut bus_sub = ctx.bus().subscribe_system();
        let target_id = id.to_string();
        let cmd_tx = tx.clone();
        tokio::spawn(async move {
            while let Ok(timed) = bus_sub.recv().await {
                match &timed.event {
                    lanforge_types::events::LanforgeEvent::System(
                        lanforge_types::events::SystemEvent::Shutdown,
                    ) => {
                        let _ = cmd_tx.send(ServiceCommand::Shutdown).await;
                        break;
                    }
                    lanforge_types::events::LanforgeEvent::System(
                        lanforge_types::events::SystemEvent::ServiceControl { id, action },
                    ) if id == &target_id => {
                        let cmd = match action {
                            lanforge_types::system::ServiceAction::Start => ServiceCommand::Start,
                            lanforge_types::system::ServiceAction::Stop => ServiceCommand::Stop,
                            lanforge_types::system::ServiceAction::Restart => {
                                ServiceCommand::Restart
                            }
                        };
                        let _ = cmd_tx.send(cmd).await;
                    }
                    _ => {}
                }
            }
        });
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
        id: &'static str,
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
    pub const fn id(&self) -> &'static str {
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
                    name: self.id.to_string(),
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
                    name: self.id.to_string(),
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
                    name: self.id.to_string(),
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
