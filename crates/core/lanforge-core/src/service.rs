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
//!     async fn serve(&mut self, _ctx: &LanforgeContext) -> Result<(), CoreError> {
//!         // Service main loop
//!         Ok(())
//!     }
//! }
//! ```

use crate::bus::{LanforgeEvent, SystemEvent};
use crate::error::CoreError;
use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Supervision metadata for a service.
///
/// Services declare this via `LanforgeService::meta()` instead of
/// the caller passing loose parameters to `supervise_async`.
///
/// # Fields
///
/// | Field              | Description                                      | Example             |
/// |--------------------|--------------------------------------------------|---------------------|
/// | `id`               | Stable identifier for readiness tracking         | "ra", "dhcpv4", "db"|
/// | `display_name`     | Human-readable name for OS thread (shows in htop)| "RA Server"         |
/// | `critical`         | If true, system exits when retries exhausted     | `true` for DB       |
/// | `max_retries`      | Max restarts before giving up (0 = unlimited)    | 3                   |
/// | `base_backoff`     | Initial backoff on failure (doubles per retry)   | 1 second            |
/// | `max_backoff`      | Maximum backoff cap                              | 30 seconds          |
/// | `shutdown_timeout` | Max grace period for async cleanup on shutdown   | 3 seconds           |
/// | `multi_threaded`   | If true, uses a multi-thread tokio runtime       | `true` for DNS      |
///
/// # Backoff Strategy
///
/// On each failure, the service waits: `min(base_backoff * 2^attempt, max_backoff)`
/// For example, with `base_backoff=1s` and `max_backoff=30s`:
/// - Attempt 0: 1s
/// - Attempt 1: 2s
/// - Attempt 2: 4s
/// - Attempt 3: 8s
/// - Attempt 4+: 16s → capped at 30s
///
/// # Example
///
/// ```rust
/// use lanforge_core::service::ServiceMeta;
/// use std::time::Duration;
///
/// let meta = ServiceMeta {
///     id: "dhcpv6",
///     display_name: "DHCPv6 Server",
///     critical: false, // Non-critical, can retry indefinitely
///     max_retries: 0,  // Unlimited
///     base_backoff: Duration::from_secs(2),
///     max_backoff: Duration::from_secs(60),
///     shutdown_timeout: Duration::from_secs(3),
///     multi_threaded: false,
/// };
/// ```
pub struct ServiceMeta {
    /// Stable identifier used for readiness tracking, logging, and
    /// `ServiceReady` events. Examples: "ra", "dhcpv4", "db", "monitor".
    pub id: &'static str,

    /// Human-readable name used for the OS thread. Shows in htop/ps.
    /// Examples: "RA Server", "`DHCPv4` Server", "DB Worker".
    pub display_name: &'static str,

    /// If true, the process exits when retries are exhausted.
    pub critical: bool,

    /// Maximum retries before giving up (0 = unlimited restarts).
    pub max_retries: u32,

    /// Base backoff duration on failure (doubles per failure).
    pub base_backoff: Duration,

    /// Maximum backoff cap.
    pub max_backoff: Duration,

    /// Maximum duration to wait for the service's async `run` loop to complete
    /// its cooperative shutdown and resource cleanup before forcibly aborting.
    pub shutdown_timeout: Duration,

    /// If true, the service's dedicated thread uses a multi-threaded Tokio runtime
    /// instead of the default single-threaded one. This allows `tokio::spawn` calls
    /// within the service to run across multiple worker threads.
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
///
/// A service is a component that provides identity and responds to
/// external signals from the global event bus.
pub trait LanforgeService: Send + Sync {
    /// Returns the service's supervision metadata.
    fn meta(&self) -> ServiceMeta;

    /// Returns a one-line description of this service instance for logging.
    /// Override to include service-specific configuration details.
    fn describe(&self) -> String {
        self.meta().display_name.to_string()
    }

    /// Called when the service is stopping or the daemon is terminating.
    /// Synchronous in-memory cleanup only. Async cleanup must be in [`AsyncService::cleanup`].
    ///
    /// # Errors
    ///
    /// Returns a [`CoreError`] if in-memory shutdown operations fail.
    fn on_shutdown(&mut self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// A service that executes within a Tokio asynchronous task.
///
/// # Lifecycle Stages
///
/// 1. **Dependencies**: Handled automatically by supervisor via [`AsyncService::dependencies`].
/// 2. **Initialization**: [`init()`](AsyncService::init) binds sockets and allocates resources.
/// 3. **Readiness**: Supervisor automatically marks service `Online` and signals `ServiceReady`.
/// 4. **Execution**: [`serve()`](AsyncService::serve) runs the main event / packet processing loop.
/// 5. **Cleanup**: [`cleanup()`](AsyncService::cleanup) performs asynchronous cooperative shutdown.
pub trait AsyncService: LanforgeService {
    /// Declares service prerequisites (e.g. Database, Interfaces, `PppoeWan`).
    /// The supervisor automatically waits for all declared dependencies before calling `init()`.
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[]
    }

    /// Returns service-specific key-value statistics and metrics for the status banner.
    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(Cow<'static, str>, String)> {
        Vec::new()
    }

    /// Generates the complete service status banner containing health, uptime, and metrics.
    fn banner(&self, ctx: &LanforgeContext) -> ServiceBanner {
        let meta = self.meta();
        ServiceBanner {
            id: meta.id.to_string(),
            name: meta.display_name.to_string(),
            state: ctx.get_service_state(meta.id),
            uptime_secs: ctx.get_service_uptime(meta.id),
            stats: self.stats(ctx),
        }
    }

    /// Resource acquisition phase (port binding, netlink sockets, cache initialization).
    /// Executed before readiness is signaled. If this fails, the supervisor applies backoff.
    fn init(
        &mut self,
        _ctx: &LanforgeContext,
    ) -> impl Future<Output = Result<(), CoreError>> + Send {
        async { Ok(()) }
    }

    /// Main execution loop. Only called after `init()` succeeds and readiness is signaled.
    fn serve(
        &mut self,
        ctx: &LanforgeContext,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    /// Cooperative async cleanup on shutdown (e.g. sending `PPPoE` PADT frame, flushing DB batch).
    fn cleanup(
        &mut self,
        _ctx: &LanforgeContext,
    ) -> impl Future<Output = Result<(), CoreError>> + Send {
        async { Ok(()) }
    }
}

use crate::context::LanforgeContext;

/// A handle provided to services to control their lifecycle and signal readiness.
#[derive(Clone)]
pub struct ServiceControl {
    id: &'static str,
    ctx: LanforgeContext,
    signaled: Arc<AtomicBool>,
}

impl ServiceControl {
    /// Creates a new service control handle.
    #[must_use]
    pub fn new(id: &'static str, ctx: LanforgeContext) -> Self {
        Self {
            id,
            ctx,
            signaled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signals that the service is now fully initialized and ready to handle traffic.
    /// This is idempotent; multiple calls will only result in one signal.
    pub fn signal_ready(&self) {
        if !self.signaled.swap(true, Ordering::SeqCst) {
            self.ctx.set_service_state(self.id, ServiceState::Online);
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::System(SystemEvent::ServiceReady {
                    name: self.id.to_string(),
                }));
        }
    }

    /// Returns the ID of the service this handle belongs to.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }
}

use lanforge_types::system::{ServiceBanner, ServiceState};

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
