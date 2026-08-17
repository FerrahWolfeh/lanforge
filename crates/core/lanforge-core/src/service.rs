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
//! 1. **Initialization**: Service declares its [`ServiceMeta`]
//! 2. **Execution**: `run()` method is called by the service registry
//! 3. **Supervision**: Failures trigger exponential backoff restarts
//! 4. **Shutdown**: `on_shutdown()` is called for cleanup
//!
//! # Example
//!
//! ```rust
//! use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta, ServiceControl};
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
//!             stack_kb: 0,
//!             multi_threaded: false,
//!         }
//!     }
//! }
//!
//! impl AsyncService for MyService {
//!     async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
//!         ctrl.signal_ready();
//!         // Service main loop
//!         Ok(())
//!     }
//! }
//! ```

use crate::bus::{LanforgeEvent, SystemEvent};
use crate::error::CoreError;
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
///     stack_kb: 0,
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

    /// **DEPRECATED**: Stack size for the service's dedicated OS thread, in KiB.
    /// This is no longer used since all services are now async.
    pub stack_kb: usize,

    /// If true, the service's dedicated thread uses a multi-threaded Tokio runtime
    /// instead of the default single-threaded one. This allows `tokio::spawn` calls
    /// within the service to run across multiple worker threads.
    pub multi_threaded: bool,
}

/// Core trait defining a service within the Lanforge system.
///
/// A service is a component that provides identity and responds to
/// external signals from the global event bus.
///
/// # Implementing
///
/// All services must:
/// 1. Implement [`meta()`](LanforgeService::meta) to declare supervision config
/// 2. Optionally override [`describe()`](LanforgeService::describe) for logging
/// 3. Optionally override [`on_shutdown()`](LanforgeService::on_shutdown) for cleanup
/// 4. Implement [`AsyncService`] for execution
///
/// # Thread Safety
///
/// Services must be `Send + Sync` as they may be accessed from multiple threads.
pub trait LanforgeService: Send + Sync {
    /// Returns the service's supervision metadata.
    fn meta(&self) -> ServiceMeta;

    /// Returns a one-line description of this service instance for logging.
    /// Override to include service-specific configuration details.
    fn describe(&self) -> String {
        self.meta().display_name.to_string()
    }

    /// Called when the service is stopping or the daemon is terminating.
    ///
    /// # Synchronous in-memory cleanup only
    ///
    /// This method is strictly for instantaneous in-memory cleanup, logging,
    /// or dropping local resources. **Do NOT perform blocking or async I/O here**
    /// (such as network calls, disk writes, or database flushes).
    ///
    /// Any asynchronous or I/O-bound cleanup (such as sending `PPPoE` PADT packets,
    /// flushing database batches, or draining network sockets) **MUST** be performed
    /// cooperatively inside the [`AsyncService::run`] loop upon observing
    /// [`SystemEvent::Shutdown`](crate::bus::SystemEvent::Shutdown) or `!ctx.is_running()`.
    /// The supervisor guarantees that [`AsyncService::run`] will be polled cooperatively
    /// with a safety timeout ([`ServiceMeta::shutdown_timeout`]) before the service is terminated.
    ///
    /// # Errors
    /// Returns `CoreError` if the shutdown procedure fails.
    fn on_shutdown(&mut self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// A service that executes within a Tokio asynchronous task.
///
/// This trait desugars the `run` method to ensure the resulting Future is `Send`,
/// which is required for spawning the service in a multi-threaded Tokio runtime.
///
/// # Guidelines
///
/// Services implementing this trait should:
/// 1. Use the [`LanforgeContext`] to access the [`EventBus`](crate::bus::EventBus) and global state
/// 2. Listen for the `LanforgeEvent::System(SystemEvent::Shutdown)` signal on the bus to exit `run`
/// 3. Prefer native async I/O (`tokio::net`) over synchronous blocking calls
/// 4. Handle errors gracefully — unrecoverable errors should return `Err(CoreError)`
///
/// # Example
///
/// ```rust
/// use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta, ServiceControl};
/// use lanforge_core::context::LanforgeContext;
/// use lanforge_core::error::CoreError;
/// use lanforge_core::bus::{LanforgeEvent, SystemEvent};
/// use std::time::Duration;
///
/// struct MyAsyncService {
///     ctx: LanforgeContext,
/// }
///
/// impl LanforgeService for MyAsyncService {
///     fn meta(&self) -> ServiceMeta {
///         ServiceMeta {
///             id: "my-async",
///             display_name: "My Async Service",
///             critical: false,
///             max_retries: 5,
///             base_backoff: Duration::from_secs(1),
///             max_backoff: Duration::from_secs(10),
///             shutdown_timeout: Duration::from_secs(3),
///             stack_kb: 0,
///             multi_threaded: false,
///         }
///     }
/// }
///
/// impl AsyncService for MyAsyncService {
///     async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
///         ctrl.signal_ready();
///         let mut rx = self.ctx.bus().subscribe();
///         loop {
///             match rx.recv().await {
///                 Ok(timed) => {
///                     if matches!(timed.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
///                         break;
///                     }
///                     // Handle events...
///                 }
///                 Err(_) => break, // Bus closed
///             }
///         }
///         Ok(())
///     }
/// }
/// ```
pub trait AsyncService: LanforgeService {
    /// Runs the service's main loop asynchronously.
    ///
    /// # Errors
    /// Returns `CoreError` if the service execution fails and cannot be recovered.
    fn run(&mut self, ctrl: ServiceControl) -> impl Future<Output = Result<(), CoreError>> + Send;
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
    fn banner(&self) -> ServiceBanner;
}
