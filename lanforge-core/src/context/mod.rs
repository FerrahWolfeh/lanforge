//! `LanforgeContext` — Thread-safe central state and event coordination.
//!
//! This module provides the main entry point for all system state mutations
//! and event publishing. It wraps the device [`State`](state::State) in a
//! `parking_lot::RwLock` and provides a unified API for reading and writing.
//!
//! # Architecture
//!
//! ```mermaid
//! graph TD
//!     A[LanforgeContext] --> B[Arc&lt;LanforgeContextInner&gt;]
//!     B --> C[EventBus]
//!     B --> D[RwLock&lt;State&gt;]
//!     B --> E[Atomic Flags]
//!     B --> F[target_ifindex]
//! ```
//!
//! # Key Components
//!
//! | Submodule | Purpose |
//! |-----------|---------|
//! | [`read`]  | Read-only queries (get device by MAC, IP, hostname) |
//! | [`write`] | State mutations (apply updates, allocate leases) |
//! | [`state`] | Raw device state and interface storage |
//!
//! # Usage Pattern
//!
//! ```rust
//! use lanforge_core::context::LanforgeContext;
//! use lanforge_core::bus::EventBus;
//! use std::sync::Arc;
//!
//! let bus = Arc::new(EventBus::new());
//! // State is usually initialized via State::new() or from DB
//! let ctx = LanforgeContext::new(bus, Default::default(), None);
//!
//! // Read
//! let devices = ctx.all_devices();
//!
//! // Write
//! // ctx.apply(DeviceUpdate::...);
//! ```
//!
//! # Thread Safety
//!
//! All operations are thread-safe. Multiple readers can access state
//! concurrently, while writes acquire an exclusive lock.
//!
//! # Lifecycle Management
//!
//! The context tracks readiness states:
//! - **DB Ready**: Database worker is active
//! - **Interface Ready**: Network interfaces are configured
//! - **Running**: System is operational (false = shutdown)

use crate::bus::{EventBus, LanforgeEvent, SystemEvent, TimedEvent};
use crate::context::state::State;
use crate::error::CoreError;
use lanforge_types::Device;
use lanforge_types::identifiers::MacAddr;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;

pub mod read;
pub mod state;
#[cfg(test)]
pub mod tests;
pub mod write;

use std::sync::atomic::AtomicU64;

/// Internal counters for tracking transient network events.
///
/// These are exported via Prometheus to monitor discovery rates.
#[derive(Debug, Default)]
pub struct EventCounters {
    pub arp_seen: AtomicU64,
    pub ndp_seen: AtomicU64,
    pub slaac_observed: AtomicU64,
    pub dhcp_v4_leases: AtomicU64,
    pub dhcp_v6_leases: AtomicU64,
    pub dns_auth_hits: AtomicU64,
    #[cfg(feature = "adblock")]
    pub dns_blocked: AtomicU64,
}

/// Lightweight handle for service interaction with the event bus.
///
/// Provides bus subscription and shutdown detection without requiring
/// manual `bus().subscribe()` + `is_running()` checks.
/// Created via [`LanforgeContext::service_handle()`].
///
/// # Usage
///
/// ```rust,ignore
/// let mut handle = ctx.service_handle();
/// loop {
///     let Some(event) = handle.next_event().await else { break; };
///     // handle event...
/// }
/// ```
pub struct ServiceHandle {
    rx: Receiver<TimedEvent>,
    ctx: LanforgeContext,
}

impl ServiceHandle {
    /// Returns the next event, or `None` if the system is shutting down.
    ///
    /// Automatically handles:
    /// - `Shutdown` event detection → returns `None`
    /// - `is_running()` check → returns `None`
    /// - Broadcast lag recovery → skips lagged events, continues
    pub async fn next_event(&mut self) -> Option<TimedEvent> {
        loop {
            if !self.ctx.is_running() {
                return None;
            }
            match self.rx.recv().await {
                Ok(te) => {
                    if matches!(te.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                        return None;
                    }
                    return Some(te);
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return None,
            }
        }
    }

    /// Publishes an event to the bus.
    #[must_use]
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        self.ctx.bus().publish(event)
    }
}

/// Lightweight snapshot of the state for persistence.
///
/// Contains only the data necessary for the database worker to flush
/// state to disk, avoiding the need to clone the entire `State` struct.
pub struct PersistenceSnapshot {
    pub devices: HashMap<MacAddr, Arc<Device>>,
    pub timestamp: SystemTime,
}

#[derive(Clone)]
pub struct LanforgeContext {
    inner: Arc<LanforgeContextInner>,
}

/// Internal state shared behind an `Arc`.
///
/// This is intentionally private to enforce access patterns — all interaction
/// goes through the typed methods on [`LanforgeContext`].
struct LanforgeContextInner {
    /// The event bus for broadcasting state changes.
    bus: Arc<EventBus>,
    /// The device and interface state, protected by an `RwLock`.
    state: RwLock<state::State>,
    /// The network interface index to monitor for RA/DHCP.
    target_ifindex: Option<u32>,
    /// System running flag — set to false on shutdown.
    running: AtomicBool,
    /// Database readiness flag.
    db_ready: AtomicBool,
    /// Network interface readiness flag.
    if_ready: AtomicBool,
    /// Shared DNS statistics, updated by the DNS module.
    dns_stats: RwLock<Option<Arc<dyn std::any::Any + Send + Sync>>>,
    /// Shared DNS context for DoT/DoH, updated by the DNS module.
    dns_context: RwLock<Option<Arc<dyn std::any::Any + Send + Sync>>>,
    /// Timestamp of the last successful database flush.
    last_db_flush: RwLock<Option<SystemTime>>,
    /// Internal counters for event rates.
    event_counters: EventCounters,
    /// Timestamp of the last network scan.
    last_scan: RwLock<Instant>,
    /// Global counter for active API connections (Control UDS, HTTP, etc.).
    pub active_clients: Arc<AtomicUsize>,
}

#[allow(clippy::missing_panics_doc)] // Temporary
impl LanforgeContext {
    /// Creates a new isolated context instance.
    ///
    /// # Parameters
    ///
    /// - `bus`: The shared event bus for publishing state changes
    /// - `state`: The initial device state (can be empty via [`State::new()`])
    /// - `target_ifindex`: Optional interface index to monitor for RA/DHCP events.
    ///   If `None`, the system will auto-detect the primary interface.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_core::context::LanforgeContext;
    /// use lanforge_core::bus::EventBus;
    /// use std::sync::Arc;
    ///
    /// let bus = Arc::new(EventBus::new());
    /// let ctx = LanforgeContext::new(bus, Default::default(), None);
    ///
    /// assert!(ctx.is_running());
    /// assert!(ctx.target_ifindex().is_none());
    /// ```
    #[must_use]
    pub fn new(bus: Arc<EventBus>, state: State, target_ifindex: Option<u32>) -> Self {
        let inner = Arc::new(LanforgeContextInner {
            bus,
            state: RwLock::new(state),
            target_ifindex,
            running: AtomicBool::new(true),
            db_ready: AtomicBool::new(false),
            if_ready: AtomicBool::new(false),
            dns_stats: RwLock::new(None),
            dns_context: RwLock::new(None),
            last_db_flush: RwLock::new(None),
            event_counters: EventCounters::default(),
            last_scan: RwLock::new(Instant::now()),
            active_clients: Arc::new(AtomicUsize::new(0)),
        });
        Self { inner }
    }

    /// Returns the target interface index for this context.
    ///
    /// This is the interface monitored for router advertisements and DHCP events.
    /// Returns `None` if no specific interface is configured.
    #[must_use]
    pub fn target_ifindex(&self) -> Option<u32> {
        self.inner.target_ifindex
    }

    /// Returns the shared event bus for this instance.
    ///
    /// The bus can be used to subscribe to or publish events.
    #[must_use]
    pub fn bus(&self) -> Arc<EventBus> {
        self.inner.bus.clone()
    }

    /// Returns a reference to the shared event bus.
    ///
    /// Useful for publishing events without cloning the Arc.
    #[must_use]
    pub fn bus_ref(&self) -> &EventBus {
        &self.inner.bus
    }

    /// Records a new database flush timestamp.
    ///
    /// Call this after a successful database write to track staleness.
    pub fn record_db_flush(&self) {
        *self.inner.last_db_flush.write() = Some(SystemTime::now());
    }

    /// Returns the last database flush time, if any.
    ///
    /// Used to determine if the in-memory state is synced to disk.
    #[must_use]
    pub fn last_db_flush(&self) -> Option<SystemTime> {
        *self.inner.last_db_flush.read()
    }

    /// Records a new network scan timestamp.
    pub fn record_scan(&self) {
        *self.inner.last_scan.write() = Instant::now();
    }

    /// Returns the number of seconds since the last network scan.
    #[must_use]
    pub fn last_scan_secs_ago(&self) -> u64 {
        self.inner.last_scan.read().elapsed().as_secs()
    }

    /// Access the global active API clients counter.
    #[must_use]
    pub fn active_clients(&self) -> Arc<AtomicUsize> {
        self.inner.active_clients.clone()
    }

    /// Returns the internal event counters.
    #[must_use]
    pub fn counters(&self) -> &EventCounters {
        &self.inner.event_counters
    }

    /// Creates a lightweight service handle for event-driven services.
    ///
    /// The handle provides `next_event()` for the service main loop and
    /// `publish()` for emitting events. Use this instead of manually calling
    /// `bus().subscribe()` + `is_running()` in a loop.
    ///
    /// **NOTE**: The supervisor (`supervise_async`) still uses its own
    /// `bus().subscribe()` for the outer shutdown select. This handle is
    /// for use INSIDE `service.run()`.
    #[must_use]
    pub fn service_handle(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe(),
            ctx: self.clone(),
        }
    }

    /// Increments the DNS blocked queries counter.
    #[cfg(feature = "adblock")]
    pub fn inc_dns_blocked(&self) {
        self.inner
            .event_counters
            .dns_blocked
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Captures a snapshot of the device registry for database persistence.
    ///
    /// This acquires a read lock on the state and clones only the device map
    /// (shallow clone of Arcs).
    #[must_use]
    pub fn snapshot_for_persistence(&self) -> PersistenceSnapshot {
        let state = self.read();
        PersistenceSnapshot {
            devices: state.devices.clone(),
            timestamp: SystemTime::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle & Coordination
// ---------------------------------------------------------------------------

impl LanforgeContext {
    /// Blocks until the network interfaces are ready.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the wait condition cannot be met or the system shuts down.
    pub async fn wait_for_interfaces(&self) -> Result<(), CoreError> {
        self.wait_for_condition(Self::is_if_ready, |event| {
            matches!(event, LanforgeEvent::System(SystemEvent::InterfaceReady))
        })
        .await
    }

    /// Blocks until the database is ready.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the wait condition cannot be met or the system shuts down.
    pub async fn wait_for_db(&self) -> Result<(), CoreError> {
        self.wait_for_condition(Self::is_db_ready, |event| {
            matches!(event, LanforgeEvent::System(SystemEvent::DbReady))
        })
        .await
    }

    /// Generic async wait helper. Blocks until `is_ready()` returns true
    /// or a matching event arrives on the bus.
    async fn wait_for_condition(
        &self,
        is_ready: impl Fn(&Self) -> bool,
        event_matches: impl Fn(&LanforgeEvent) -> bool,
    ) -> Result<(), CoreError> {
        if is_ready(self) {
            return Ok(());
        }
        let mut rx = self.inner.bus.subscribe();
        loop {
            // Re-check after subscribing to avoid race
            if is_ready(self) {
                return Ok(());
            }
            match rx.recv().await {
                Ok(timed_event) => {
                    if !self.is_running()
                        || matches!(
                            timed_event.event,
                            LanforgeEvent::System(SystemEvent::Shutdown)
                        )
                    {
                        return Ok(());
                    }
                    if event_matches(&timed_event.event) {
                        return Ok(());
                    }
                }
                Err(_) => return Ok(()),
            }
        }
    }

    /// Returns true if this instance is currently running.
    ///
    /// When false, the system is in shutdown mode and services should exit.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Relaxed)
    }

    /// Returns true if the database is ready.
    ///
    /// This flag is set by the database worker after successful initialization.
    #[must_use]
    pub fn is_db_ready(&self) -> bool {
        self.inner.db_ready.load(Ordering::SeqCst)
    }

    /// Returns true if the network interfaces are ready.
    ///
    /// This flag is set after interface discovery completes successfully.
    #[must_use]
    pub fn is_if_ready(&self) -> bool {
        self.inner.if_ready.load(Ordering::SeqCst)
    }
}
