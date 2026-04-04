//! `GlobalContext` — Thread-safe singleton for system-wide state.
//!
//! This module provides a global access point for the [`ManagedTable`] and
//! [`EventBus`]. It is intended to reduce "constructor drilling" while
//! maintaining thread safety.

use crate::bus::{EventBus, ManagedTable};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// The global container for Lanforge's shared services.
pub struct LanforgeContext {
    bus: Arc<EventBus>,
    table: Arc<ManagedTable>,
}

static INSTANCE: OnceLock<LanforgeContext> = OnceLock::new();
static RUNNING: AtomicBool = AtomicBool::new(true);
static DB_READY: AtomicBool = AtomicBool::new(false);
static IF_READY: AtomicBool = AtomicBool::new(false);

impl LanforgeContext {
    /// Initializes the global context. MUST be called exactly once during system startup.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn init(bus: Arc<EventBus>, table: Arc<ManagedTable>) {
        let context = Self { bus, table };
        assert!(
            INSTANCE.set(context).is_ok(),
            "LanforgeContext::init called more than once!"
        );
    }

    /// Returns the global event bus.
    ///
    /// # Panics
    ///
    /// Panics if the context has not been initialized.
    #[must_use]
    pub fn bus() -> Arc<EventBus> {
        INSTANCE
            .get()
            .expect("LanforgeContext not initialized")
            .bus
            .clone()
    }

    /// Returns the global managed device table.
    ///
    /// # Panics
    ///
    /// Panics if the context has not been initialized.
    #[must_use]
    pub fn table() -> Arc<ManagedTable> {
        INSTANCE
            .get()
            .expect("LanforgeContext not initialized")
            .table
            .clone()
    }

    /// Sets the system lifecycle to shutdown mode.
    pub fn terminate() {
        RUNNING.store(false, Ordering::SeqCst);
    }

    /// Returns true if the system is currently running and hasn't been terminated.
    #[must_use]
    pub fn is_running() -> bool {
        RUNNING.load(Ordering::SeqCst)
    }

    /// Sets the database readiness state.
    pub fn set_db_ready(ready: bool) {
        DB_READY.store(ready, Ordering::SeqCst);
    }

    /// Returns true if the database is ready.
    #[must_use]
    pub fn is_db_ready() -> bool {
        DB_READY.load(Ordering::SeqCst)
    }

    /// Sets the interface readiness state.
    pub fn set_if_ready(ready: bool) {
        IF_READY.store(ready, Ordering::SeqCst);
    }

    /// Returns true if the network interfaces are ready.
    #[must_use]
    pub fn is_if_ready() -> bool {
        IF_READY.load(Ordering::SeqCst)
    }

    /// Blocks the current task until the database is ready.
    /// Safely handles the race condition where the event is published before subscription.
    ///
    /// # Errors
    ///
    /// Returns a `CoreError` if the underlying communication bus fails.
    pub async fn wait_for_db() -> crate::error::Result<()> {
        let bus = Self::bus();
        let mut rx = bus.subscribe();
        if Self::is_db_ready() {
            return Ok(());
        }

        while let Ok(event) = rx.recv().await {
            if !Self::is_running() || matches!(event, crate::bus::LanforgeEvent::Shutdown) {
                return Ok(());
            }
            if matches!(event, crate::bus::LanforgeEvent::DbReady) {
                break;
            }
        }
        Ok(())
    }

    /// Blocks the current task until the network interfaces are ready.
    ///
    /// # Errors
    ///
    /// Returns a `CoreError` if the underlying communication bus fails.
    pub async fn wait_for_interfaces() -> crate::error::Result<()> {
        let bus = Self::bus();
        let mut rx = bus.subscribe();
        if Self::is_if_ready() {
            return Ok(());
        }

        while let Ok(event) = rx.recv().await {
            if !Self::is_running() || matches!(event, crate::bus::LanforgeEvent::Shutdown) {
                return Ok(());
            }
            if matches!(event, crate::bus::LanforgeEvent::InterfaceReady) {
                break;
            }
        }
        Ok(())
    }

    /// Blocks the current THREAD (sync) until dependencies are ready.
    pub fn wait_for_db_sync(rx: &std::sync::mpsc::Receiver<crate::bus::LanforgeEvent>) {
        if Self::is_db_ready() {
            return;
        }
        while let Ok(event) = rx.recv() {
            if matches!(event, crate::bus::LanforgeEvent::DbReady) {
                break;
            }
            if matches!(event, crate::bus::LanforgeEvent::Shutdown) || !Self::is_running() {
                break;
            }
        }
    }

    pub fn wait_for_interfaces_sync(rx: &std::sync::mpsc::Receiver<crate::bus::LanforgeEvent>) {
        if Self::is_if_ready() {
            return;
        }
        while let Ok(event) = rx.recv() {
            if matches!(event, crate::bus::LanforgeEvent::InterfaceReady) {
                break;
            }
            if matches!(event, crate::bus::LanforgeEvent::Shutdown) || !Self::is_running() {
                break;
            }
        }
    }
}
