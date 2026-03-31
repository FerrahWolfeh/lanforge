//! `GlobalContext` — Thread-safe singleton for system-wide state.
//!
//! This module provides a global access point for the [`ManagedTable`] and
//! [`EventBus`]. It is intended to reduce "constructor drilling" while
//! maintaining thread safety.

use crate::bus::{EventBus, ManagedTable};
use std::sync::{Arc, OnceLock};

/// The global container for Lanforge's shared services.
pub struct LanforgeContext {
    bus: Arc<EventBus>,
    table: Arc<ManagedTable>,
}

static INSTANCE: OnceLock<LanforgeContext> = OnceLock::new();

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
}
