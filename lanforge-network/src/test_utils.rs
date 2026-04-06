#[cfg(test)]
use lanforge_core::bus::EventBus;
use lanforge_core::{context::LanforgeContext, state::State};
use std::sync::Arc;

/// Initializes a fresh `LanforgeContext` for unit tests.
/// This ensures that the global singleton is NOT reused and tests are isolated.
pub fn init_test_context() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    LanforgeContext::new(bus, table, None)
}
