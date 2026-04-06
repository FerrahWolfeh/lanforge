//! `state` — Re-exports of consolidated state types.
//!
//! Note: `DeviceTable` has been replaced by `crate::context::state::State`.
//! Logic previously in `expiry.rs` and `update.rs` has been moved to `crate::context::state`.

pub use crate::context::state::{
    DeviceUpdate, FieldUpdate, InterfaceState, LeaseTarget, State, StaticEntry,
};

#[cfg(test)]
pub mod tests;
