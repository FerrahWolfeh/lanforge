//! `state` — Re-exports of consolidated state types.
//!
//! This module re-exports the core state types from [`context::state`](crate::context::state)
//! for ergonomic access. Prefer importing from `lanforge_core::state` for public API usage.
//!
//! # Re-exported Types
//!
//! | Type                | Description                                  |
//! |---------------------|----------------------------------------------|
//! | [`State`]           | Central device and interface state storage   |
//! | [`DeviceUpdate`]    | All possible state mutation commands         |
//! | [`FieldUpdate<T>`]  | Optional change specification (`Set`/`Clear`/`NoChange`) |
//! | [`InterfaceState`]  | Network interface IP configuration           |
//! | [`LeaseTarget`]     | Identifies a specific lease type (`V4`, `V6`, `V6Prefix`) |
//! | [`StaticEntry`]     | Manual device reservation record             |
//!
//! # Migration Note
//!
//! The `DeviceTable` has been replaced by [`State`]. Logic previously in
//! `expiry.rs` and `update.rs` has been consolidated into
//! [`crate::context::state`].

pub use crate::context::state::{
    DeviceUpdate, FieldUpdate, InterfaceState, LeaseTarget, State, StaticEntry,
};

#[cfg(test)]
pub mod jit_tests;
#[cfg(test)]
pub mod tests;
