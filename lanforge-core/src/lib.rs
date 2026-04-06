//! # Lanforge Core
//!
//! `lanforge-core` is the central logic engine for the Lanforge daemon. It manages
//! the global state of discovered network devices, handles addressing identifiers
//! (MACs, DUIDs), and provides a thread-safe event bus for internal communication.
//!
//! ## Key Components
//!
//! - **[`bus`]**: A multi-producer, multi-consumer event bus ([`EventBus`](bus::EventBus)).
//! - **[`context`]**: The central thread-safe singleton ([`LanforgeContext`](context::LanforgeContext)) that manages state and events.
//! - **[`device`]**: Datastructures representing network devices and their state (IPv4/v6 leases, SLAAC).
//! - **[`identifiers`]**: Strong types for network addresses like MACs and DHCP DUIDs.
//! - **[`state`]**: The main `DeviceTable` implementation and complex update/expiry logic.
//! - **[`ndp`]**: Kernel-level neighbor discovery event mapping.
//!
//! ## Architectural Pattern
//!
//! The system follows a **reagent** model where protocol tasks (DHCP, RA, DNS)
//! submit [`DeviceUpdate`](state::update::DeviceUpdate) requests to the [`LanforgeContext`](context::LanforgeContext).
//! The context applies the logic and broadcasts [`LanforgeEvent`](bus::LanforgeEvent)s
//! back to any interested listeners.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
pub mod bus;
pub mod context;
pub mod device;
pub mod error;
pub mod identifiers;
pub mod ndp;
pub mod service;
pub mod state;
pub mod utils;
pub mod vendor;
