#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
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
//! - **[`state`]**: The main `State` implementation and complex update/expiry logic.
//! - **[`ndp`]**: Kernel-level neighbor discovery event mapping.
//! - **[`service`]**: Service supervision traits for async/sync task execution.
//!
//! ## Architectural Pattern
//!
//! The system follows a **reactor** model where protocol tasks (DHCP, RA, DNS)
//! submit [`DeviceUpdate`](state::DeviceUpdate) requests to the [`LanforgeContext`](context::LanforgeContext).
//! The context applies the logic and broadcasts [`LanforgeEvent`](bus::LanforgeEvent)s
//! back to any interested listeners.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant Worker as Protocol Worker (DHCP/NDP)
//!     participant Ctx as LanforgeContext
//!     participant State as Device State
//!     participant Bus as EventBus
//!     participant Handler as UI / Control Handler
//!
//!     Worker->>Ctx: apply(DeviceUpdate)
//!     Ctx->>State: apply_update()
//!     Ctx->>Bus: publish(LanforgeEvent)
//!     Bus-->>Handler: Event Received
//!     Note right of Handler: UI updates or CLI notification
//! ```
//!
//! ## Data Flow
//!
//! 1. **Discovery**: Protocol workers observe network events (DHCP leases, NDP/ARP neighbors, mDNS hints)
//! 2. **State Mutation**: Workers submit [`DeviceUpdate`](state::DeviceUpdate) via [`LanforgeContext::apply`](context::LanforgeContext::apply)
//! 3. **Event Broadcasting**: Context publishes [`LanforgeEvent`](bus::LanforgeEvent) to all subscribers
//! 4. **Persistence**: Dirty state triggers background DB flush
//!
//! ## Threading Model
//!
//! All state is protected by `parking_lot::RwLock` inside an `Arc<LanforgeContextInner>`.
//! The [`EventBus`](bus::EventBus) uses `tokio::sync::broadcast` for async event distribution.
pub mod bus;
pub mod config;
pub mod context;
pub mod error;
pub mod macros;
pub mod service;
pub mod utils;
