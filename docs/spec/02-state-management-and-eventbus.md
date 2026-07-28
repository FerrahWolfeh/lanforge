# Specification 02: State Management & EventBus (`lanforge-core`)

## 1. Overview & Architectural Position

`lanforge-core` is the **Level 1 (L1)** core orchestration crate of Lanforge. Often referred to as the "brain" of the daemon, it owns global state transitions, context propagation, event routing, and background service lifecycle primitives.

```
       +-------------------------------------------------------+
       |   Services & Interfaces (DHCP, RA, DNS, CLI, HTTP)    |
       +-------------------------------------------------------+
                |                                    |
                | ctx.apply(DeviceUpdate)            | ctx.bus().subscribe()
                v                                    v
       +-------------------------------------------------------+
       |                lanforge-core (L1 Crate)               |
       |  - LanforgeContext (Central engine handle)            |
       |  - State Management (Copy-on-Write / parking_lot)     |
       |  - EventBus (tokio::sync::broadcast)                  |
       |  - Service Models & Readiness Signaling               |
       +-------------------------------------------------------+
                                   |
                                   v (Depends on)
       +-------------------------------------------------------+
       |             lanforge-types (L0 Crate)                 |
       +-------------------------------------------------------+
```

---

## 2. Global Context (`LanforgeContext`)

The `LanforgeContext` (`crates/core/lanforge-core/src/context/mod.rs`) is the thread-safe, Arc-wrapped handle passed to every service, handler, and background task.

### Responsibilities
- **State Handle Access:** Provides read handles (`ctx.state()`) and update submission (`ctx.apply(update)`).
- **Event Bus Access:** Exposes `ctx.bus()` for publishing and subscribing to `LanforgeEvent`s.
- **Capabilities & Config:** Supplies daemon configuration and feature capability descriptors.
- **Service Handles:** Exposes internal handles (e.g., DNS resolver handles).

---

## 3. Copy-on-Write State Management

To maintain high throughput across many concurrently running network services without lock contention, Lanforge implements a **Copy-on-Write (CoW)** state strategy (`crates/core/lanforge-core/src/context/state/`).

### How State Updates Work
1. Services do **NOT** mutate global state directly.
2. When a service discovers a device or grants a lease, it creates a `DeviceUpdate` delta (e.g., `DeviceUpdate::Discovered`, `DeviceUpdate::IpAssigned`).
3. The service calls `ctx.apply(update)`.
4. The internal state container acquires a `parking_lot::RwLock` write lock briefly, uses `Arc::make_mut` to clone the state only when shared references exist, applies the delta, and drops the write lock.
5. Corresponding `LanforgeEvent::Device` events are broadcast to notify interested services (such as persistent storage or DNS).

---

## 4. Event Bus (`EventBus`)

The `EventBus` (`crates/core/lanforge-core/src/bus/mod.rs`) provides inter-service pub/sub messaging backed by `tokio::sync::broadcast`.

### Design Characteristics
- **Non-blocking Broadcast:** `bus.publish(event)` sends events to all active subscribers.
- **Async Subscribers:** Services obtain a `tokio::sync::broadcast::Receiver` via `bus.subscribe()`.
- **Fast Event Routing:** Listeners must perform minimal inline work. If processing an event requires I/O (e.g., writing to disk), the receiver task spawns an asynchronous worker or pushes to a background channel.

---

## 5. Service Traits & Lifecycle Control (`service.rs`)

Lanforge standardizes background workers (DHCP server, RA daemon, TFTP server, DNS resolver, WOL agent) using unified service traits defined in `crates/core/lanforge-core/src/service.rs`.

### Service Types
- **`AsyncService`**: Trait for asynchronous background tasks. Implements `async fn run(&self, ctx: LanforgeContext, ctrl: ServiceControl) -> Result<(), ServiceError>`.
- **`SyncService`**: Trait for synchronous/blocking background workers running on dedicated threads.

### Service Lifecycle & Readiness (`ServiceControl`)
- **Ready Signal:** Services receive a `ServiceControl` handle. Once a service successfully binds its sockets/ports (e.g., UDP 67 for DHCP), it **MUST** invoke `ctrl.signal_ready()`.
- **Supervisor Integration:** The supervisor monitors service readiness and status (`ServiceStatus::Starting`, `ServiceStatus::Running`, `ServiceStatus::Stopped`, `ServiceStatus::Failed`), handling retries and exponential backoff.

---

## 6. System Invariants & Execution Guarantees

1. **Strict Copy-on-Write Memory Safety:** Global state updates utilize atomic CoW swaps. Readers never block writers, and writers only lock during pointer updates or delta applications.
2. **Asynchronous Non-Blocking Event Propagation:** The `EventBus` operates via broadcast channels. Fast path network tasks broadcast events without awaiting subscriber processing, preventing slow background tasks (e.g. disk persistence) from degrading network response times.
3. **Deterministic Readiness Control:** A network service is not considered operational by the daemon supervisor until `ctrl.signal_ready()` is called following successful socket/port binding.
