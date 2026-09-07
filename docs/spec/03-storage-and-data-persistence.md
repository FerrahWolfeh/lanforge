# Specification 03: Storage & Data Persistence (`crates/db`)

## 1. Overview & Embedded Storage Architecture

Lanforge supports long-term data persistence for device tracking, IP lease history, audit logs, and network events. The persistence system is located under `crates/db/` and is built around `redb`, a pure-Rust embedded ACID key-value store, with support for volatile RAM/tmpfs operation.

```
       +-------------------------------------------------------+
       |                  Lanforge EventBus                    |
       +-------------------------------------------------------+
                                   |
                                   | (Subscribes to LanforgeEvent)
                                   v
       +-------------------------------------------------------+
       |             lanforge-db (DbWorker Service)            |
       |  - Listens for Device/Dhcp/Pppoe events               |
       |  - Batches and dispatches async DB writes             |
       +-------------------------------------------------------+
                                   |
                                   v (Uses trait interfaces)
       +-------------------------------------------------------+
       |               lanforge-db-core (Traits)               |
       |  - Store traits (DeviceStore, DhcpConfigStore, etc.)  |
       |  - LogStore trait                                     |
       +-------------------------------------------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |                   lanforge-db-redb                    |
       |  - Pure-Rust embedded redb backend                    |
       |  - Implements DatabaseStore & LogStore                |
       +-------------------------------------------------------+
                   /                               \
                  /                                 \
                 v                                   v
   +---------------------------+       +---------------------------+
   |   config.redb             |       |   runtime.redb            |
   |   - Persistent Flash/Disk |       |   - Volatile tmpfs (/run) |
   |   - Configs, Devices, Auth|       |   - Leases, Logs, DNS     |
   +---------------------------+       +---------------------------+
```

---

## 2. Crate Responsibilities

### `lanforge-db-core` (`crates/db/lanforge-db-core/`)
- **Store Traits:** Trait bounds defining persistence methods for devices, leases, static mappings, and system settings (`DeviceStore`, `DhcpConfigStore`, `DnsStore`, `UserStore`, etc.).
- **`LogStore` Trait:** Defines interfaces for querying, pruning, and recording high-frequency audit and DNS query logs.
- **Data Models & Schema Trait Bounds:** Ensures engine implementations consume domain types from `lanforge-types`.

### `lanforge-db-redb` (`crates/db/lanforge-db-redb/`)
- **Embedded Engine:** Implements all core store traits and `LogStore` backed by pure-Rust `redb::Database`. Supports both zero-overhead persistent flash storage (`config.redb`) and volatile tmpfs storage (`runtime.redb`).

### `lanforge-db` (`crates/db/lanforge-db/`)
- **`LanforgeDb` Facade:** Wraps `lanforge-db-redb` for persistent configuration and device state.
- **`LogDb` Facade:** Wraps `lanforge-db-redb` for high-frequency volatile telemetry and audit trails.
- **`DbWorker` Service:** Implements `AsyncService` to run as a supervised background task. It listens for `LanforgeEvent`s published to the `EventBus` and asynchronously writes state mutations to disk.

---

## 3. Event-Driven Persistence Pipeline

To prevent disk I/O latency from slowing down real-time network services (such as DHCP or RA packet handlers), database writes are completely decoupled from network packet loops.

1. **Packet Event:** A service (e.g., `lanforge-dhcp`) processes a packet, assigns an IP, and publishes `LanforgeEvent::Dhcp(DhcpEvent::LeaseGranted)`.
2. **Event Dispatch:** The `EventBus` broadcasts the event across `tokio::sync::broadcast`.
3. **Async DB Ingestion:** `DbWorker` receives the event via its subscription, batches changes over a 5s debounce window, and writes asynchronously to `redb`.

---

## 4. Invariants & System Guarantees

1. **Non-Blocking Packet Processing:** Packet handling loops in network services never perform synchronous database operations. Database persistence occurs reactively via `DbWorker` event consumption.
2. **Crash-Consistent Storage:** `redb` enforces full ACID transactions with MVCC. If the daemon crashes unexpectedly, the state container on restart repopulates its baseline CoW memory state directly from the persistent database store.
3. **Zero External Dependencies:** No external database process or service (such as PostgreSQL) is required. The embedded file format allows portable deployment across small single-board computers, OpenWrt routers, and standard Linux servers alike.
