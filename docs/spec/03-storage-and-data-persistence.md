# Specification 03: Storage & Data Persistence (`crates/db`)

## 1. Overview & Multi-Backend Architecture

Lanforge supports long-term data persistence for device tracking, IP lease history, audit logs, and network events. The persistence system is located under `crates/db/` and is divided into modular crates to allow flexible backend swapping between lightweight domestic environments (SQLite) and high-throughput enterprise setups (PostgreSQL).

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
       |  - DatabaseEngine trait                               |
       |  - LogBufferEngine trait                              |
       +-------------------------------------------------------+
                   /                               \
                  /                                 \
                 v                                   v
   +---------------------------+       +---------------------------+
   |   lanforge-db (SQLite)    |       |   lanforge-db-postgres    |
   |   - Embedded file / memory|       |   - External PostgreSQL pool  |
   +---------------------------+       +---------------------------+
```

---

## 2. Crate Responsibilities

### `lanforge-db-core` (`crates/db/lanforge-db-core/`)
- **`DatabaseEngine` Trait:** Abstracts database operations for devices, leases, static mappings, and system settings.
- **`LogBufferEngine` Trait:** Defines interfaces for buffering and writing high-frequency audit and event logs.
- **Data Models & Schema Trait Bounds:** Ensures engine implementations consume domain types from `lanforge-types`.

### `lanforge-db` (`crates/db/lanforge-db/`)
- **SQLite Engine:** Implements `DatabaseEngine` backed by `sqlx::SqlitePool`.
- **`DbWorker` Service:** Implements `AsyncService` to run as a supervised background task. It listens for `LanforgeEvent`s published to the `EventBus` and asynchronously writes state mutations to disk.

### `lanforge-db-postgres` (`crates/db/lanforge-db-postgres/`)
- **PostgreSQL Engine:** Implements `DatabaseEngine` backed by `sqlx::PgPool` for large-scale or multi-node LAN orchestration.

### `lanforge-db-logbuf` (`crates/db/lanforge-db-logbuf/`)
- **Log Buffering Engine:** Optimized append-only ring buffer for high-volume network telemetry and packet activity logs.

---

## 3. Event-Driven Persistence Pipeline

To prevent disk I/O latency from slowing down real-time network services (such as DHCP or RA packet handlers), database writes are completely decoupled from network packet loops.

1. **Packet Event:** A service (e.g., `lanforge-dhcp`) processes a packet, assigns an IP, and publishes `LanforgeEvent::Dhcp(DhcpEvent::LeaseGranted)`.
2. **Event Dispatch:** The `EventBus` broadcasts the event across `tokio::sync::broadcast`.
3. **Async DB Ingestion:** `DbWorker` receives the event via its subscription, formats the database query, and executes the write asynchronously against the configured `DatabaseEngine`.

---

## 4. Schema & Migrations (`sqlx`)

- **Compile-Time Verification:** Queries are checked using SQLx offline metadata (`sqlx-data.json`).
- **Automated Schema Migrations:** On startup, the database service automatically executes pending SQL migrations before invoking `ctrl.signal_ready()`.
- **Schema Modifications:** When changing SQL tables or queries, developer guidelines require running `cargo sqlx prepare` to keep offline metadata in sync across the workspace.

---

## 5. Persistence Invariants & System Guarantees

1. **Non-Blocking Packet Processing:** Packet handling loops in network services never perform synchronous database operations. Database persistence occurs reactively via `DbWorker` event consumption.
2. **Crash-Consistent Storage:** Database engines wrap state changes in transactions. If the daemon crashes unexpectedly, the state container on restart repopulates its baseline CoW memory state directly from the persistent database store.
3. **Pluggable Persistence Engines:** The daemon core operates identically whether running against an embedded SQLite backend or an external PostgreSQL cluster, as persistence interaction is strictly governed by `DatabaseEngine` trait abstractions.
