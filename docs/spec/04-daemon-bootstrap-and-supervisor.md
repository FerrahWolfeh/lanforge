# Specification 04: Daemon Bootstrap & Service Supervisor (`bin/lanforge`)

## 1. Overview & System Role

The `lanforge` binary daemon (`crates/bin/lanforge/`) serves as the entry-point executable for the entire Lanforge suite. It initializes runtime configuration, constructs the central `LanforgeContext`, boots storage engines, spawns API services (Unix Sockets & HTTP), and supervises all background network services (DHCP, RA, PPPoE, DNS, TFTP, WOL, Discovery).

```
                      +-----------------------------+
                      |      Main Entry Point       |
                      |   (main.rs / bootstrap.rs)  |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Configuration Parsing     |
                      |   (lanforge.toml / env)     |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      | Construct LanforgeContext   |
                      |  - Init CoW State Engine    |
                      |  - Init EventBus            |
                      |  - Init Database Backend    |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      | Service Supervisor          |
                      | (supervisor.rs)             |
                      +-----------------------------+
                        /            |            \
                       /             |             \
                      v              v              v
               [ lanforge-dhcp ] [ lanforge-dns ] [ lanforge-pppoe ] ...
```

---

## 2. Daemon Bootstrap Sequence (`bootstrap.rs`, `app.rs`)

When the daemon starts up:

1. **Configuration & Logging Setup:** Parses configuration parameters from `lanforge.toml`, environment variables, and CLI flags. Initializes `tracing` telemetry and log levels.
2. **Storage Engine Initialization:** Opens database connection pools (SQLite or PostgreSQL) via `lanforge-db`. Runs pending database schema migrations before starting dependent network daemons.
3. **Core Context Construction:** Instantiates `LanforgeContext`, creating the shared Copy-on-Write (CoW) memory state container and initializing the `tokio::sync::broadcast` `EventBus`.
4. **API Service Binding:** Starts `lanforge-uds` (Unix Domain Socket server) and `lanforge-http` (HTTP/REST/WebSocket server) so CLI and Web users can interact with the daemon immediately.
5. **Supervisor Spawn:** Hands over network service descriptors to `ServiceSupervisor`.

---

## 3. Service Supervisor Mechanics (`supervisor.rs`)

The `ServiceSupervisor` manages the execution lifecycle of all background network services:

### A. Ordered Startup & Dependency Sequencing
- Services register their readiness requirements.
- The supervisor starts core dependencies (such as `DbWorker` and `DnsServer`) prior to starting packet-handling services like `DhcpServer` or `RaServer`.

### B. Readiness Signal Monitoring (`ctrl.signal_ready()`)
- As each service boots, the supervisor monitors its `ServiceControl` handle.
- The service remains in `ServiceStatus::Starting` until it invokes `ctrl.signal_ready()` following successful socket/port binding.
- If a service fails to signal readiness within its startup timeout, the supervisor marks it failed and initiates recovery.

### C. Health Monitoring & Restart Backoff Algorithm
- Supervises background `tokio` tasks. If a service task panics or exits unexpectedly:
  1. The supervisor catches the crash log.
  2. Updates service status to `ServiceStatus::Failed`.
  3. Applies an **exponential backoff delay** (e.g., 1s $\rightarrow$ 2s $\rightarrow$ 4s $\rightarrow$ 8s up to a maximum cap) before attempting restart.
  4. Broadcasts `LanforgeEvent::System(SystemEvent::ServiceRestarted)` on the bus.

### D. Graceful Shutdown Protocol (`SIGTERM` / `SIGINT`)
Upon receiving OS termination signals (`SIGINT` or `SIGTERM`):
1. **Signal Broadcast:** Sends cancellation tokens across all running service contexts.
2. **Port Closure:** Network services stop accepting new packets and close bound sockets.
3. **Storage Flush:** `DbWorker` flushes all pending in-memory write queues to disk.
4. **Clean Exit:** The supervisor waits for worker tasks to join before exiting cleanly.

---

## 4. System Invariants & Execution Guarantees

1. **Crash Isolation:** A panic or error in an individual network service (e.g. TFTP) is isolated by the supervisor and does not crash the entire daemon or impair other services.
2. **Clean State Restoration:** On startup, the daemon hydrates its memory state from the persistent database before enabling network interface sockets.
3. **Graceful Shutdown:** Shutdown signals guarantee that pending database writes are committed to disk prior to process termination.
