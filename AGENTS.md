# AGENTS.md

# Lanforge
A high-performance, resource-efficient Rust-based router and LAN orchestration platform designed for domestic homelabs and OpenWrt/SBC gateway appliances. Features integrated DHCPv4/v6, IPv6 RA, authoritative/recursive DNS with adblocking, PPPoE WAN client, stateful Netlink/nftables firewall, TFTP, network discovery with MAC/DUID/IP device tracking, embedded redb persistence, Unix Domain Socket and HTTP APIs, alongside an admin CLI and modern SvelteKit WebUI.

## Module Crate Architecture
- `crates/core/lanforge-types` (L0) - Foundational crate. Contains core domain types (`Device`, `MacAddr`, `Duid`), event definitions (`LanforgeEvent`), and state update protocols (`DeviceUpdate`). **Rule:** Must never depend on any other workspace crate.
- `crates/core/lanforge-core` (L1) - The "brain" of the project. Orchestrates global state transitions, event bus, and context management. Depends on `lanforge-types`.
- `crates/core/lanforge-crypto` (L1) - Foundational security crate. Encapsulates password hashing (Argon2id), key derivation, and cryptographic utilities.
- `crates/core/lanforge-macros` (L0) - Internal procedural macros for service registration and boilerplate.
- `crates/net/lanforge-transport` (L1) - Foundational transport crate. Implements dual-stack Y-architecture (`UdpTransport`, `DualTcpListener`, `Icmp6Transport`), lock-free rate limiting, atomic metrics, and pure dependency injection (`InertHandle`) for rootless simulation.
- `crates/net/lanforge-dhcp`, `crates/net/lanforge-ra`, `crates/net/lanforge-dns`, `crates/net/lanforge-dns-wire`, `crates/net/lanforge-pppoe`, `crates/net/lanforge-nft`, `crates/net/lanforge-discovery`, `crates/net/lanforge-traffic`, `crates/net/lanforge-tftp` (L2) - Specialized network service crates (Wake-on-LAN lives in `lanforge-transport`).
- `crates/api/lanforge-api` (L1) - Shared API protocol definitions, DTOs, and RPC trait contracts. Used by both CLI and Daemon.
- `crates/api/lanforge-api-dispatch` (L2) - Server-side RPC protocol handlers. Depends on `core`, `api`, and `crypto`. Operates decoupled from database persistence via event-driven CQRS.
- `crates/api/lanforge-uds`, `crates/api/lanforge-http` (L2) - Communication endpoints exposing the API via Unix Domain Sockets or HTTP/WebSockets.
- `crates/webui/lanforge-webui` (L2) - Embedded WebUI asset distribution crate.
- `crates/db/lanforge-db`, `crates/db/lanforge-db-core`, `crates/db/lanforge-db-redb` (L2) - Embedded data persistence backed by `redb`.
- `crates/bin/lanforge`, `crates/bin/lanforge-cli`, `crates/bin/lanforge-lab` (L3) - Entry-point binaries for daemon, admin CLI, and testbed simulation.
- `web/` - Front-end WebUI application (SvelteKit + shadcn-svelte + Tailwind CSS).

---

# Architectural Patterns & Service Lifecycle

## 1. The Service Model & The Golden Rule of Isolation
Background daemons (DHCP, RA, DNS, PPPoE, Firewall, etc.) are implemented using the `#[lanforge_service]` attribute and the `AsyncService` or `SyncService` traits. They are managed by a central **Supervisor** that handles retries, backoff, and state monitoring.

### The Golden Rule of Isolation
**Configuration changes, module reconnections, or single-service bounces MUST NEVER trigger a global daemon reboot or tear down unrelated services.**
- `SystemEvent::ReloadConfig` is **strictly reserved** for explicit, manual administrator commands (e.g. `lanforge reload` via CLI).
- **In-Place Updates**:
  - **Firewall (`lanforge-nft`)**: Listens for `FirewallEvent::RulesetChanged` to recompile and apply Netlink rules in-place in ~5ms. Never restarts HTTP, DNS, DHCP, or UDS.
  - **PPPoE (`lanforge-pppoe`)**: Self-contained lifecycle. Reconnection cooperatively sends a PADT termination packet to the AC, bounces only its internal session task via `ServiceAction::Restart`, and absorbs updated credentials directly from `ctx`. WAN interface transitions (`SessionUp` / `SessionDown`) are absorbed in-place by the firewall and DNS upstream resolvers.
  - **DHCP / RA / DNS**: Absorb configuration changes in-memory via domain-specific events without closing sockets.
  - **Dormant / Disabled Services (TFTP, Discovery, mDNS)**: Return clean `Ok(())` setting `ServiceState::Inactive`. **Never use `std::future::pending::<()>()`.**

### Supervisor Architecture
- **Dependency graph** (`crates/bin/lanforge/src/supervisor/`): typed edges `Requires` / `Wants` / `After`. Losing a
  `Requires` dependency **never stops or restarts** the dependent; it applies the edge's `LossPolicy`
  (`Continue` / `Degrade` / `Pause`) and sends `ServiceCommand::DependencyLost` / `DependencyRestored`.
- **Conditions** (`ServiceSpec.condition`) are re-evaluated on every `SystemEvent::ConfigChanged`: a service whose
  condition turns dormant is stopped (`Inactive(Dormant)`), and started again when it becomes active. Never poll config.
- **Admin control**: `SystemEvent::ServiceControl` is routed by the supervisor to the target runner, which sends
  `ServiceCommand::{Stop, Restart}` through the `ServiceHandle`. Services must handle commands only via
  `h.next_command()` and must **not** react to `ServiceControl` on the bus. `Restart` may be handled in place
  (PPPoE, firewall) or by returning after `h.request_restart()`. A service that ignores `Stop` is cancelled after
  `shutdown_timeout`.
- **Live config**: services consume config only through `ctx.config_subscription::<T>()`; the legacy
  `Config*Changed` bus events are notifications for UI/CLI observers.
- Uses **topic-isolated** subscriptions: the supervisor listens exclusively to `ctx.bus().subscribe_system()`.
- Recognizes `ServiceState::Inactive` as an intentional settled state without triggering error backoffs or false alerts.
- **Clean Shutdown**: `ctx.terminate()` is called *prior* to broadcasting `SystemEvent::Shutdown`, ensuring terminating services are recognized and preventing the supervisor from re-spawning exiting tasks.
- **System Readiness**: Recognizes both `Online` and settled `Inactive` states so disabled services never block `SystemReady`.

### Async hygiene (bugs found in phase 6)
- Never end a `select!` arm with a polling future (`yield_now`, `has_changed` loops): await a real change.
- Tasks that own sockets must not spawn detached child tasks holding them: use a `JoinSet` owned by the task, and
  `abort()` **and await** the handle before rebinding.
- A closed broadcast channel (`RecvError::Closed`) must end the loop, never `continue`; only `Lagged` is skipped.
- `Notify::notify_waiters` stores no permit: use a `watch` epoch when a wake-up must not be lost.

## 2. Global State & Context
`LanforgeContext` is the central Arc-wrapped handle passed to all services.
- Access state via scoped closures: `ctx.with_state(|state| ...)` and `ctx.with_config(|cfg| ...)`.
- State updates **MUST** be performed via `ctx.apply(DeviceUpdate::...)`. Never mutate state directly.
- `DeviceUpdate::InterfaceIpsChanged` carries a **full snapshot** of the interface addresses: a missing address was
  removed. Never send a partial state through it.
- `NetworkEvent::PrefixChanged` is emitted by **every** interface (LAN, `ppp0`, ...) and carries `ifindex`: always
  filter on the interface you serve. The advertised/leased LAN prefix is the LAN interface's GUA (delegated by the
  OS), never the WAN link prefix.
- The `State` uses `Arc::make_mut` (Copy-on-Write) for efficient, lock-minimized updates.

## 3. The Event Bus & Topic Isolation
Inter-service communication is powered by a multi-topic broadcast bus:
- **Publishing:** `ctx.bus().publish(LanforgeEvent::...)`
- **Topic-Isolated Subscriptions**: Avoid subscribing to the global stream. Subscribe only to the domain topics needed (e.g. `ctx.bus().subscribe_network()`, `subscribe_dns()`, `subscribe_system()`, `subscribe_firewall()`) to prevent waking sleeping worker threads unnecessarily.

## 4. Firewall & Traffic Security Model
- **External WAN is a Strict Closed Wall**: Interfaces in the `external` zone (`ppp0`, `wan0`) have default policies of `DROP` for both `input` and `forward`.
- **Restricted DNAT Acceptance**: `ct status dnat accept` is strictly scoped to internal (`internal`) and trusted (`trusted`, `podman*`, `tailscale0`) interfaces. WAN packets with DNAT flags generated by host container engines (Netavark/Docker) are **dropped** unless explicitly authorized.
- **WAN Ingress Authorization**:
  - **Router Host Services**: Controlled strictly by Host Rules in the `external` zone (`input` chain).
  - **Internal LAN Services**: Controlled by explicit Port Forwarding rules (IPv4 DNAT) or IPv6 Pinholes (routed directly without NAT) matching specific target IP and port in the `forward` chain.
- **Unified Port Forwarding**: The WebUI manages both IPv4 DNAT and IPv6 routed pinholes in a single, unified interface with automatic device recognition, static lease pinning, and dual-stack rule creation.

## 5. Transport Layer & Inert Simulation (`lanforge-transport`)
- **Dual-Stack Native ("Y" Architecture)**: Avoid hybrid sockets (`IPV6_V6ONLY = false`) to eliminate kernel IPv4-mapped address translation (`::ffff:x.x.x.x`). Services bind native IPv4 and IPv6 independently while exposing unified async streams (`UdpTransport`, `DualTcpListener`).
- **Rootless & Zero-Mock Daemons**: Domain services (`RaService`, `Dhcpv4Service`, `Dhcpv6Service`, `DnsService`, etc.) must not contain mock branches, synthetic flags, or simulation-specific conditionals.
- **Pure Dependency Injection**: Tests and simulations instantiate in-memory transports via `(handle, transport) = ...::inert()` and pass them to services via `Service::with_transport(cfg, ctx, transport)`.

---

# Recommended Developer Commands

### Rust & Backend
- `cargo clippy -p <crate>` - Lint a specific workspace crate (or `cargo clippy --workspace`).
- `cargo test -p <crate>` - Run unit and integration tests for a specific crate.
- `cargo add -p <crate> <dependency>` - Add dependencies to a specific workspace crate.

### WebUI (`web/`)
- `pnpm --prefix web dev` - Start local WebUI development server with hot-module reloading.
- `pnpm --prefix web build` - Build the production static SPA bundle for embedding.
- `pnpm --prefix web check` - Run `svelte-check` and TypeScript type diagnostics.

#### WebUI Language Rule
- **Strict English Only**: All user-facing text in `web/` (labels, placeholders, tooltips, modals/dialogs, toast notifications, table headers, descriptions, and code comments) must be written exclusively in English. **Never write Portuguese or any non-English text in the WebUI.**

---

# Coding Idioms & Performance Guidelines (SBC & Embedded Targets)

Lanforge runs on single-board computers (Raspberry Pi, NanoPi, OpenWrt routers) where CPU cycles, allocator churn, and memory bandwidth are constrained:
- **Imports**: Group imports at the very top of each file. Avoid inline full path qualification unless resolving name collisions.
- **Lock Primitives**: Prefer `parking_lot` (RwLock/Mutex) over `std` or `tokio` sync primitives unless `.await` is held across the critical section.
- **Zero Allocations & Stack Buffers**: Prefer stack-allocated fixed-size buffers (`[u8; 1500]`) or `SmallVec` for transient packet decoding over heap allocations.
- **Scoped Borrowing**: Use closures (`ctx.with_state`, `ctx.with_config`) rather than cloning full `Vec` or struct structures.
- **Zero-Copy Wire Protocols**: Borrow subslices (`&[u8]`, `&str`) when decoding packets instead of allocating owned strings.
- **Batched I/O**: High-frequency disk writes, audit logs, and metrics must be batched (e.g. `DbWorker` 5s tick) rather than committed per-packet or per-event.