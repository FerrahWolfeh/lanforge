# AGENTS.md

# Lanforge
A high-performance, resource-efficient Rust-based router and LAN orchestration platform designed for domestic homelabs and OpenWrt/SBC gateway appliances. Features integrated DHCPv4/v6, IPv6 RA, authoritative/recursive DNS with adblocking, PPPoE WAN client, stateful Netlink/nftables firewall, TFTP, network discovery with MAC/DUID/IP device tracking, embedded redb persistence, Unix Domain Socket and HTTP APIs, alongside an admin CLI and modern SvelteKit WebUI.

## Module Crate Architecture
- `core/lanforge-types` (L0) - Foundational crate. Contains core domain types (`Device`, `MacAddr`, `Duid`), event definitions (`LanforgeEvent`), and state update protocols (`DeviceUpdate`). **Rule:** Must never depend on any other workspace crate.
- `core/lanforge-core` (L1) - The "brain" of the project. Orchestrates global state transitions, event bus, and context management. Depends on `lanforge-types`.
- `api/lanforge-api` (L1) - Shared API protocol definitions, DTOs, and RPC trait contracts. Used by both CLI and Daemon.
- `api/lanforge-api-dispatch` (L2) - Server-side RPC protocol handlers. Depends on `core` and `db`.
- `api/lanforge-uds`, `api/lanforge-http` (L2) - Communication endpoints exposing the API via Unix Domain Sockets or HTTP/WebSockets.
- `net/lanforge-dhcp`, `net/lanforge-ra`, `net/lanforge-dns`, `net/lanforge-dns-wire`, `net/lanforge-pppoe`, `net/lanforge-nft`, `net/lanforge-discovery`, `net/lanforge-wol`, `net/lanforge-tftp` (L2) - Specialized network service crates.
- `db/lanforge-db` (L2) - Embedded data persistence backed by `redb`.
- `bin/lanforge`, `bin/lanforge-cli`, `bin/lanforge-lab` (L3) - Entry-point binaries for daemon, admin CLI, and testbed simulation.
- `core/lanforge-macros` (L0) - Internal procedural macros for service registration and boilerplate.
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
- Uses **topic-isolated** subscriptions: the supervisor listens exclusively to `ctx.bus().subscribe_system()`.
- Recognizes `ServiceState::Inactive` as an intentional settled state without triggering error backoffs or false alerts.
- **Clean Shutdown**: `ctx.terminate()` is called *prior* to broadcasting `SystemEvent::Shutdown`, ensuring terminating services are recognized and preventing the supervisor from re-spawning exiting tasks.
- **System Readiness**: Recognizes both `Online` and settled `Inactive` states so disabled services never block `SystemReady`.

## 2. Global State & Context
`LanforgeContext` is the central Arc-wrapped handle passed to all services.
- Access state via scoped closures: `ctx.with_state(|state| ...)` and `ctx.with_config(|cfg| ...)`.
- State updates **MUST** be performed via `ctx.apply(DeviceUpdate::...)`. Never mutate state directly.
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

---

# Coding Idioms & Performance Guidelines (SBC & Embedded Targets)

Lanforge runs on single-board computers (Raspberry Pi, NanoPi, OpenWrt routers) where CPU cycles, allocator churn, and memory bandwidth are constrained:
- **Imports**: Group imports at the very top of each file. Avoid inline full path qualification unless resolving name collisions.
- **Lock Primitives**: Prefer `parking_lot` (RwLock/Mutex) over `std` or `tokio` sync primitives unless `.await` is held across the critical section.
- **Zero Allocations & Stack Buffers**: Prefer stack-allocated fixed-size buffers (`[u8; 1500]`) or `SmallVec` for transient packet decoding over heap allocations.
- **Scoped Borrowing**: Use closures (`ctx.with_state`, `ctx.with_config`) rather than cloning full `Vec` or struct structures.
- **Zero-Copy Wire Protocols**: Borrow subslices (`&[u8]`, `&str`) when decoding packets instead of allocating owned strings.
- **Batched I/O**: High-frequency disk writes, audit logs, and metrics must be batched (e.g. `DbWorker` 5s tick) rather than committed per-packet or per-event.

---

# Claude-only guidelines
- If you are Claude, you are the user's project and implementation planner. You must not write code unless explicitly allowed.

---

# Behavioral Guidelines to Reduce Common LLM Mistakes

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding
**Don't assume. Don't hide confusion. Surface tradeoffs.**
- State assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.

## 2. Simplicity First
**Minimum code that solves the problem. Nothing speculative.**
- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- If you write 200 lines and it could be 50, rewrite it.

## 3. Surgical Changes
**Touch only what you must. Clean up only your own mess.**
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution
**Define success criteria. Loop until verified.**
- Transform tasks into verifiable goals with automated checks.
- For multi-step tasks, state a brief plan:
  ```
  1. [Step] → verify: [check]
  2. [Step] → verify: [check]
  ```