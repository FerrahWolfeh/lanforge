# AGENTS.md

# Lanforge
A rust-based complete and simplified solution for domestic homelab/openwrt-based LAN orchestration with integrated DHCP, TFTP, RA and DNS servers with special address tracking, embedded redb data persistence, unix socket and http APIs alongside full fledged cli and tui utilities.

## Special concerns about each module crate
- `core/lanforge-types` (L0) - The foundational crate. Contains core domain types (Device, MacAddr, Duid), shared event definitions (LanforgeEvent), and state update protocols (DeviceUpdate). **Rule:** Must not depend on any other crate except macros and basic utilities.
- `core/lanforge-core` (L1) - The "brain" of the project. Orchestrates global state transitions and event distribution. Depends on `lanforge-types`.
- `api/lanforge-api` (L1) - Shared API protocol definitions and RPC trait contracts. Used by both CLI and Daemon.
- `api/lanforge-api-dispatch` (L2) - Server-side implementation of the RPC protocol handlers. Depends on `core` and `db`.
- `api/lanforge-uds`, `lanforge-http` (L2) - Service crates that expose the API via Unix Sockets or HTTP.
- `net/lanforge-dhcp`, `net/lanforge-ra`, `net/lanforge-discovery`, `net/lanforge-wol`, `net/lanforge-dns`, `db/lanforge-db`, `net/lanforge-tftp` (L2) - Specialized service crates.
- `bin/lanforge`, `bin/lanforge-cli`, `bin/lanforge-lab` (L3) - Entry-point binaries for daemon, admin CLI, and testbed simulation workbench.
- `core/lanforge-macros` (L0) - Internal procedural macros for service registration and boilerplate.
- `web/` - Front-end WebUI application (SvelteKit + shadcn-svelte + Tailwind CSS).

# Architectural Patterns

## 1. The Service Model
Most background tasks (DHCP, RA, DNS, etc.) are implemented as services using the `#[lanforge_service]` attribute and the `AsyncService` or `SyncService` traits.
- Services are managed by a **Supervisor** that handles retries and backoff.
- Use `ctrl.signal_ready()` once a service has successfully bound its ports/sockets.

## 2. Global State & Context
The `LanforgeContext` is the central Arc-wrapped handle passed to all services.
- It provides access to the `EventBus` and the `State`.
- State updates **MUST** be performed via `ctx.apply(DeviceUpdate::...)`. Never mutate state directly.
- The `State` uses `Arc::make_mut` (Copy-on-Write) for efficient updates.

## 3. The Event Bus
A `tokio::sync::broadcast` based bus facilitates inter-service communication.
- **Publishing:** `ctx.bus().publish(LanforgeEvent::...)`
- **Subscribing:** `ctx.bus().subscribe()`
- Avoid heavy processing in event listeners; if an event requires I/O, spawn a task or send it to a dedicated worker.

# Recommended cargo & pnpm commands
- `cargo clippy --workspace` - Run instead of `cargo check`. This will catch more potential issues.
- `cargo test -p lanforge-lab` - Run automated lab testbed suite without root/sudo.
- `cargo run --bin lanforge-lab -- suite --json` - Execute complete regression test suite headlessly.
- `cargo run --bin lanforge-lab -- run dhcp --json` - Simulate DHCP client DORA cycle headlessly.
- `cargo run --bin lanforge-lab -- run dns --domain "domain.lan" --json` - Test DNS resolution/adblocking.
- `cargo add -p <crate>` - Use to add dependencies to specific workspace members.
- `pnpm --prefix web dev` - Start local WebUI development server with HMR.
- `pnpm --prefix web build` - Build production static SPA bundle for embedding.
- `pnpm --prefix web check` - Verify WebUI types and Svelte templates.

# Recommended Rust coding idioms
- Define type usage in files only through use statements at the very top of the file. Only place the type's full name outside of a use statement when its name alone causes conflicts with another type inside the file.
- Prefer `parking_lot` primitives (RwLock/Mutex) over `std` or `tokio` sync primitives for state protection unless `.await` is required across the lock.
- Use the `Identifier` derive macro for any new address-like types (MAC, DUID, etc.).

# Performance & Resource Efficiency Guidelines (Embedded & SBC Targets)
Lanforge is designed to run efficiently on resource-constrained single-board computers (like Raspberry Pi 4B and OpenWrt devices). Keep memory bandwidth low, minimize allocator churn, and eliminate CPU wakeups:
- **Avoid Unnecessary Clones**: Prefer borrowing references or using scoped closures (e.g. `ctx.with_state(|state| ...)` and `ctx.with_config(|cfg| ...)`) over legacy helpers that clone entire `Vec` collections.
- **Topic-Isolated Event Subscriptions**: Subscribe only to the specific domain topics needed (e.g. `ctx.bus().subscribe_network()`, `subscribe_dns()`, `subscribe_system()`) instead of the global stream, preventing high-frequency event floods from waking sleeping tasks.
- **Stack Buffers & Allocation Reuse**: Prefer stack-allocated fixed-size buffers (`[u8; 1500]`) or `SmallVec` / `EventVec` for transient packet handling and event collection over heap `Vec` allocations.
- **Zero-Copy Parsing**: Use subslice borrows (`&'a [u8]`, `&str`) where feasible when decoding wire protocols instead of allocating owned strings.
- **Batched I/O**: Batch high-frequency disk writes, log entries, and database flushes (e.g. `DbWorker` 5-second tick) rather than performing synchronous per-event I/O.
---

# Claude-only guidelines
- If you are Claude, you are the user's project and implementation planner. You must not write code unless explicitly allowed.

# Behavioral guidelines to reduce common LLM coding mistakes.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.