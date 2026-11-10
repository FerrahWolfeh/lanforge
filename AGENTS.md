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
Background daemons (DHCP, RA, DNS, PPPoE, Firewall, etc.) implement the `AsyncService` or `SyncService` traits (with a hand-written `spec()`). They are managed by a central **Supervisor** that handles retries, backoff, and state monitoring.

### The Golden Rule of Isolation
**Configuration changes, module reconnections, or single-service bounces MUST NEVER trigger a global daemon reboot or tear down unrelated services.**
- `lanforge reload` (CLI/HTTP) goes through the API handler `handle_reload`
  (`crates/api/lanforge-api-dispatch/src/handlers/system/reload.rs`), which re-reads the file-owned sections and
  applies them in place. Nothing in production publishes `SystemEvent::ReloadConfig`; never hang new reload logic
  off it (a whole reload path once lived there, dead, with green tests).
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

## 2b. Configuration & Persistence Model
- **Files are config, redb is state.** `/etc/lanforge/lanforge.toml` (plus line-oriented bulk files such as
  `adblock/*.rules`) is the single source of configuration. redb holds only state: devices, leases, users,
  tokens, stats, last known GUA. Do not add new config to redb, and do not build TOML⇄redb sync code.
- File-owned sections are listed in `SectionSet::FILE_OWNED` (`crates/api/lanforge-api/src/config_file/section.rs`).
  Their file forms live in `crates/api/lanforge-api/src/config_file/`.
- **What goes in the file**: only what a minimal lanforge needs to run the network. WebUI conveniences and
  logging switches (e.g. per-device DNS log flags) stay in redb as device settings. Removing a host from the file
  demotes the device; it never deletes it.
- **Derived values** ("effective" config) live in `config_file/effective.rs`. They are applied in memory at boot
  and on reload and are never written back to the file.
- **Writes from the API/WebUI** go through a `change_*` method in
  `crates/api/lanforge-api-dispatch/src/handlers/system/config_write.rs`, under `ctx.config_change_lock()`:
  read the live value, normalize it through the file form, refuse on issues, persist, apply.
- **Bad config never takes the network down.** An invalid entry is skipped and reported as a `config_issues`
  item (shown in the CLI/WebUI); a section that cannot be read is *set aside*: live state stays as it was
  (`None`, never an empty value), and **no code may persist over a set-aside section**. This includes startup
  "heal"/sanity writers: one once wrote defaults over a set-aside `[dhcp]` and deleted the configured pools.
- Before changing who writes a key or field, grep **every** writer and reader of it.
- IPv6 addressing: lanforge never assigns addresses to physical interfaces. The LAN ULA/GUA are whatever the OS
  (e.g. systemd-networkd, DHCPv6-PD) put on the interface; detect them, never generate them.

## 2c. Known Traps
- **Status banners come from a non-serving instance.** `ServiceRegistry::register` keeps a `factory()` instance as
  the status provider, and the supervisor builds a separate instance that serves. `stats()` /
  `transport_snapshot()` must read live data through `ctx` (shared `Arc`s, snapshots), never fields `serve`
  mutates, or the value stays frozen at boot.
- **UDS uses postcard**: never put `#[serde(skip_serializing_if = ...)]` on RPC DTOs that cross the UDS
  (postcard is not self-describing; decoding breaks). It is fine on TOML file forms.
- **JS numbers are 53-bit**: never send 64-bit ids to the WebUI as JSON numbers.
- API errors: bad input must map to `Response::Rejected` / `NotFound` (HTTP 4xx), not a 500.

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
- **Host seams**: what a service does to the machine beyond sockets is a trait with the real implementation as the
  default type parameter: `PppoeService<H: PppoeHost = KernelHost>`, `NftService<A: NftApplier = KernelNft>`,
  `TrafficService<H: TrafficHost = KernelTraffic>`. Test stand-ins live behind the crate's `inert` feature or in the
  tests themselves, never as a flag or an `is_inert()` check inside the service.
- **Raw syscalls** go through `lanforge_transport::sys` (one documented `unsafe` per wrapper); service crates do not
  add their own `unsafe` blocks.

---

# Recommended Developer Commands

### Rust & Backend
- `cargo clippy -p <crate>` - Lint a specific workspace crate (or `cargo clippy --workspace`).
- `cargo test -p <crate>` - Run unit and integration tests for a specific crate.
- `cargo add -p <crate> <dependency>` - Add dependencies to a specific workspace crate.
- `cargo fmt --all` - Format before every commit.
- `./scripts/check-dns-features.sh` - Feature matrix for `lanforge-dns` (CI runs it; run it when touching DNS features/cfgs).
- `./scripts/check-daemon-features.sh` - Feature matrix for the daemon (`lanforge`): each service alone, the profiles,
  no services (CI runs it; run it when touching `#[cfg(feature = ...)]` in `crates/bin/lanforge`).
- `./scripts/check-cli-features.sh` - Feature matrix for the CLI (`lanforge-cli`): without `remote`, each crypto
  provider (CI runs it; run it when touching `#[cfg(feature = ...)]` in `crates/bin/lanforge-cli`).
- Iterate with `cargo check --all-targets -p <crate>`; run the full `cargo test` once at the end. Feature-matrix
  runs produce many large test binaries, so prefer `-p <crate>` over `--workspace` while iterating.
- **One test binary per crate.** Integration tests live in the lib as `#[cfg(test)] mod integration_tests`
  (`src/integration_tests/`, shared helpers in its `common/`), not in `tests/`: every file under `tests/` is a
  separate executable linking the whole dependency graph (≈100–400 MB each), and the RAM-disk target fills up.
  They still go through the public entry points (`serve`, API handlers), never private internals. Gate a module
  that needs features with `#[cfg(feature = ...)]` on its `mod` line. Run one area with
  `cargo test -p <crate> integration_tests::<module>::`. Only tests that must run the built binary
  (`CARGO_BIN_EXE_*`) or install their own `#[global_allocator]` stay in `tests/`.
- Tests that execute the CLI binary must set `HOME`/`XDG_DATA_HOME` to a nonexistent directory and drop
  `LANFORGE_REMOTE_URL`/`LANFORGE_TOKEN`: the CLI has a remote mode with a saved login, and a test can otherwise reach
  a live instance.
- Rootless dev daemon for WebUI/API checks:
  `lanforged --dev -c <tmp>/lanforge.toml --config-db-path memory --runtime-db-path memory --http-listen 127.0.0.1:18096 --control-socket /tmp/lf.sock`
  (the file needs `[dns] listen = "127.0.0.1:15353"`; create the first user via `POST /api/v1/users`; stop it with
  `pkill -x lanforged`). `lanforge-webui`'s build script runs pnpm itself.
- Raw sockets without root: build first, then `unshare -rn sh -c 'ip link set lo up && <test binary> --ignored <name>'`.
- nftables rulesets can be validated rootless with `unshare -rn nft -c -f <file>`.

### WebUI (`web/`)
- `pnpm --prefix web dev` - Start local WebUI development server with hot-module reloading.
- `pnpm --prefix web build` - Build the production static SPA bundle for embedding.
- `pnpm --prefix web check` - Run `svelte-check` and TypeScript type diagnostics.

#### WebUI Language Rule
- **Strict English Only**: All user-facing text in `web/` (labels, placeholders, tooltips, modals/dialogs, toast notifications, table headers, descriptions, and code comments) must be written exclusively in English. **Never write non-English text in the WebUI.**

---

# Coding Idioms & Performance Guidelines (SBC & Embedded Targets)

Lanforge runs on single-board computers (Raspberry Pi, NanoPi, OpenWrt routers) where CPU cycles, allocator churn, and memory bandwidth are constrained:
- **Imports**: Group imports at the very top of each file. Avoid inline full path qualification unless resolving name collisions.
- **Lock Primitives**: Prefer `parking_lot` (RwLock/Mutex) over `std` or `tokio` sync primitives unless `.await` is held across the critical section.
- **Zero Allocations & Stack Buffers**: Prefer stack-allocated fixed-size buffers (`[u8; 1500]`) or `SmallVec` for transient packet decoding over heap allocations.
- **Scoped Borrowing**: Use closures (`ctx.with_state`, `ctx.with_config`) rather than cloning full `Vec` or struct structures.
- **Zero-Copy Wire Protocols**: Borrow subslices (`&[u8]`, `&str`) when decoding packets instead of allocating owned strings.
- **Batched I/O**: High-frequency disk writes, audit logs, and metrics must be batched (e.g. `DbWorker` 5s tick) rather than committed per-packet or per-event.
- **Lean code**: no speculative machinery, extra layers, or abstractions nobody asked for. Reuse existing parsers
  and helpers; allocate only on rare admin paths, never in hot paths (DNS engine, packet loops).
- **DSL crates**: `lanforge-types` and `lanforge-api` describe the domain language. Logic there is allowed only as
  methods/trait impls (`FromStr`, `Display`, ...) on the type it belongs to, never as a free-function `utils` module.
- **Generics vs dyn**: monomorphize only on per-packet hot paths (transport, wire codecs, DNS/DHCP fast path); use `dyn` for handlers, setup, config plumbing, CLI/API. No `impl Into<T>` parameters.
- **RFCs are the spec**: protocol behaviour (DHCPv4/v6, RA, DNS, DoT/DoQ/DoH, PPPoE) is derived from the RFCs, not
  from what the current code does.

---

# How to Work in This Repository

Lanforge runs real networks: a broken build or a bad deploy takes a LAN offline.
**Stability comes before style work or new features.**

**Local instructions:** if `AGENTS.local.md` exists at the repository root (gitignored), read it after this file;
it holds maintainer- and machine-specific rules and takes precedence over this file.

## Language
- Code, identifiers, code comments, commit messages, docs and all WebUI text: **English only**.

## Tests: distrust, then prove
- **Some existing tests were written from the implementation and assert buggy behaviour.** A green test is not
  proof that the behaviour is right.
- Derive expected behaviour from RFCs and `docs/`, not from the current code.
- **Every bug fix needs a regression test that fails on the old code.** Prove it: revert the fix (or check out the
  previous commit in a `git worktree add --detach <dir> <hash>` with its own `CARGO_TARGET_DIR`), run the test,
  watch it fail, then restore. A worktree sharing the main target dir can silently test the wrong build; after
  removing the worktree, `cargo clean -p <touched crates>`.
- Test the **real entry point** (the API handler, the service's `serve`), not an internal helper that nothing calls.
- Reproduce reported hardware bugs in an inert-transport test (`::inert()`, `with_transport`) before fixing.
- When editing test files with repeated setup snippets via scripts (sed/Python), scope the edit to the target
  function, or the replacement lands in the wrong test.

## Scope and findings
- Do what the task asks. Do not refactor, rename or "improve" unrelated code on the way.
- When you spot a bug or smell outside the task, **do not fix it silently**: report it with `file:line` and why.
- If the code makes a documented design decision impossible, or a choice is not covered by the task or docs,
  **stop and ask** instead of improvising.

## Large mechanical refactors (lints, style passes, renames)
- **Behaviour-preserving only.** Never mix a logic change, bug fix or "while I'm here" cleanup into a style commit;
  report the finding instead.
- One lint/rule per commit, rolled out **crate by crate**; every commit builds, passes
  `cargo clippy --workspace --all-targets` and the tests of the touched crates.
- **Never edit a test assertion to make a refactor pass.** A failing test after a refactor means the refactor
  changed behaviour: undo it and find out why.
- **Serialized shapes are contracts.** Do not rename, reorder or retype fields/variants of anything that is
  serialized, and do not add or remove `#[serde(...)]` attributes on them:
  - TOML file forms (`config_file/`): renames break existing config files.
  - redb records: renames/reorders break databases already on disk (postcard is positional).
  - UDS DTOs (postcard, positional): field order is the wire format; CLI and daemon must agree.
  - HTTP/JSON DTOs: the WebUI's TypeScript types (`web/src/lib/api/`) are hand-written mirrors, so a rename
    breaks the UI silently and `pnpm check` does not catch it.
- Lint suppressions: no blanket crate-level `#![allow(...)]`. Use a targeted
  `#[expect(clippy::lint, reason = "...")]` on the smallest item, and only when the fix would be worse.
- `.unwrap()` in production code becomes `?` where the caller already returns a fitting error, otherwise
  `.expect("<the invariant that makes this infallible>")`. Do not change public signatures just to add `?`.
- Bulk edits with `sed`/scripts/`clippy --fix`: run them per crate, then read the whole diff before committing.
  Unread diffs do not get committed.

## Commits and branches
- Work on a branch, never directly on `main`. Do not push or rewrite published history unless asked.
- Each commit must **build, pass tests, and be one coherent, revertible unit** (one logical fix/feature), so a
  deployment can be rolled back commit by commit. No floods of micro-commits, no giant per-task commit.
- Conventional style: `fix(dns): ...`, `feat(webui): ...`, `chore: ...`; the body explains the why.
- Never disable or bypass commit signing or hooks.

## Releases and versioning
- One version for the whole workspace (`[workspace.package] version`, every crate uses `version.workspace = true`).
- A merge into `main` is a release: `git merge --no-ff`, preceded by a `chore: release X.Y.Z` bump commit, tagged
  `vX.Y.Z` on main. Patch = fixes/internal only; minor = a user-visible change, or one that requires swapping CLI
  and daemon together or reinstalling the systemd unit. Stay on `0.x`.
- Merges and version numbers are the maintainer's call: propose the version with the reason, then ask.

## Running instances
- **Never deploy, restart a daemon, or run state-changing commands against a running lanforge** unless asked.
  A daemon restart reconnects PPPoE and may renumber the LAN's delegated IPv6 prefix: a visible outage.
- Validate offline first (inert tests, the rootless dev daemon, `nft -c`). Prefer in-place mechanisms
  (firewall reapply, single-service restart) over a daemon restart.
- With every behaviour-changing commit, state a short, concrete post-deploy check, and whether it needs a
  restart/reconnect.
