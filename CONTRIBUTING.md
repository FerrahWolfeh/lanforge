# Contributing to Lanforge

Thank you for your interest in contributing to Lanforge! Whether you are fixing a bug, improving documentation, or proposing an architectural enhancement, we welcome your help.

---

## 1. Development Prerequisites

- **Rust**: Version 1.85+ (Edition 2024).
- **Node.js & pnpm**: Node.js 22+ and pnpm 9+ (required for building the embedded SvelteKit WebUI).
- **Linux Environment**: Linux kernel 5.10+ (development on Linux is recommended due to Netlink, raw sockets, and packet routing protocols).

---

## 2. Getting Started & Building

```bash
# 1. Clone the repository
git clone https://github.com/FerrahWolfeh/lanforge.git
cd lanforge

# 2. Build WebUI assets
cd web
pnpm install
pnpm build
cd ..

# 3. Build Rust workspace binaries (daemon and CLI)
cargo build
```

---

## 3. Running Tests & Simulation

### Automated Test Suite
Run the full workspace tests:
```bash
cargo test --workspace
```

### Rootless Simulation Testbed (`lanforge-lab`)
You do not need root privileges or a spare physical router to experiment with Lanforge. We provide `lanforge-lab`, a simulation engine that tests DHCP leases, DNS resolution, and packet queues in-memory using inert handles:

```bash
cargo run -p lanforge-lab
```

### WebUI Diagnostics
```bash
cd web
pnpm check   # TypeScript & Svelte type checking
pnpm dev     # Hot-reloading development server on http://localhost:5173
```

---

## 4. Key Architectural Invariants

When writing code for Lanforge, please keep these core design principles in mind:

1. **The Golden Rule of Isolation**:
   - Configuration changes, interface transitions (e.g. PPPoE WAN reconnect), or individual service bounces **must never** crash or reboot the global daemon or tear down unrelated services.
   - Services absorb state updates in-place through topic-isolated event bus subscriptions.
2. **State Updates via CQRS Protocol**:
   - Services do not mutate global state directly.
   - Submit mutations via `ctx.apply(DeviceUpdate::...)`. Read state through scoped borrow closures (`ctx.with_state(...)`).
3. **Embedded Performance & Zero Allocation in Hot Paths**:
   - Lanforge targets edge gateways and SBCs (Raspberry Pi, NanoPi).
   - Prefer stack buffers (`[u8; 1500]`) or `SmallVec` for transient packet decoding over heap allocations.
   - High-throughput database writes are batched through the out-of-band `DbWorker` rather than committed per-packet.
4. **WebUI Language Standard**:
   - All user-facing text, placeholders, labels, and code comments in `web/` must be written exclusively in **English**.

---

## 5. Submitting Pull Requests

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-enhancement
   ```
2. Ensure everything compiles cleanly and tests pass:
   ```bash
   cargo check --workspace
   cargo test --workspace
   pnpm --prefix web check
   ```
3. Open a Pull Request with a clear summary of what changed and how you tested it.
