# Lanforge Roadmap 🚀

This document outlines planned and potential future improvements for the Lanforge network monitoring system.

## 1. Performance & Transport Optimizations
- [x] **Response Compression**: Implement `zstd` or `lz4` compression for large diagnostic dumps (`ContextDump`) to reduce I/O overhead.
- [x] **Binary Protocol**: Add support for a binary wire format (e.g., MessagePack or Bincode) as an alternative to JSON for high-performance data exchange.
- [ ] **Streaming JSON Deserializer**: Optimize the CLI to use a streaming JSON parser for extremely large state dumps to further reduce memory pressure.
- [ ] **Lazy Indexing**: Explore lazy-loading or background rebuilding of DNS indices to speed up daemon cold starts.

## 2. CLI & User Experience
- [ ] **Interactive TUI Dashboard**: Build a real-time terminal dashboard using `ratatui` that consumes the `watch` event stream. (Will display detailed mDNS metadata & category icons).
- [ ] **State Diffing**: Add a `lanforge state diff` command to compare the current state with a previous snapshot.
- [x] **Granular Querying**: Allow sub-filtering in `query state` (e.g., `--only-devices`, `--only-orphans`).
- [ ] **Compact Log Format**: Provide a "compact" view for logs that squashes repeated flapping events into a single "X is flapping" entry.

## 3. Core Logic & Networking
- [ ] **Active Probing Engine**: Implement a background service to actively probe (ICMP/TCP) devices that haven't been seen recently to verify status before pruning.
- [ ] **OUI Anomaly Detection**: Flag devices with MAC addresses that don't match their expected vendor or usage patterns.
- [ ] **Topology Mapping**: Use LLDP or neighbor observation patterns to attempt a basic mapping of "which device is behind which switch port."
- [x] **Advanced mDNS Scraper**: Expand mDNS hint gathering to extract detailed service types (e.g., AirPlay, HomeKit) for better device classification.

## 4. Integration & Persistence
- [ ] **Web UI**: Develop a lightweight React/Next.js dashboard using the HTTP API for visual network management.
- [x] **Prometheus Exporter**: Add a metrics endpoint for integration with Grafana/Prometheus.
- [x] **Database Migrations**: Implement a robust migration system for `lanforge-db` to handle schema changes more gracefully (Already implemented using `sqlx::migrate!`).
- [ ] **Backup & Restore**: Add CLI commands to safely export and import the full system state and configuration.

---

# Extra roadmap and Wishlist:

### Phase 0: Core Stabilization
- [ ] Freeze core daemon scope. Current orchestrator (IPv4/IPv6, mDNS, SLAAC, persistence) is stable. No new features in the main engine.
- [ ] Refine UDS CLI. Continue improving management commands using `clap` over Unix Domain Sockets.
- [ ] Retain `zstd` for state dumps. In-memory compression justifies the 1MiB binary size increase by reducing I/O bottlenecks on edge hardware.

### Phase 1: DNS Filtering (Micro Adblock)
- [ ] Implement in-memory filtering structures. Use `HashSet` or Radix Tree for O(1) blocklist lookups prior to recursive resolution.
- [ ] Integrate lightweight HTTP client. Use `ureq` (blocking, minimal dependencies) in a background thread for fetching blocklists to avoid `reqwest` bloat.
- [ ] Implement stateless metrics. Use atomic counters in memory for blocked queries (e.g., blocked per MAC/IP). Strictly avoid disk I/O for query logs.
- [ ] Delegate metrics visualization. Expose counters via Prometheus exporter. Offload time-series storage and graphing to external tools (e.g., Grafana).

### Phase 2: API Security & Authentication
- [ ] Implement CLI credential setup. Create a `lanforge config set-password` command via UDS to calculate the password hash and store it statically in `lanforge.toml`.
- [ ] Enable static credential loading. The HTTP engine reads the hash from the config file on startup and stores it in global memory (zero DB dependency).
- [ ] Implement login endpoint. Create a `POST /login` route that validates the incoming password against the in-memory hash and returns an ephemeral token.
- [ ] Implement auth middleware. Require `Authorization: Bearer <token>` for all API routes. Use O(1) in-memory token validation to preserve CPU cycles.

### Phase 3: Internal IPC, DoT, and DoH
- [ ] Resolve cross-compilation dependencies. Migrate from `openssl` to `rustls` (or use `features = ["vendored"]` for unavoidable C libs) to fix `aarch64` dynamic linking issues.
- [ ] Integrate API with DNS via Actor model. Implement `tokio::select!` in the `lanforge-dns` loop to listen to both the UDP socket and internal MPSC/Broadcast channels simultaneously without blocking.
- [ ] Implement DNS over TLS (DoT). Wrap the TCP listener in a `rustls` TLS stream on port 853.
- [ ] Implement DNS over HTTPS (DoH). Add a `/dns-query` route to the existing HTTP engine, decode requests, and route them to the internal resolver using isolated context reads.

### Anti-Goals (Out of Scope)
- [x] DO NOT implement NTP. Delegate time synchronization to `systemd-timesyncd` or `chrony`.
- [x] DO NOT use PAM for authentication. Incompatible with OpenWrt/musl libc and severely complicates cross-compilation.
- [x] DO NOT log individual DNS queries to SQLite/Postgres. Prevents storage degradation on edge devices (SD cards/eMMC).
- [x] DO NOT use `reqwest`. Adds unnecessary binary bloat and TLS overhead for simple background HTTP GET operations.
