# Lanforge Roadmap 🚀

This document outlines planned and potential future improvements for the Lanforge network monitoring system.

## 1. Performance & Transport Optimizations
- [x] **Response Compression**: Implement `zstd` or `lz4` compression for large diagnostic dumps (`ContextDump`) to reduce I/O overhead.
- [x] **Binary Protocol**: Add support for a binary wire format (e.g., MessagePack or Bincode) as an alternative to JSON for high-performance data exchange.
- [ ] **Streaming JSON Deserializer**: Optimize the CLI to use a streaming JSON parser for extremely large state dumps to further reduce memory pressure.
- [ ] **Lazy Indexing**: Explore lazy-loading or background rebuilding of DNS indices to speed up daemon cold starts.

## 2. CLI & User Experience
- [ ] **Interactive TUI Dashboard**: Build a real-time terminal dashboard using `ratatui` that consumes the `watch` event stream.
- [ ] **State Diffing**: Add a `lanforge state diff` command to compare the current state with a previous snapshot.
- [x] **Granular Querying**: Allow sub-filtering in `query state` (e.g., `--only-devices`, `--only-orphans`).
- [ ] **Compact Log Format**: Provide a "compact" view for logs that squashes repeated flapping events into a single "X is flapping" entry.

## 3. Core Logic & Networking
- [ ] **Active Probing Engine**: Implement a background service to actively probe (ICMP/TCP) devices that haven't been seen recently to verify status before pruning.
- [ ] **OUI Anomaly Detection**: Flag devices with MAC addresses that don't match their expected vendor or usage patterns.
- [ ] **Topology Mapping**: Use LLDP or neighbor observation patterns to attempt a basic mapping of "which device is behind which switch port."
- [ ] **Advanced mDNS Scraper**: Expand mDNS hint gathering to extract detailed service types (e.g., AirPlay, HomeKit) for better device classification.

## 4. Integration & Persistence
- [ ] **Web UI**: Develop a lightweight React/Next.js dashboard using the HTTP API for visual network management.
- [ ] **Prometheus Exporter**: Add a metrics endpoint for integration with Grafana/Prometheus.
- [ ] **Database Migrations**: Implement a robust migration system for `lanforge-db` to handle schema changes more gracefully.
- [ ] **Backup & Restore**: Add CLI commands to safely export and import the full system state and configuration.

---

*Note: This roadmap is a living document and represents a wishlist of features discussed during development sessions.*
