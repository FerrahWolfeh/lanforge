# Establishing the Master Client Manager

## Goal
Formalize the [DeviceTable](file:///home/datcr/Projects/Rust/ipv6_namer/src/state.rs#116-122) as the **Master Client Manager** of the system. In this pattern:
1. **Servers (DHCPv4, DHCPv6, RA)** act as protocol-specific "propagators" that identify network events and client intentions.
2. They return **DeviceUpdates** to the service loops.
3. The **Master Client Manager** ([DeviceTable](file:///home/datcr/Projects/Rust/ipv6_namer/src/state.rs#116-122)) is the sole authority for merging these updates, managing the persistence layer (SQLite), and triggering global events (EventBus).

This decoupling ensures that future components—like a DNS server or a CLI/Socket interface—always interact with a single, consistent source of truth.

## Proposed Changes

### Stage 4.4: Zero-Cost Abstractions & Object Packing

#### [netlink.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/netlink.rs)
- [MODIFY] Replace [extract_neigh_info](file:///home/datcr/Projects/Rust/ipv6_namer/src/netlink.rs#52-87) raw tuple returns with a `NeighborEvent` struct.
- [MODIFY] Add semantic methods to `NeighborEvent` (e.g., `.is_stale()`, `.has_mac()`).

#### [ra/packet.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/ra/packet.rs)
- [NEW] Introduce `RaPacket` and `RaPacketBuilder`.
- [MODIFY] Replace the procedural [build_ra_packet](file:///home/datcr/Projects/Rust/ipv6_namer/src/ra/packet.rs#12-111) with a builder-pattern approach to simplify option management (RDNSS, MTU, etc.).

#### [dhcp/v4/raw.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/dhcp/v4/raw.rs)
- [NEW] Create a `DhcpRawFrame` struct to encapsulate the Ethernet/IP/UDP layering logic.

---

### Stage 4.5: Establishing the Master Client Manager

### [state.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/state.rs)
- [NEW] Define `DeviceUpdate` to encapsulate cross-protocol client data (MAC, IP, Hostname, DUID, etc.).
- [MODIFY] Formalize [DeviceTable](file:///home/datcr/Projects/Rust/ipv6_namer/src/state.rs#116-122) as the central manager:
    - Add `apply_update(&mut self, update: DeviceUpdate)` method.
    - [FUTURE] Integrate reactive persistence (saving to DB when dirty).

---

### [dhcp/v6/server.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/dhcp/v6/server.rs)
- [MODIFY] Remove `&RwLock<DeviceTable>` from [handle_packet](file:///home/datcr/Projects/Rust/ipv6_namer/src/dhcp/v4/server.rs#35-81). The server should only need the `nl_handle` (for synchronous lookups) or be given the MAC directly if the service loop handles the lookup.
- [MODIFY] Update `HandleResult` to return `DeviceUpdate` instead of raw ID pieces.

### [dhcp/v6/mod.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/dhcp/v6/mod.rs)
- [MODIFY] Adapt the service loop to take the `DeviceUpdate` from the server and apply it to the [DeviceTable](file:///home/datcr/Projects/Rust/ipv6_namer/src/state.rs#116-122).
- [MODIFY] Move the "learned DUID" and "LeaseGranted" event publishing here to keep the server "pure".

---

### [dhcp/v4/server.rs](file:///home/datcr/Projects/Rust/ipv4_namer/src/dhcp/v4/server.rs)
- [MODIFY] Similar refactor to v6: return `DeviceUpdate` in `HandleResult`.
- [MODIFY] Ensure hostname and IP assignments are bundled in the update.

### [dhcp/v4/mod.rs](file:///home/datcr/Projects/Rust/ipv4_namer/src/dhcp/v4/mod.rs)
- [MODIFY] Adapt the service loop to apply the `DeviceUpdate`.

## Verification Plan

### Automated Tests
- Run `cargo test` for [state.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/state.rs), [dhcp/v4/server.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/dhcp/v4/server.rs), and [dhcp/v6/server.rs](file:///home/datcr/Projects/Rust/ipv6_namer/src/dhcp/v6/server.rs).
- Add integration tests for `DeviceTable::apply_update` to ensure correctly merging v4, v6, and static info.

### Manual Verification
- Verify `lanforge devices` output continues to show aggregated info correctly.
