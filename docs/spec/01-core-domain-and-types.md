# Specification 01: Core Domain & Types (`lanforge-types`)

## 1. Overview & Architectural Position

`lanforge-types` is the **Level 0 (L0)** foundational crate of the Lanforge workspace. It contains all core domain models, address identifiers, event broadcast primitives, and state mutation protocol definitions.

```
       +-------------------------------------------------------+
       |   Higher Layers (L1-L3): Core, API, Net Services, Bin |
       +-------------------------------------------------------+
                                   |
                                   v (Depends on)
       +-------------------------------------------------------+
       |           core/lanforge-types (L0 Crate)              |
       |  - Identifiers (MacAddr, Duid, DeviceId)              |
       |  - Core Domain Models (Device, Interface, Leases)     |
       |  - Event Definitions (LanforgeEvent)                  |
       |  - State Update Protocol (DeviceUpdate)               |
       +-------------------------------------------------------+
```

### Key Architectural Constraints
- **Zero Inter-Crate Dependencies:** `lanforge-types` does NOT depend on any other crate in the workspace (except procedural macros like `lanforge-macros` or basic utility crates).
- **Pure Data & Protocols:** Contains serializable domain types (via `serde`), value objects, and protocol contracts without any I/O, network binding, or background execution logic.
- **Ubiquitous Language:** Defines the canonical representations used consistently across storage (SQLite/PostgreSQL), inter-service buses, APIs (Unix Socket / HTTP), and user interfaces (CLI/TUI).

---

## 2. Address Identifiers (`lanforge-types::identifiers`)

Lanforge relies on strongly typed hardware and protocol address abstractions to prevent primitive obsession and misuse.

### Key Types
- **`MacAddr`** (`crates/core/lanforge-types/src/identifiers/mac.rs`): Represents a 6-byte IEEE 802 MAC address with formatting (colon-separated notation), parsing, and binary conversions.
- **`Duid`** (`crates/core/lanforge-types/src/identifiers/duid.rs`): DHCPv6 Unique Identifier supporting DUID-LLT, DUID-EN, DUID-LL, and DUID-UUID variants.
- **`DeviceId`** (`crates/core/lanforge-types/src/identifiers/device.rs`): Unique identifier for tracked LAN devices.

---

## 3. Core Domain Models (`lanforge-types::device`, `network`, `system`)

### Device Model (`device/core.rs`)
The central entity in Lanforge is the **`Device`**, representing a physical or virtual host discovered or managed on the network.

- Key attributes tracked:
  - Hardware addresses (`MacAddr`) & DUIDs.
  - Active and historical IPv4 / IPv6 addresses assigned or observed.
  - Device hostname, vendor metadata (via OUI lookup), lease state, and first/last seen timestamps.
  - Current connection state (`DeviceState`: `Active`, `Idle`, `Stale`, `Blocked`).

### Network Interfaces & System Models (`network/`, `system.rs`)
- **`Interface`**: Describes system network interfaces, IP bindings, link speeds, MTU, and flags (UP, BROADCAST, MULTICAST).
- **`SystemStatus` / `SystemHealth`**: High-level health telemetry of the Lanforge daemon runtime.

---

## 4. State Update Protocol (`lanforge-types::update`)

Lanforge employs a Copy-on-Write (CoW) state architecture. To ensure consistency and lock-free thread safety across background services, state mutations are never performed directly. Instead, services emit delta updates using **`DeviceUpdate`** (`crates/core/lanforge-types/src/update/mod.rs`).

### Mutation Variants (`DeviceUpdate`)
Services dispatch `DeviceUpdate` items to `LanforgeContext`, which applies the mutations atomically:
- `Discovered`: A new device was observed on the wire (DHCP, ARP, RA, or NDP).
- `IpAssigned`: An IPv4 or IPv6 address was assigned to a device.
- `HostnameChanged`: Hostname updated via DHCP request or DNS query.
- `LeaseExpired` / `DeviceOffline`: Update state transition on timeout.

---

## 5. Global Event Bus Schemas (`lanforge-types::events`)

Inter-service communication is decoupled via `tokio::sync::broadcast` broadcasting of **`LanforgeEvent`**.

```
 [ Service (e.g. lanforge-dhcp) ] 
                 |
                 | publishes LanforgeEvent::Dhcp(DhcpEvent::LeaseGranted)
                 v
   +---------------------------+
   |   Broadcast Event Bus     |
   +---------------------------+
                 |
        +--------+--------+
        |                 |
        v                 v
  [ lanforge-db ]   [ lanforge-dns ]
 (Persist Lease)   (Update Dynamic DNS)
```

### Sub-Event Domains (`LanforgeEvent` Enum Variants)
- **`Device(DeviceEvent)`**: Device added, updated, removed, or state changed.
- **`Dhcp(DhcpEvent)`**: Lease requested, granted, renewed, released, or expired.
- **`Pppoe(PppoeEvent)`**: Session initialized, authenticated, terminated, or keepalive failed.
- **`Dns(DnsEvent)`**: Domain query logged or dynamic record updated.
- **`Network(NetworkEvent)`**: Interface state change, link up/down event.
- **`System(SystemEvent)`**: Service readiness signal, configuration reload, or shutdown requested.

---

## 6. System Invariants & Domain Boundaries

1. **Isolation of Domain Types:** `lanforge-types` is strictly decoupled from network I/O, database drivers, and RPC serialization protocols. It serves as the single source of truth for domain data layout across all subsystems.
2. **Decoupled State Mutation:** Data structures within `lanforge-types` do not mutate themselves. Mutations are represented declaratively via `DeviceUpdate` objects that are processed by the central state engine.
3. **Event Granularity:** `LanforgeEvent` variants represent immutable facts about occurrences in the network or daemon runtime. Once published, events cannot be modified or canceled by subscribers.
