# Service Specification: DHCP Engine (`lanforge-dhcp`)

## 1. Overview & System Role

`lanforge-dhcp` is Lanforge's integrated DHCP service supporting both IPv4 (DHCPv4) and IPv6 (DHCPv6) lease management.

Rather than acting as a standalone DHCP server, `lanforge-dhcp` operates as a **first-class participant in Lanforge's reactive state engine**. Every incoming packet discovered on the wire feeds device tracking, lease allocations, dynamic hostname resolution, and system-wide broadcast notifications.

```
Incoming Wire Packet (UDP 67 / 547)
            |
            v
   +--------------------+
   | lanforge-dhcp      |
   | - Packet Handler   |
   +--------------------+
        |            |
        |            +------------------------------------+
        | (1) DeviceUpdate::Discovered / IpAssigned       | (2) LanforgeEvent::Dhcp(...)
        v                                                 v
+-----------------------+                    +-------------------------+
| LanforgeContext       |                    | Lanforge EventBus       |
| - CoW State Engine    |                    | - DbWorker (Persist)    |
| - Device Inventory    |                    | - DnsServer (Dyn DNS)   |
+-----------------------+                    +-------------------------+
```

---

## 2. Inbound Reaction & Processing Flow

### A. Device Discovery & Identity Extraction
When a client sends a DHCP request (e.g. `DHCPDISCOVER`, `DHCPREQUEST`, or DHCPv6 `SOLICIT`), `lanforge-dhcp`:
1. Extracts client identifiers (`MacAddr`, `Duid`, client-id option).
2. Reads requested options (Hostname, Parameter Request List, Vendor Class).
3. Immediately dispatches `DeviceUpdate::Discovered` to `LanforgeContext` so the central engine registers the device in memory even before a lease is finalized.

### B. Address Allocation & Pool Management
- **Static Bindings Check:** Checks state for fixed IP reservations matched by MAC or DUID.
- **Dynamic Pool Allocation:** If no static binding exists, selects an available address from the configured IP pool.
- **Conflict Prevention & Ping Check:** Verifies address availability before sending an offer/ack.
- **State Mutation:** On successful binding, dispatches `DeviceUpdate::IpAssigned` and `DeviceUpdate::HostnameChanged` to update the global CoW state.

### C. Event Bus Emission
Once a lease is granted or renewed, `lanforge-dhcp` broadcasts `LanforgeEvent::Dhcp(DhcpEvent::LeaseGranted)` containing:
- Assigned IP address and prefix/subnet.
- Hardware `MacAddr` and `Duid`.
- Hostname (if reported by client).
- Lease start time and expiration duration.

---

## 3. Subsystem Reactions to DHCP Events

When `lanforge-dhcp` emits DHCP events to the bus:
- **`lanforge-db` (Persistence):** Captures `LeaseGranted`, `LeaseReleased`, or `LeaseExpired` events and asynchronously updates `redb` storage.
- **`lanforge-dns` (Dynamic DNS):** Reacts to `LeaseGranted` events containing hostnames to instantly register dynamic local `.lan` DNS records without daemon restarts.
- **API & UI Clients:** Real-time CLI and WebUI listeners receive the event over Unix Sockets / HTTP (SSE) to update active dashboard displays.

---

## 4. System Invariants

1. **Integrated State Source:** DHCP lease allocations are synchronized directly with Lanforge's central memory state; there are no disconnected secondary lease files.
2. **Dynamic Hostname Integration:** Hostnames supplied in DHCP option 12 or DHCPv6 FQDN options automatically update central device state and dynamic DNS resolution.
3. **Non-Blocking Packet Loops:** Lease persistence and DNS record sync happen asynchronously via event listeners; the DHCP server thread remains dedicated to low-latency packet processing.
