# Sub-System Specification: DHCPv6 Engine (`01-02`)

## 1. Overview & IPv6 Address Management

The DHCPv6 module (`crates/net/lanforge-dhcp/src/v6/`) manages stateful IPv6 address assignments (IA_NA) and IPv6 Prefix Delegation (IA_PD) over UDP port 547.

```
 Client Packet (SOLICIT / REQUEST / RENEW / RELEASE)
                          |
                          v
            +----------------------------+
            | DHCPv6 Packet Engine       |
            +----------------------------+
                          |
           +--------------+--------------+
           |                             |
           v                             v
[ DUID & Identity Match ]      [ IA_NA / IA_PD Allocation ]
  - DUID-LLT / DUID-EN           - Stateful IPv6 Address
  - DUID-LL  / DUID-UUID         - Delegated IPv6 Subnet Prefix
           \                             /
            \                           /
             v                         v
              DeviceUpdate & LanforgeEvent::Dhcp
```

---

## 2. Inbound Reaction & Processing Flow

### A. DUID Extraction & Identity Parsing
- Parses DHCPv6 Unique Identifier (`Duid`) variants (DUID-LLT, DUID-EN, DUID-LL, DUID-UUID).
- Extracts client FQDN options and requested Option Request Lists (ORL).
- Dispatches `DeviceUpdate::Discovered` with `Duid` hardware tracking.

### B. IA_NA & IA_PD Allocation
- **IA_NA (Non-Temporary Address):** Allocates a stateful 128-bit IPv6 address to the client interface.
- **IA_PD (Prefix Delegation):** Delegates an entire IPv6 prefix (e.g. `/64` or `/56`) to downstream routers or switches.

### C. Packet Response & Event Emission
- Responds with `ADVERTISE` or `REPLY` containing assigned IA_NA / IA_PD options, preferred/valid lifetimes, and Recursive DNS Server (RDNSS) options.
- Broadcasts `LanforgeEvent::Dhcp(DhcpEvent::LeaseGranted)` for IPv6 address and prefix tracking.

---

## 3. System Invariants

1. **DUID Persistence:** IPv6 clients are tracked deterministically across network reconnections using their `Duid` rather than volatile link-local MAC addresses.
2. **Prefix Delegation Sync:** Delegated IPv6 prefixes assigned via IA_PD update internal routing descriptors so Lanforge routes traffic to downstream prefixes automatically.
