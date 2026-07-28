# Sub-System Specification: IPv6 Router Advertisement Engine (`02-01`)

## 1. Overview & SLAAC Mechanics

The IPv6 Router Advertisement (RA) subsystem (`crates/net/lanforge-ra/`) operates on raw ICMPv6 sockets to handle Stateless Address Autoconfiguration (SLAAC), prefix announcements, and default gateway routing.

```
       ICMPv6 Socket (Type 133 Router Solicitation)
                           |
                           v
             +---------------------------+
             | ICMPv6 Listener           |
             | - Extracts Source MAC     |
             +---------------------------+
                           |
            +--------------+--------------+
            |                             |
            v                             v
  (Immediate Solicited RA)       DeviceUpdate::Discovered
   ICMPv6 Type 134 Response         (State Inventory Update)
```

---

## 2. Inbound Reaction & Processing Flow

### A. ICMPv6 Packet Handling
- **Router Solicitation (Type 133):** When a host sends an RS packet, `lanforge-ra` extracts source Link-Local IPv6 and MAC address, notifies the device inventory via `DeviceUpdate::Discovered`, and immediately responds with a solicited Router Advertisement (RA, Type 134).
- **Periodic Timer Loop:** In parallel, a background timer loop broadcasts unsolicited RAs at configurable intervals (e.g. 200–600 seconds) to maintain default router validity on LAN segments.

### B. Option Assembly & Flags
- **Prefix Information Options (PIO):** Advertises IPv6 prefixes with Autonomous Address Configuration (`A=1`), On-Link (`L=1`), and valid/preferred lifetimes.
- **Managed & Other Flags:** Configures `M=1` (Managed) when DHCPv6 stateful assignment is enforced, or `O=1` (Other) when stateless DHCPv6 is used for DNS configuration.
- **RDNSS & DNSSL:** Embeds Recursive DNS Server IPv6 addresses and DNS Search List domain options directly inside RA packets.

---

## 3. System Invariants

1. **Dynamic SLAAC Lifetime Sync:** When WAN IPv6 prefixes change, `lanforge-ra` instantly transmits RAs with zero-lifetime on old prefixes and valid lifetime on new prefixes, preventing stale IPv6 connectivity.
2. **Immediate Solicitation Response:** Does not delay RS responses; solicited RAs are transmitted immediately to ensure sub-second IPv6 network join times for clients.
