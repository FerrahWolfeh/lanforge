# Sub-System Specification: Host Discovery & Wake-on-LAN (`05-02`)

## 1. Overview & Mechanics

`lanforge-discovery` and `lanforge-wol` handle passive/active network host discovery and Wake-on-LAN (WOL) remote power management.

```
                  +-----------------------------------+
                  | Discovery & WOL Subsystems        |
                  +-----------------------------------+
                   /                 |               \
                  /                  |                \
                 v                   v                 v
     [ Passive Sniffing ]   [ Active Probe ]   [ WOL Magic Packet ]
     - mDNS (.local)        - ARP Ping         - Sends 6x 0xFF +
     - ARP / NDP Traffic    - ICMP Sweep         16x Target MAC
                 \                   |                 /
                  \                  |                /
                   v                 v               v
                +---------------------------------------+
                | DeviceUpdate::Discovered / LanforgeEvent|
                +---------------------------------------+
```

---

## 2. Inbound Reaction & Processing Flow

### A. Passive Network Sniffing (`lanforge-discovery`)
- **mDNS Listener:** Listens on UDP multicast port 5353 (`224.0.0.251` / `ff02::fb`). Extracts hostname and service descriptors broadcast by Apple Bonjour, Avahi, or smart home devices.
- **ARP & NDP Observation:** Passively sniffs ARP requests and IPv6 Neighbor Discovery traffic to identify static IP hosts on the local link.
- **State Inventory Update:** Dispatches `DeviceUpdate::Discovered` to populate the central memory inventory for devices that do not use DHCP or PPPoE.

### B. Wake-on-LAN Magic Packet Generation (`lanforge-wol`)
- **Target Lookup:** Accepts target device identifiers (`MacAddr` or `DeviceId`).
- **Magic Packet Construction:** Constructs an Ethernet broadcast frame containing 6 payload bytes of `0xFF` followed by 16 repetitions of the target MAC address.
- **Transmission:** Broadcasts the payload over UDP ports 7/9 or raw Ethernet frames across all configured LAN interfaces, emitting `LanforgeEvent` notifications.

---

## 3. System Invariants

1. **Complete LAN Visibility:** Passive discovery ensures statically configured hosts and mDNS devices appear in Lanforge's global device state alongside dynamic clients.
2. **Interface Broadcast Routing:** WOL magic packets are broadcast across all active interfaces to ensure reachability even in multi-VLAN or bridged segment topologies.
