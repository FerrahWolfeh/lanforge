# Service Specification: IPv6 Router Advertisement Engine (`lanforge-ra`)

## 1. Overview & System Role

`lanforge-ra` is Lanforge's IPv6 Router Advertisement (RA) daemon. It orchestrates IPv6 stateless address autoconfiguration (SLAAC), prefix delegation (RDNSS, DNSSL), default route announcements, and IPv6 neighbor discovery on local networks.

```
       Multicast / Unicast Router Solicitation (ICMPv6 Type 133)
                                  |
                                  v
                        +--------------------+
                        | lanforge-ra        |
                        | - ICMPv6 Listener  |
                        +--------------------+
                             /          \
                            /            \
                           v              v
       (Periodic / Solicited RA)     DeviceUpdate / LanforgeEvent::Network
        (ICMPv6 Type 134 Packet)     (Notifies State & EventBus)
```

---

## 2. Inbound Reaction & Processing Flow

### A. ICMPv6 Solicitation Reaction
- **Listener:** Listens on raw ICMPv6 sockets bound to network interfaces for Router Solicitation (RS, Type 133) messages.
- **Immediate Response:** When an RS packet arrives from a host, `lanforge-ra` extracts the source Link-Local IPv6 address and MAC address, dispatches `DeviceUpdate::Discovered` to the state engine, and immediately transmits a unicast or multicast Router Advertisement (RA, Type 134) without waiting for the next periodic timer.

### B. Unsolicited Periodic Announcements
- **Timer Loop:** Maintains configurable periodic advertisement intervals (e.g. 200-600 seconds) to ensure IPv6 hosts refresh default routes, prefix lifetimes, MTU settings, and recursive DNS servers (RDNSS options).

### C. State & Event Integration
- Whenever interface IPv6 configuration or link states change, `lanforge-ra` emits `LanforgeEvent::Network` events and updates interface state descriptors in `LanforgeContext`.

---

## 3. System Invariants

1. **SLAAC & RDNSS Coordination:** Advertises prefix flags (Autonomous Address Configuration `A=1`, Managed Address Configuration `M=0/1`, Other Configuration `O=0/1`) in lockstep with `lanforge-dhcp` configuration.
2. **Zero-Downtime Prefix Updates:** Changes in WAN IPv6 prefix delegation dynamically trigger updated RA broadcasts to LAN interfaces so clients update SLAAC addresses seamlessly.
