# Lanforge Architectural Specifications - Master Index

Welcome to the architectural specifications suite for **Lanforge**. This directory contains structured technical documentation explaining the inner workings, system invariants, data flows, and runtime behavior of Lanforge for both human engineers and LLMs.

---

## 1. Core Architecture Specifications

| Specification | Target Area | Description |
| :--- | :--- | :--- |
| **`01-core-domain-and-types.md`** (`docs/spec/01-core-domain-and-types.md`) | `core/lanforge-types` | L0 foundational domain types (`MacAddr`, `Duid`), CoW delta updates (`DeviceUpdate`), and global event schemas (`LanforgeEvent`). |
| **`02-state-management-and-eventbus.md`** (`docs/spec/02-state-management-and-eventbus.md`) | `core/lanforge-core` | L1 orchestrator, `LanforgeContext`, Copy-on-Write state mutation execution, `EventBus` pub/sub, and `ServiceControl`. |
| **`03-storage-and-data-persistence.md`** (`docs/spec/03-storage-and-data-persistence.md`) | `db/` | Modular database engine abstraction (SQLite / PostgreSQL), out-of-band `DbWorker` event-driven writes, and SQLx migrations. |
| **`04-daemon-bootstrap-and-supervisor.md`** (`docs/spec/04-daemon-bootstrap-and-supervisor.md`) | `bin/lanforge` | Daemon startup sequence, configuration parsing, `ServiceSupervisor` readiness monitoring (`signal_ready`), restart backoff, and graceful shutdown. |

---

## 2. Network Services Specifications (`docs/spec/services/`)

| Specification | Module | Description |
| :--- | :--- | :--- |
| **`services/01-dhcp-service.md`** (`docs/spec/services/01-dhcp-service.md`) | `lanforge-dhcp` | DHCP server role, device inventory updates, lease lifecycle, and dynamic DNS event generation. |
| **`services/01-01-dhcpv4-engine.md`** (`docs/spec/services/01-01-dhcpv4-engine.md`) | `lanforge-dhcp/src/v4` | DHCPv4 option parsing, static vs dynamic address pool allocation, and raw UDP socket I/O. |
| **`services/01-02-dhcpv6-engine.md`** (`docs/spec/services/01-02-dhcpv6-engine.md`) | `lanforge-dhcp/src/v6` | DHCPv6 SOLICIT/REQUEST state machine, DUID tracking, stateful IA_NA address assignment, and IA_PD prefix delegation. |
| **`services/02-ra-service.md`** (`docs/spec/services/02-ra-service.md`) | `lanforge-ra` | IPv6 Router Advertisement (RA), SLAAC prefix distribution, ICMPv6 solicitation handling, and RDNSS/DNSSL options. |
| **`services/02-01-ra-slaac-engine.md`** (`docs/spec/services/02-01-ra-slaac-engine.md`) | `lanforge-ra` | ICMPv6 Type 133/134 socket loops, immediate solicitation responses, prefix flag assembly (`A`, `M`, `O`), and periodic timer loops. |
| **`services/03-pppoe-service.md`** (`docs/spec/services/03-pppoe-service.md`) | `lanforge-pppoe` | PPPoE Discovery (PADI/PADR), LCP/IPCP negotiation, PAP/CHAP authentication, and Linux kernel PPP interface binding. |
| **`services/03-01-pppoe-discovery-and-sessions.md`** (`docs/spec/services/03-01-pppoe-discovery-and-sessions.md`) | `lanforge-pppoe` | Detailed PPPoE Discovery PADI/PADO/PADR/PADS negotiation flow, kernel PPP device creation, and IPCP parameters. |
| **`services/03-02-pppoe-keepalives.md`** (`docs/spec/services/03-02-pppoe-keepalives.md`) | `lanforge-pppoe` | Automated LCP echo-request/reply keepalive polling, timeout miss thresholds, session teardown, PADT transmission, and IP reclamation. |
| **`services/04-dns-service.md`** (`docs/spec/services/04-dns-service.md`) | `lanforge-dns` | Authoritative local DNS server, dynamic `.lan` hostname resolution, AdBlocker integration, and query telemetry. |
| **`services/04-01-dns-pipeline.md`** (`docs/spec/services/04-01-dns-pipeline.md`) | `lanforge-dns/src/pipeline` | DNS middleware processing pipeline (`Adblock` $\rightarrow$ `Local` $\rightarrow$ `Rewrite` $\rightarrow$ `Cache` $\rightarrow$ `Upstream`). |
| **`services/04-02-dns-adblocker-and-filtering.md`** (`docs/spec/services/04-02-dns-adblocker-and-filtering.md`) | `lanforge-dns/src/resolver/filter` | 3-tier lookup hierarchy (LRU cache $\rightarrow$ Bloom filter $\rightarrow$ Mmap FST), background list compilation, and zero-downtime atomic pointer swaps. |
| **`services/04-03-dns-transports-and-encryption.md`** (`docs/spec/services/04-03-dns-transports-and-encryption.md`) | `lanforge-dns/src/server/transport` | Multi-transport encrypted listeners: UDP/TCP 53, DoT (DNS over TLS), DoH (DNS over HTTPS), and DoQ (DNS over QUIC). |
| **`services/05-auxiliary-services.md`** (`docs/spec/services/05-auxiliary-services.md`) | `lanforge-tftp`, `wol`, etc. | Overview of auxiliary homelab services: TFTP boot serving, Wake-on-LAN (WOL), passive host discovery, and link state monitoring. |
| **`services/05-01-tftp-boot-server.md`** (`docs/spec/services/05-01-tftp-boot-server.md`) | `lanforge-tftp` | TFTP UDP 69 packet loop, read request handling, RFC 2347 option negotiation (`blksize`, `tsize`), block ACK tracking, and PXE bootloader serving. |
| **`services/05-02-discovery-and-wol.md`** (`docs/spec/services/05-02-discovery-and-wol.md`) | `lanforge-discovery`, `wol` | Passive mDNS/ARP/NDP packet sniffing for host inventory updates, and Wake-on-LAN (WOL) Magic Packet generation. |

---

## 3. End-to-End System Event Flow

```
+---------------------------------------------------------------------------------------------------------+
|                                    End-to-End Device Lifecycle Flow                                     |
+---------------------------------------------------------------------------------------------------------+

 (1) New Host connects to LAN & sends DHCPDISCOVER (UDP 67)
                             |
                             v
 (2) lanforge-dhcp receives packet, extracts MAC/DUID/Hostname
                             |
                             +-----------------------------------+
                             |                                   |
                             v (State Delta Update)              v (Event Emission)
 (3) ctx.apply(DeviceUpdate::Discovered / IpAssigned)   (4) bus.publish(LanforgeEvent::Dhcp(LeaseGranted))
                             |                                   |
                             v                                   +-----------------+
 (5) LanforgeContext Atomic CoW Memory Swap                                        |
                             |                                                     |
                             v                                                     v
 (6) In-Memory Device Inventory instantly updated        (7) lanforge-dns          (8) lanforge-db (DbWorker)
                                                             (Registers Dyn DNS)     (Asynchronously writes
                                                             (e.g. host.lan)          lease to SQLite/Postgres)
```
