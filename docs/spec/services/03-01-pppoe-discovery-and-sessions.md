# Sub-System Specification: PPPoE Discovery & Session Negotiation (`03-01`)

## 1. Overview & Mechanics

The PPPoE module (`crates/net/lanforge-pppoe/`) manages PPPoE discovery, link negotiation, authentication, IP address assignment, and Linux kernel datapath binding.

```
 Client PADI Broadcast ---> Lanforge PADO Offer
 Client PADR Request   ---> Lanforge PADS Session Confirmation
                                  |
                                  v
                        PPP LCP Negotiation
                                  |
                                  v
                     PAP / CHAP Authentication
                                  |
                                  v
                        PPP IPCP Negotiation
                                  |
                                  v
                 Kernel PPP Interface Creation (`ppp0`)
                                  |
                                  v
                  DeviceUpdate & LanforgeEvent::Pppoe
```

---

## 2. Processing Stages

### A. Discovery Stage (`discovery.rs`)
- **PADI (Initiation):** Client broadcasts PADI. `lanforge-pppoe` checks service name tags and responds with `PADO`.
- **PADR (Request) & PADS (Session):** Client responds with PADR. `lanforge-pppoe` assigns a unique Session ID and confirms with `PADS`, creating an active session tracking entry.

### B. PPP Link Negotiation & Auth (`lcp.rs`, `auth.rs`)
- **LCP (Link Control Protocol):** Negotiates maximum receive unit (MRU) and magic numbers to detect looped links.
- **PAP / CHAP Auth:** Validates client credentials against `lanforge-types` authentication models.

### C. IPCP & Kernel Interface Binding (`ipcp.rs`, `kernel.rs`)
- **IPCP:** Grants client IPv4 address and primary/secondary DNS server IP addresses.
- **Kernel Datapath Binding:** Creates and configures Linux kernel `ppp` interfaces for high-throughput, zero-copy payload routing.

---

## 3. System Invariants

1. **Kernel Datapath Offloading:** Userspace code handles discovery and LCP control frames, while IP payload routing is offloaded to the Linux kernel PPP subsystem.
2. **Synchronized Session Inventory:** Active PPPoE clients immediately appear in global device inventory alongside DHCP clients.
