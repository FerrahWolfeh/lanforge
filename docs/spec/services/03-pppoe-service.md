# Service Specification: PPPoE Server Engine (`lanforge-pppoe`)

## 1. Overview & System Role

`lanforge-pppoe` provides Point-to-Point Protocol over Ethernet (PPPoE) access server capabilities within Lanforge. It manages discovery stage negotiation, PPP link control protocol (LCP) echo keepalives, PAP/CHAP authentication, IP Control Protocol (IPCP) address assignment, and Linux kernel tun/ppp interface binding.

```
 Client PADI (Discovery Initiation)
                 |
                 v
     +-----------------------+
     | lanforge-pppoe        |
     | - Discovery Engine    | ---> Sends PADO (Offer)
     +-----------------------+
                 |
 Client PADR (Session Request)
                 |
                 v
     +-----------------------+
     | LCP / PAP / IPCP      | ---> Assigns IP, Binds Kernel PPP Interface
     +-----------------------+
                 |
                 +-------------------> DeviceUpdate & LanforgeEvent::Pppoe
```

---

## 2. Inbound Reaction & Processing Flow

### A. Discovery Phase (PPPoED)
1. **PADI Reaction:** Receives `PADI` (PPPoE Active Discovery Initiation) broadcast from a client MAC. Checks service availability and responds with `PADO` (PPPoE Active Discovery Offer).
2. **PADR & Session Allocation:** On receiving `PADR` (Request), allocates a unique PPPoE Session ID, emits `PADS` (Session-confirmation), and transitions the client to the PPP session stage.

### B. PPP Negotiation & Authentication (LCP / IPCP)
- **LCP Negotiation:** Establishes link parameters (MRU, Magic Number).
- **Authentication:** Validates client credentials against `lanforge-types` authentication models (PAP / CHAP).
- **IPCP Address Assignment:** Grants client IP address, DNS servers, and updates central state via `DeviceUpdate::IpAssigned`.
- **Kernel Datapath Binding:** Configures Linux kernel PPP interface for zero-copy hardware routing.

### C. Session Maintenance & Keepalive (`keepalive.rs`)
- **LCP Echo Monitoring:** Continuously transmits LCP Echo-Requests at defined intervals.
- **Session Termination:** If a client fails to reply within the timeout threshold or sends a `PADT` (Termination), the session is torn down, the IP address is released back to the pool, and `LanforgeEvent::Pppoe(PppoeEvent::SessionTerminated)` is broadcast.

---

## 3. System Invariants

1. **Integrated Session State:** PPPoE sessions directly reflect device status in the central CoW state; active sessions appear in global inventory alongside DHCP leases.
2. **Kernel Offloading:** Control plane packets (LCP, IPCP, Discovery) are handled in userspace by `lanforge-pppoe`, while data plane payload routing is handed off to the kernel for maximum throughput.
