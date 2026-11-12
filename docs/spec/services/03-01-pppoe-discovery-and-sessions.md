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

### D. Session Handoff Across Daemon Restarts (`handoff.rs`, `kernel/store.rs`)
- The kernel keeps `pppN` up while the session's descriptors (the `AF_PPPOX` socket, the `/dev/ppp` channel and
  unit) are open. When a session comes up, copies of them and a `SessionRecord` (memfd: concentrator MAC, session
  ID, LCP magic numbers, IPCP/IPv6CP results, the dialling identity) go to systemd's fd store
  (`FileDescriptorStoreMax=4` in the unit; needs systemd ≥ 254 for `$FDSTORE`). Under SELinux, systemd (`init_t`)
  may not receive `/dev/ppp` or `AF_PPPOX` descriptors: `deploy/selinux/lanforge_fdstore.cil` allows it.
- At shutdown the daemon asks systemd which job runs for its unit (`systemctl list-jobs`). A `restart` job leaves
  the session up: no PADT, no `SessionDown`. A `stop` (or anything unexpected) sends the PADT and drops the store
  entries, as before.
- The next process takes the descriptors back at start, sends LCP Echo-Requests with the recorded magic number and
  announces the same session (`SessionUp`) once the concentrator answers: no discovery, the interface, IPv4 address
  and the OS's DHCPv6-PD lease on it stay. A session dialled with other identity settings (interface, credentials,
  service/AC name, auth, MRU), on a changed link, or that gets no Echo-Reply within 3 s is terminated (PADT) and a
  new one dialled.
- Admin reconnects, config changes that reconnect, and `pppoe.enabled = false` end the session as before.

---

## 3. System Invariants

1. **Kernel Datapath Offloading:** Userspace code handles discovery and LCP control frames, while IP payload routing is offloaded to the Linux kernel PPP subsystem.
2. **Synchronized Session Inventory:** Active PPPoE clients immediately appear in global device inventory alongside DHCP clients.
