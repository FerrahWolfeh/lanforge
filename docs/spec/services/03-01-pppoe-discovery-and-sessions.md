# Sub-System Specification: PPPoE Discovery & Session Negotiation (`03-01`)

## 1. Overview

How `lanforge-pppoe` (a PPPoE **client**, see `03-pppoe-service.md`) gets from a WAN link to a configured `pppN`,
and how a live session survives a daemon restart.

```
 wait for carrier ─► terminal probe ─► PADI ─► PADO ─► PADR ─► PADS        (§A, discovery/)
                                                              │
                                    LCP ─► PAP / CHAP-MD5 ─► IPCP + IPv6CP  (§B, §C)
                                                              │
                         /dev/ppp unit + channel ─► ppp0 configured ─► SessionUp
                                                              │
                         session kept in systemd's fd store (§D)
```

---

## 2. Processing Stages

### Pre-dial checks (`service.rs`)
- **Carrier:** the WAN interface (or its VLAN parent) must report carrier in sysfs; until then the state is
  `WaitingForCarrier`, checked every second.
- **Terminal probe** (optional, `terminal_probe`): an ARP probe to the ONT/modem. A soft gate: discovery waits up
  to `max_wait_secs` for a reply, then dials anyway. Its result later tells an upstream failure (terminal answers)
  from a local one (`TerminalUnreachable`) when the keepalive gives up.

### A. Discovery (`discovery/`, RFC 2516 §5)
- **PADI** is broadcast with the Service-Name tag (`service_name`, empty = any) and a Host-Uniq tag; re-sent up to
  `discovery_padi_retries` times, `discovery_padi_timeout_secs` apart.
- **PADO** is accepted only with our Host-Uniq; with `ac_name` set, offers from other ACs are ignored. Its
  AC-Cookie is echoed back.
- **PADR** carries Service-Name, Host-Uniq and the AC-Cookie; the **PADS** (matching Host-Uniq, within 3 s) gives
  the session ID.
- **Half-open sessions:** if discovery hands out the (AC, session ID) of a session that just went silent (LCP
  opened, no CHAP Challenge), it is terminated (`StaleSession`, PADT) instead of negotiated; refused once only, as
  some ACs always give the same ID to the same MAC.

### B. LCP & Authentication (`lcp.rs`, `auth.rs`; RFC 1661, 1334, 1994)
- **LCP:** our Configure-Request carries MRU (`mru`) and a random Magic-Number; restart timer 3 s, overall deadline
  15 s. A Nak'd MRU is adopted. From the peer we accept MRU, Magic-Number, and the configured auth protocol; a
  different auth protocol is Nak'd with ours (CHAP-MD5 or PAP), unknown options are rejected. Up to 8 early
  auth frames (a Challenge arriving before our side is Opened) are kept for the auth phase.
- **CHAP-MD5:** every Challenge is answered (including re-sent ones); only Success/Failure for the last answered
  Identifier ends the phase. The first Challenge must arrive within 5 s (`NoChallenge` otherwise: an AC still
  tearing down the previous session).
- **PAP:** Authenticate-Request re-sent every 3 s with a new Identifier until Ack/Nak.
- One overall deadline of 20 s (a slow RADIUS behind the AC). An explicit reject is `AuthFailed` (published as
  `PppoeEvent::AuthFailed`), silence is `AuthTimeout`. LCP Echo-Requests are answered during the phase.

### C. IPCP / IPv6CP & Kernel Handoff (`ipcp.rs`, `kernel/`)
- **IPCP** (RFC 1332, 1877) and **IPv6CP** (RFC 5072) run concurrently. IPCP asks for `0.0.0.0` plus primary and
  secondary DNS (options 129/131) and takes the Nak'd values; IPv6CP proposes an interface ID derived from the WAN
  MAC (EUI-64). The session needs at least one of the two; a missing peer IPv4 address falls back to ours.
- **Handoff** (`kernel/ppp_dev.rs`): `/dev/ppp` → `PPPIOCNEWUNIT` (the unit, `pppN`); `PPPIOCGCHAN` on the
  connected `AF_PPPOX` socket; a second `/dev/ppp` → `PPPIOCATTCHAN` + `PPPIOCCONNECT` (the channel, joined to the
  unit); `PPPIOCSMRU`, `PPPIOCSFLAGS`. From then on control frames (LCP echo) travel on the channel descriptor and
  IP payload stays in the kernel. The `AF_PPPOX` socket must stay open: closing it unbinds the channel.
- **Interface setup** (`kernel/mod.rs`): IPv6 enabled with `accept_ra = 2` (RAs accepted although forwarding is
  on, for the OS's DHCPv6-PD/SLAAC), `rp_filter = 2`, TSO/GSO off; MTU = negotiated MRU, link up; IPv4 /32 with the
  peer address, default route via the peer; IPv6 link-local (no DAD) with the peer's, IPv6 default route via it.
- Then `SessionUp` is published and the keepalive starts (`03-02`).

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
  new one dialled. A record that comes back without its descriptors (refused by the store) ends its session with
  a PADT the same way.
- The stored copies also let a crash (`Restart=on-failure`) or a restarted service task take the session over.
- Admin reconnects, config changes that reconnect, and `pppoe.enabled = false` end the session as before.

---

## 3. System Invariants

1. **Client only:** the stages above dial an AC; lanforge never answers PADI/PADR.
2. **Kernel data path:** userspace handles discovery and PPP control frames; IP payload is routed by the kernel
   PPP subsystem from the handoff on.
3. **Identity decides reuse:** a session (fresh or kept) always runs with the identity settings it was dialled
   with; a change of them reconnects.
4. **No half-open sessions left behind:** every session this side abandons gets a PADT, whether it ends live, is
   refused as stale, or is not taken over after a restart.
