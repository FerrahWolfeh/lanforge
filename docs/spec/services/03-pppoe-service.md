# Service Specification: PPPoE WAN Client (`lanforge-pppoe`)

## 1. Overview & System Role

`lanforge-pppoe` is the router's **PPPoE client** (RFC 2516): it dials the ISP's access concentrator (AC/BNG)
over the WAN interface, negotiates PPP (LCP, PAP/CHAP, IPCP/IPv6CP) in userspace, and hands the data path to the
Linux kernel (`ppp_generic` + `pppoe`), which then routes IP packets through `pppN` without userspace involvement.
It serves no PPPoE clients itself.

```
 wan0 carrier ─► terminal probe (ARP, optional) ─► PADI ─► PADO ─► PADR ─► PADS     (03-01 §A)
                                                                     │
                                       LCP ─► PAP / CHAP-MD5 ─► IPCP + IPv6CP         (03-01 §B, §C)
                                                                     │
                                       kernel handoff: /dev/ppp unit + channel ─► ppp0 configured
                                                                     │
                       SessionUp ─► keepalive (LCP echo, PADT watch, RA RDNSS)        (03-02)
                                                                     │
                       session end ─► PADT (unless the AC ended it) ─► SessionDown ─► backoff ─► redial
```

The OS, not lanforge, runs DHCPv6-PD on `ppp0` (e.g. systemd-networkd); lanforge only prepares the link for it
(`accept_ra = 2`, IPv6 link-local from IPv6CP).

---

## 2. Lifecycle, Configuration & Events

- **Service:** `PppoeService<H: PppoeHost = KernelHost>` (`service.rs`), `AsyncService` under the supervisor.
  Depends on `interfaces` (`Requires`, `LossPolicy::Continue`): an interface flap never drops the session.
  Condition: `pppoe.enabled` and the WAN link present (`ctx.wan_link_wait`), otherwise `Inactive(Dormant)`.
- **Host seam:** `PppoeHost` (`host.rs`) holds every machine operation (interface lookup, carrier, `/dev/ppp`,
  kernel handoff, RA listener, session keeper). Rootless tests inject a stand-in and an inert `PppoeTransport`.
- **Live config:** read through `ctx.config_subscription::<PppoeConfig>()`. `ConfigSection::classify`:
  - `wan_iface` → `Rebind`; `username`, `password`, `service_name`, `ac_name`, `auth`, `mru` → `Reconnect`
    (PADT and redial with the new values);
  - everything else (LCP echo timers, reconnect delay, PADT on shutdown, PADI retries/timeout, terminal probe,
    nftables options) → `Hot`, applied without touching the session.
- **Admin control:** `ServiceCommand::Restart` reconnects in place (PADT, new discovery); `Stop` ends the session
  (PADT) and the task. Other commands (dependency notifications) never touch the session.
- **Events (`LanforgeEvent::Pppoe`):** `SessionUp` (interface, AC, session ID, MRU, IPv4/peer, IPCP DNS),
  `SessionDown { reason }` (exactly once per `SessionUp`), `Reconnecting { attempt, next_retry_secs }`,
  `AuthFailed`, `KeepaliveWarning { consecutive_failures, max_failures }` (each missed LCP Echo-Reply) and
  `KeepaliveRestored` (replies back before the threshold), `DnsServersChanged` (the ISP's IPv6 resolvers from RAs). Consumers: firewall (WAN interface),
  DNS (ISP upstreams), traffic shaping, DHCPv4 (DNS fallback), WebUI/CLI.
- **Status:** `ctx.set_pppoe_status` (`PppoeStatusResponse`): state, addresses, AC, uptime, reconnect attempts,
  last error, terminal reachability.

### Reconnect pacing (`backoff.rs`)
- Delay = `reconnect_delay_secs` × 2^(failures−1), capped at 300 s, jittered ×[0.8, 1.2].
- A session that lived ≥ 120 s resets the failure count. A re-plugged cable, an admin restart or a reconnect-level
  config change retries at once.
- An explicit authentication reject waits at least 60 s (do not hammer RADIUS); a half-open session at the AC
  (`NoChallenge`, `StaleSession`) retries after 3 s, doubling.
- No discovery starts sooner than 6 s after this process sent a PADT: the owner's MX204 BNG hands the just-ended
  session ID out again for 2.9–6.0 s.

---

## 3. System Invariants

1. **Client only:** lanforge never answers PADI/PADR and allocates no session IDs or addresses.
2. **Kernel data path:** userspace handles discovery and PPP control frames only; IP payload never crosses it.
3. **Paired events:** every `SessionUp` is followed by exactly one `SessionDown`, except across a daemon restart
   that hands the session over (03-01 §D), where the session never went down.
4. **PADT once:** a session ended by this side gets exactly one PADT (three frames); one ended by the AC (PADT
   received) gets none (RFC 2516 §5.5).
5. **The session never blocks the LAN:** the service settles `Degraded` as soon as the physical path is known, so
   daemon readiness never waits on the ISP.
