# Sub-System Specification: PPPoE Session Keepalive (`03-02`)

## 1. Overview

Once the session is up, `run_keepalive` (`crates/net/lanforge-pppoe/src/keepalive.rs`) watches the one live
session of the PPPoE client until it ends, and decides how it ended. It runs on the `/dev/ppp` channel (PPP
control frames) and the discovery socket (PADT), next to the RA listener that follows the ISP's IPv6 resolvers
(`wan_dns.rs`).

```
 every lcp_echo_interval_secs ─► Echo-Request (our magic) ─► missed += 1
 Echo-Reply                   ─► missed = 0
 missed > lcp_echo_max_failures ─► terminal probe ─► KeepAliveTimeout | TerminalUnreachable
 LCP Terminate-Request        ─► Terminate-Ack ─► LcpFailed
 PADT from the AC             ─► PadtReceived (no PADT back)
 config change / shutdown     ─► Hot: retime in place | Reconnect/Rebind: ConfigUpdated | disabled | Shutdown
```

---

## 2. Inner Workings

### A. LCP Echo (RFC 1661 §5.8)
- Echo-Requests carry our LCP Magic-Number, every `lcp_echo_interval_secs` (default 20 s; `0` sends none). The
  first goes out one period after the session comes up.
- Any Echo-Reply resets the miss count. The AC's own Echo-Requests are answered with our magic number.
- Unknown PPP protocols get a Protocol-Reject; IP frames seen on the control channel are ignored.

### B. Failure Detection
- When the misses exceed `lcp_echo_max_failures` (default 5; `0` never gives up), the session ends. With the
  terminal probe enabled, an ARP probe to the ONT/modem classifies the failure: terminal answers →
  `KeepAliveTimeout` (upstream), no answer → `TerminalUnreachable` (local hardware or cable).
- An LCP Terminate-Request is acknowledged and ends the session.
- A PADT from the AC matching the session (AC MAC, session ID) ends it (RFC 2516 §5.5); no PADT is sent back. A
  broken discovery socket only stops the PADT watch; LCP echo still detects a dead session.

### C. Configuration While Up
- `Hot` changes of the echo interval/threshold retime the keepalive in place. `Reconnect`/`Rebind` changes, or
  `enabled = false`, end the session (`ConfigUpdated` / `ConfigDisabled`). A daemon shutdown ends the watch
  (`Shutdown`).

### D. Teardown (`service.rs`, `teardown_session`)
1. PADT (three frames) to the AC, unless the AC ended the session or `send_padt_on_shutdown = false`; a daemon
   restart that hands the session over (03-01 §D) sends none.
2. The kernel link goes away with the session's descriptors (the `ppp` unit is destroyed when its last
   descriptor closes); the fd-store copies are released.
3. The status is cleared and `SessionDown { reason }` published once.
4. The service waits the reconnect delay (03 §2) and dials again.

---

## 3. System Invariants

1. **One session, one watch:** the keepalive serves the client's single live session; there is no per-client
   table.
2. **Silence is detected:** a session whose AC stopped answering ends within roughly
   `lcp_echo_interval_secs × (lcp_echo_max_failures + 1)`.
3. **No zombie links:** every end of the watch goes through `teardown_session`, which releases the kernel link
   and pairs the `SessionDown` with its `SessionUp`.
