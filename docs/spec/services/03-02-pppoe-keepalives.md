# Sub-System Specification: PPPoE Session Keepalives (`03-02`)

## 1. Overview & Mechanics

To ensure stale or disconnected PPPoE sessions are cleaned up promptly, `lanforge-pppoe` includes an automated session keepalive worker (`crates/net/lanforge-pppoe/src/keepalive.rs`).

```
                    +--------------------------------+
                    | Keepalive Worker Loop          |
                    +--------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
 (Active Session Check)                        (LCP Echo Request Sent)
            |                                               |
            v                                               v
  Client Responds (Echo Reply)                 Client Fails to Respond (Timeout)
            |                                               |
            v                                               v
 Reset Failure Counter                          Increment Failure Counter
                                                            |
                                                            v (Exceeds Max Retries)
                                                Teardown Session & PADT Sent
                                                            |
                                                            v
                                                LanforgeEvent::Pppoe(Terminated)
```

---

## 2. Inner Workings & Teardown Protocol

### A. LCP Echo Request Polling
- Transmits LCP Echo-Request packets to all active PPPoE sessions at configurable intervals (e.g. every 10 seconds).
- Tracks outstanding request sequences per session.

### B. Timeout Detection & Retries
- Maintains per-session miss counters.
- If a client fails to reply to $N$ consecutive Echo Requests (e.g. 3 misses), the session is marked dead.

### C. Session Teardown & Cleanup
1. Sends a `PADT` (PPPoE Active Discovery Terminate) frame to the client MAC.
2. Destroys the corresponding Linux kernel `ppp` interface.
3. Releases assigned IP address back to the pool.
4. Broadcasts `LanforgeEvent::Pppoe(PppoeEvent::SessionTerminated)` to update state, database storage, and active UI dashboards.

---

## 3. System Invariants

1. **Prompt IP Reclamation:** Disconnected PPPoE sessions are reclaimed within the keepalive window, preventing IP address leakage.
2. **Event-Driven Teardown:** Session teardown triggers immediate updates across all interested subsystems without leaving zombie interface handles in the OS kernel.
