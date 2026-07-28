# Sub-System Specification: DNS Processing Pipeline (`04-01`)

## 1. Overview & Mechanics

The DNS pipeline in `lanforge-dns` (`crates/net/lanforge-dns/src/pipeline/`) processes incoming DNS wire queries through a sequential, non-blocking middleware chain.

```
                  Incoming DNS Query Context (QueryContext)
                                     |
                                     v
                  +-------------------------------------+
                  | 1. AdblockMiddleware                |
                  |    - Checks active blocklists       |
                  +-------------------------------------+
                                     | (If Allowed / Unmatched)
                                     v
                  +-------------------------------------+
                  | 2. LocalMiddleware                  |
                  |    - Matches dynamic DHCP hostnames |
                  |    - Matches static local records   |
                  +-------------------------------------+
                                     | (If Unmatched)
                                     v
                  +-------------------------------------+
                  | 3. RewriteMiddleware                |
                  |    - Applies domain rewrites/regex  |
                  +-------------------------------------+
                                     |
                                     v
                  +-------------------------------------+
                  | 4. CacheMiddleware                  |
                  |    - Serves cached responses        |
                  +-------------------------------------+
                                     | (If Miss)
                                     v
                  +-------------------------------------+
                  | 5. UpstreamMiddleware               |
                  |    - Resolves via recursive upstreams|
                  +-------------------------------------+
```

---

## 2. Middleware Components

### A. `AdblockMiddleware` (`pipeline/middleware/adblock.rs`)
- Evaluates query domain against loaded blocklists.
- If blocked, sets response code (`NXDOMAIN`, `0.0.0.0`, or `REFUSED`), flags query context as blocked, and short-circuits further processing.

### B. `LocalMiddleware` (`pipeline/middleware/local.rs`)
- Intercepts requests for local domain zones (e.g. `.lan`).
- Queries in-memory dynamic host map populated by `lanforge-dhcp` and `lanforge-pppoe` events.
- Resolves static hostname overrides.

### C. `RewriteMiddleware` (`pipeline/middleware/rewrite.rs`)
- Evaluates domain rewrite rules and regex match patterns (e.g., redirecting `*.internal` to a specific gateway IP).

### D. `CacheMiddleware` (`pipeline/middleware/cache.rs`)
- Performs lock-free in-memory lookups.
- Checks TTL validity and serves cached answers immediately on hit.

### E. `UpstreamMiddleware` (`pipeline/middleware/upstream.rs`)
- Dispatches query to configured upstream resolvers (UDP/TCP/DoH/DoT) using parallel or failover resolution strategies.

---

## 3. Dynamic Host Registration Flow

```
[ DHCP / PPPoE Service ] ---> LanforgeEvent::Dhcp / Pppoe
                                     |
                                     v
                           [ lanforge-dns Listener ]
                                     |
                                     v
                    Updates Dynamic Record Map in LocalMiddleware
                               (Atomic Swap - No Restart)
```

---

## 4. System Invariants

1. **Short-Circuit Performance:** Blocked domains or local matches immediately terminate the pipeline, bypassing cache and upstream network I/O.
2. **Atomic Record Sync:** Dynamic records learned from DHCP/PPPoE are updated via atomic memory swaps, ensuring microsecond query lookup latency.
