# Service Specification: DNS Engine & Filtering Pipeline (`lanforge-dns`, `lanforge-dns-wire`)

## 1. Overview & System Role

`lanforge-dns` is Lanforge's enterprise-grade, high-performance DNS subsystem. It acts as an authoritative local DNS server, dynamic DHCP host resolver, recursive upstream resolver, and an **integrated adblocker & domain filtering engine**.

Beyond standard UDP/TCP port 53 transport, `lanforge-dns` provides modern encrypted DNS servers:
- **DoH (DNS over HTTPS)**
- **DoT (DNS over TLS)**
- **DoQ (DNS over QUIC)**

```
 Client DNS Request (UDP/TCP 53, DoH, DoT, DoQ)
                        |
                        v
         +-----------------------------+
         |      DNS Pipeline Engine    |
         +-----------------------------+
                        |
      +-----------------+-----------------+
      |                                   |
      v                                   v
[ Middleware Pipeline ]          [ Resolver Engine ]
  1. AdBlock Middleware            1. Domain Filtering (Blocklists / Allowlists)
  2. Local Resolver Middleware     2. Custom Domain Rewriting & Regex Rules
  3. Caching Middleware            3. Dynamic DHCP/PPPoE Record Matching
  4. Upstream Forwarder            4. Multi-Strategy Recursive Resolver
                                      (Parallel / Fast-Fallback / Round-Robin)
```

---

## 2. Pipeline & Middleware Architecture (`pipeline/`)

Incoming requests pass through a modular middleware pipeline (`pipeline/middleware/`):

1. **`AdblockMiddleware` (`adblock.rs`):** Intercepts queries against loaded blocklists (e.g. ad servers, telemetry, malware domains). If matched, short-circuits the pipeline with `NXDOMAIN`, `0.0.0.0`, or custom sinkhole responses.
2. **`LocalMiddleware` (`local.rs`):** Resolves local domain zones (`.lan`), static DNS overrides, and live dynamic hostnames registered by `lanforge-dhcp` or `lanforge-pppoe`.
3. **`RewriteMiddleware` (`rewrite.rs`):** Applies domain rewriting, wildcard rules, CNAME overrides, and regex query transformations.
4. **`CacheMiddleware` (`cache.rs`):** Serves cached DNS records with TTL management and stale-while-revalidate handling.
5. **`UpstreamMiddleware` (`upstream.rs`):** Forwards unhandled queries to configured upstream recursive resolvers.

---

## 3. Integrated AdBlocker & Domain Filter (`resolver/filter/`)

Lanforge features an embedded, memory-optimized domain filtering engine (`blocklist.rs`):

- **Blocklist Sources:** Loads external blocklist files (Hosts format, AdBlock syntax, domain lists) with automated background updating.
- **Fast Matching Data Structures:** Uses trie and hash-set matching to evaluate domain queries in sub-microsecond time.
- **Per-Client / Per-Group Filtering:** Supports selective blocklists based on client IP / subnet.
- **Sinkhole Policies:** Configurable block responses: `NXDOMAIN`, `REFUSED`, `0.0.0.0`, or custom IPv6 sinkhole addresses.
- **Allowlist Overrides:** Explicit allowlists supersede blocklist rules to prevent false positives.

---

## 4. Multi-Transport Server & Encryption (`server/transport/`)

`lanforge-dns` exposes multiple transport listeners concurrently:
- **Classic UDP / TCP 53:** Low-latency standard LAN resolution.
- **DNS over TLS (DoT):** TLS-encrypted port 853 transport (`dot.rs`, `tls.rs`).
- **DNS over HTTPS (DoH):** HTTP/2 and HTTP/3 DoH endpoint serving (`doh.rs`).
- **DNS over QUIC (DoQ):** Next-generation UDP-based QUIC transport (`doq.rs`) for high-concurrency, zero-head-of-line-blocking resolution.

---

## 5. Dynamic Host Synchronization & Telemetry

- **Reactive DHCP & Device Sync:** Listens for `LanforgeEvent::Dhcp(LeaseGranted)` and `LanforgeEvent::Device(DeviceUpdated)`. Hostnames are added to the local resolver instantly without daemon reloads.
- **Query Telemetry (`telemetry/`):** Emits detailed query events (`LanforgeEvent::Dns`) containing query domain, record type, resolution source (Local, Cache, Upstream, Blocked), client IP, and latency.

---

## 6. System Invariants

1. **Integrated Adblocking:** Adblocking and domain filtering happen directly inside the DNS resolution pipeline without requiring external proxies like Pi-hole or AdGuard Home.
2. **Zero-Downtime Blocklist Reloading:** Blocklist updates compile in the background and swap atomically into the memory lookup structure.
3. **Multi-Protocol Parity:** Local DNS records, dynamic DHCP hostnames, and adblock rules apply consistently across all transport listeners (UDP, TCP, DoT, DoH, DoQ).
