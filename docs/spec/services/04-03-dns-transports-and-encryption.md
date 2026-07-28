# Sub-System Specification: DNS Transports & Encryption (`04-03`)

## 1. Overview & Multi-Transport Architecture

`lanforge-dns` supports concurrent execution of multiple DNS transport listeners under `crates/net/lanforge-dns/src/server/transport/`.

```
                    +------------------------------------+
                    |        lanforge-dns Server         |
                    +------------------------------------+
                      /          |            |         \
                     /           |            |          \
                    v            v            v           v
               +--------+   +--------+   +--------+   +--------+
               |  UDP/  |   |  DoT   |   |  DoH   |   |  DoQ   |
               | TCP 53 |   | (853)  |   | (443)  |   | (853)  |
               +--------+   +--------+   +--------+   +--------+
                    \            |            |           /
                     \           |            |          /
                      v          v            v         v
                    +------------------------------------+
                    |    Unified DNS Pipeline Engine     |
                    +------------------------------------+
```

---

## 2. Supported Transport Protocols

### A. Standard UDP / TCP Port 53 (`service.rs`)
- **UDP Worker:** High-throughput socket worker handling standard unencrypted client queries.
- **TCP Worker:** Stream-based worker handling large payloads, EDNS0 extensions, or zone transfers.

### B. DNS over TLS (DoT) (`dot.rs`, `tls.rs`)
- **Port:** 853.
- **Mechanism:** Wraps DNS wire format in TLS sessions (`tokio-rustls`). Provides encrypted DNS transport to prevent eavesdropping and tampering on local or WAN segments.

### C. DNS over HTTPS (DoH) (`doh.rs`)
- **Port:** 443 (or custom HTTP ports).
- **Mechanism:** Exposes HTTP/2 and HTTP/3 GET/POST endpoints (`/dns-query`) accepting `application/dns-message`. Compatible with modern web browsers and mobile devices.

### D. DNS over QUIC (DoQ) (`doq.rs`)
- **Port:** 853 (UDP).
- **Mechanism:** Implements RFC 9250 DNS over QUIC streams. Eliminates head-of-line blocking inherent to TCP and offers ultra-fast TLS 1.3 handshake negotiation.

---

## 3. System Invariants

1. **Protocol Feature Parity:** Regardless of whether a query enters via UDP 53, DoH, DoT, or DoQ, it traverses the exact same DNS pipeline, benefiting from identical AdBlock rules, local DHCP host matching, and telemetry.
2. **Zero Head-of-Line Blocking:** DoQ and DoH HTTP/2+ listeners allow multiplexed stream processing, preventing a single slow query from delaying subsequent queries.
