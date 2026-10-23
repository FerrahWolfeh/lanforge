# Lanforge HTTP API — Specification

The HTTP API powers the embedded WebUI and remote CLI administration (`lanforge --remote`).


---

## Base URL

```
https://{host}:{port}/api/v1/
```

Port is configurable in `lanforge.toml`. Default: `8088`. TLS is required in production; plaintext HTTP is allowed for local development only and should be explicitly opted-in via config.

---

## Authentication

All endpoints require a valid API token or session JWT except `POST /api/v1/auth/login`, `POST /api/v1/auth/validate`, and `GET /api/v1/auth/status`.

Authentication credentials may be provided via header or HTTP-only session cookie:

```
Authorization: Bearer <token>
Cookie: session=<token>
```

### Endpoints

- `GET /api/v1/auth/status` — Checks server authentication requirement (`auth_required`) and validates the current Bearer token/cookie if provided (`authenticated`).
- `POST /api/v1/auth/login` — Authenticates via API Token (`ak_...`) or Username/Password. Supports `"remember_me": true` (extends JWT session duration from 24 hours to 30 days). Returns a signed JWT session token and issues a `Set-Cookie: session=<token>; Path=/; HttpOnly; SameSite=Lax` header.
- `POST /api/v1/auth/validate` — Validates an existing API token or session JWT.
- `GET /api/v1/auth/me` — Returns profile information for the authenticated user (`username`, `role`).
- `POST /api/v1/auth/change-password` — Changes password for the authenticated user.

**On missing or invalid token:** `401 Unauthorized`
```json
{ "error": "Unauthorized" }
```

**UDS-only endpoints called over HTTP:** `403 Forbidden`
```json
{ "error": "This operation is only available via local socket" }
```

---

## Response Envelope

All responses use a flat JSON envelope. No `type` discriminator — HTTP status codes carry that information.

**Success with body:**
```json
{ "data": { ... } }
```

**Success with list:**
```json
{
  "data": [ ... ],
  "meta": { "total": 34, "limit": 20, "offset": 0 }
}
```

**Success with no body:** `204 No Content` — empty response, no JSON.

**Error:**
```json
{ "error": "Device not found: 00:11:22:33:44:55" }
```

Error strings come directly from the daemon — they are already user-readable.

---

## HTTP Status Codes

| Code | Meaning |
|:-----|:--------|
| `200 OK` | Successful read or action with response body |
| `204 No Content` | Successful action with no response body |
| `400 Bad Request` | Malformed request body or invalid parameters |
| `401 Unauthorized` | Missing or invalid API token |
| `403 Forbidden` | UDS-only endpoint called over HTTP |
| `404 Not Found` | Resource does not exist |
| `409 Conflict` | Constraint violation (e.g., duplicate CNAME) |
| `500 Internal Server Error` | Daemon-side failure |

---

## Pagination

Endpoints that return potentially large collections accept:

| Parameter | Type | Default | Description |
|:----------|:-----|:--------|:------------|
| `limit` | `usize` | `50` | Maximum entries to return |
| `offset` | `usize` | `0` | Number of entries to skip |

Paginated responses include a `meta` object: `total`, `limit`, `offset`.

Endpoints that support pagination are marked **Paginated** in the reference below.

---

## SSE Streaming

Endpoints that support streaming use **Server-Sent Events** (`Content-Type: text/event-stream`). Each event has a typed `event:` field and a `data:` field containing a JSON object.

```
event: DeviceOnline
id: 1718123456001
data: {"mac":"04:d9:f5:0a:25:94","hostname":"Solarium","ip":"192.168.0.10"}

event: DhcpLeaseGranted
id: 1718123456045
data: {"mac":"e0:d5:5e:e2:d4:89","ip":"192.168.0.22","expires_secs":86400}
```

The `id:` field is the event's millisecond timestamp. Clients may send the `Last-Event-ID` header on reconnect — the server resumes from that point if the event is still in the buffer. This enables reliable reconnection for both the CLI and the WebUI.

Streaming endpoints are marked **SSE** in the reference below.

---

## CORS

CORS is enabled for all `/api/v1/` routes. Allowed origins are configured in `lanforge.toml` under `[http.cors]`. For development, wildcard (`*`) is supported. For production, explicit origins should be listed.

---

## Endpoint Reference

### System

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/status` | `status` | Daemon health, services, network info |
| `POST` | `/api/v1/scan` | `scan` | Trigger immediate ARP/NDP scan |
| `POST` | `/api/v1/reload` | `reload` | Reload config from disk |
| `POST` | `/api/v1/shutdown` | `shutdown` | Graceful shutdown |
| `GET` | `/api/v1/events` | `log` | **SSE.** System event stream. See §Events. |

#### `GET /api/v1/events` — SSE

Query parameters:

| Param | Type | Description |
|:------|:-----|:------------|
| `filter` | `String` | Comma-separated `EventKind` values. Server-side filter. Absent = all events. |
| `initial` | `usize` | Replay last N events before streaming live. Default `0`. |

On connection, the server emits up to `initial` historical entries (oldest-first), then streams live events indefinitely. Each SSE `event:` field maps to an `EventKind` variant name.

---

### Devices

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/devices` | `list_devices` | **Paginated.** All discovered devices |
| `GET` | `/api/v1/devices/{target}` | `whois` | Detail for one device. `{target}` = MAC, IP, or hostname |
| `DELETE` | `/api/v1/devices/{target}` | `purge` | Remove device from memory and DB |
| `POST` | `/api/v1/devices/{target}/wol` | `wol` | Send Wake-on-LAN magic packet |
| `GET` | `/api/v1/topology` | `topology` | Inferred physical network topology |

#### `GET /api/v1/devices` — Query Parameters

| Param | Type | Description |
|:------|:-----|:------------|
| `filter` | `String` | Full-text search across hostname, MAC, IP |
| `sort` | `String` | One of: `mac`, `host`, `last-seen`, `ip`, `online` |
| `limit` | `usize` | Pagination |
| `offset` | `usize` | Pagination |

---

### Hosts

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/hosts` | `host_list` | All static host configurations |
| `POST` | `/api/v1/hosts` | `host_add` | Add or fully replace a static host (upsert) |
| `PATCH` | `/api/v1/hosts/{mac}` | `host_set` | Update a single field on an existing static host |
| `DELETE` | `/api/v1/hosts/{mac}` | `host_remove` | Remove a static host configuration |
| `GET` | `/api/v1/hosts/export` | `host_export` | Export all static hosts as JSON |
| `POST` | `/api/v1/hosts/import` | `host_import` | Bulk import static hosts from JSON body |

#### `PATCH /api/v1/hosts/{mac}` — Body

```json
{ "field": "hostname", "value": "new-hostname" }
```

Valid `field` values: `hostname`, `v4`, `v6_suffix`.

---

### DNS — Resolver

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/dns/stats` | `dns_stats` | Resolver performance counters |
| `GET` | `/api/v1/dns/analytics` | `dns_analytics` | Top domains, clients, query rates |
| `GET` | `/api/v1/dns/query` | `dns_query` | Diagnostic DNS resolution |
| `GET` | `/api/v1/dns/log` | `dns_query_log` | **Paginated** or **SSE.** DNS query history |
| `GET` | `/api/v1/dns/upstreams` | `dns_upstreams` | Upstream resolver health |

#### `GET /api/v1/dns/query` — Query Parameters

| Param | Type | Description |
|:------|:-----|:------------|
| `name` | `String` | Domain name or IP (for PTR) |
| `type` | `String` | Record type. Default: `A` |

#### `GET /api/v1/dns/log` — Query Parameters

| Param | Type | Description |
|:------|:-----|:------------|
| `client` | `String` | Filter by client IP or hostname |
| `limit` | `usize` | Entries to return (non-streaming). Default `50`, max `1000` |
| `offset` | `usize` | Pagination offset (non-streaming) |
| `follow` | `bool` | If `true`, switches to **SSE** mode. `limit` becomes the initial replay count. |

When `follow=false` (default): returns a paginated JSON response.
When `follow=true`: upgrades to SSE. Server emits `limit` historical entries (oldest-first) then streams live query log events. Each SSE event has `event: DnsQuery` and a `DnsQueryLogEntry` data payload.

---

### DNS — Cache

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/dns/cache` | `dns_cache_dump` | **Paginated.** Current cache entries. Query params: `limit`, `offset`, `q` (search), `kind` (record type) |
| `DELETE` | `/api/v1/dns/cache` | `dns_cache_flush` | Clear the DNS cache |
| `GET` | `/api/v1/dns/cache/stats` | `dns_cache_stats_ext` | In-depth cache stats and memory usage |

---

### DNS — Adblock

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/dns/adblock` | `dns_adblock_status` | Filter status, sizes, active timer |
| `PUT` | `/api/v1/dns/adblock` | `dns_adblock_set` | Enable or disable adblocking |
| `POST` | `/api/v1/dns/adblock/reload` | `dns_adblock_reload` | Re-download and reload all lists |
| `GET` | `/api/v1/dns/adblock/allowlist` | `dns_adblock_allowlist` | Entries in the allowlist |
| `POST` | `/api/v1/dns/adblock/block` | `dns_block` | Force-block a domain |
| `POST` | `/api/v1/dns/adblock/allow` | `dns_allow` | Add a domain to the allowlist |
| `DELETE` | `/api/v1/dns/adblock/allow/{target}` | `dns_unallow` | Remove from allowlist. `{target}` = domain or entry ID |
| `GET` | `/api/v1/dns/adblock/sources` | `dns_adblock_urls` | Configured blocklist/allowlist source URLs |
| `POST` | `/api/v1/dns/adblock/sources` | `dns_adblock_url_add` | Add a source URL |
| `DELETE` | `/api/v1/dns/adblock/sources` | `dns_adblock_url_remove` | Remove a source URL |

#### `PUT /api/v1/dns/adblock` — Body

```json
{ "enabled": false, "duration_secs": 3600 }
```

`duration_secs` is optional. Absent or `null` means permanent when disabling. Timer semantics match the RPC definition.

#### `POST /api/v1/dns/adblock/block` and `/allow` — Body

```json
{ "domain": "tracker.example.com" }
```

#### `DELETE /api/v1/dns/adblock/sources` — Body

```json
{ "url": "https://somehost/blocklist.txt", "kind": "blocklist" }
```

---

### DNS — Rewrites

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/dns/rewrites` | `dns_rewrite_list` | All active rewrite rules |
| `POST` | `/api/v1/dns/rewrites` | `dns_rewrite_add` | Add a rewrite rule |
| `DELETE` | `/api/v1/dns/rewrites/{id}` | `dns_rewrite_remove` | Remove a rule by ID |
| `DELETE` | `/api/v1/dns/rewrites` | `dns_rewrite_clear` | Remove all rewrite rules |
| `GET` | `/api/v1/dns/rewrites/export` | `dns_rewrite_export` | Export all rules as JSON |
| `POST` | `/api/v1/dns/rewrites/import` | `dns_rewrite_import` | Bulk import rules from JSON body |

#### `POST /api/v1/dns/rewrites` — Body

```json
{ "domain": "myserver.lan", "answer": "192.168.0.50" }
```

Or with `dev:` syntax:
```json
{ "domain": "myserver.lan", "answer": "dev:myserver" }
```

Record type is inferred server-side. `rtype` may be passed explicitly to override.

---

### DHCP

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/dhcp/leases` | `leases` | All active DHCPv4/v6 leases |
| `GET` | `/api/v1/dhcp/pools` | `dhcp_pools` | Pool utilization |
| `POST` | `/api/v1/dhcp/leases/{mac}/renew` | `lease_renew` | Force lease renewal |
| `POST` | `/api/v1/dhcp/leases/{mac}/release` | `lease_release` | Force lease release |

#### `POST /api/v1/dhcp/leases/{mac}/renew` and `/release` — Body

```json
{ "target": "V4" }
```

`target` is optional. Values: `V4`, `V6`, `Both`. Default: `V4`.

---

### Database

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `POST` | `/api/v1/db/prune` | `db_prune` | Prune old entries |
| `POST` | `/api/v1/db/log-clean` | `db_log_clean` | Clear transient event log |
| `DELETE` | `/api/v1/db` | `db_reset` | **DANGEROUS.** Wipe entire database |

---

### Users & Management

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/users` | `user_list` | List all registered user accounts |
| `POST` | `/api/v1/users` | `user_create` | Create a new user account |
| `DELETE` | `/api/v1/users/{username}` | `user_delete` | Delete a user account |
| `PUT` | `/api/v1/users/{username}/password` | `user_passwd` | Update user password |

---

### Auth

| Method | Path | RPC | Notes |
|:-------|:-----|:----|:------|
| `GET` | `/api/v1/auth/status` | — | Check auth requirement & token validity |
| `POST` | `/api/v1/auth/login` | — | Password or API token authentication -> JWT |
| `GET` | `/api/v1/auth/me` | — | Current user profile (`username`, `role`) |
| `POST` | `/api/v1/auth/change-password` | — | Change current user password |
| `GET` | `/api/v1/auth/tokens` | `ak_list` | Token metadata only, no secrets |
| `POST` | `/api/v1/auth/tokens` | `ak_generate` | **403** — UDS-only |
| `DELETE` | `/api/v1/auth/tokens/{id}` | `ak_delete` | **403** — UDS-only |
| `POST` | `/api/v1/auth/tokens/{id}/renew` | `ak_renew` | **403** — UDS-only |
| `POST` | `/api/v1/auth/validate` | `ak_validate` | Validate a token. No auth required on this route. |

#### `POST /api/v1/auth/validate` — Body

```json
{ "token": "lf_ak_7f3a9b2c4d5e6f1a..." }
```

**Response:**
```json
{ "data": { "valid": true } }
```

This route is unauthenticated alongside `/login` and `/status`. Used by CLI and WebUI to confirm token validity.

---

### Firewall & NAT

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/firewall/status` | `firewall_status` | Active firewall status and zone counters |
| `GET` | `/api/v1/firewall/config` | `firewall_config` | Active firewall configuration (zones, rules, NAT) |
| `POST` | `/api/v1/firewall/config` | `update_firewall_config` | Update firewall rules and zones in-place |
| `POST` | `/api/v1/firewall/reload` | `firewall_reload` | Trigger in-place Netlink/nftables recompile |
| `POST` | `/api/v1/firewall/propose` | `firewall_propose` | Validate a candidate firewall configuration |
| `POST` | `/api/v1/firewall/commit` | `firewall_commit` | Two-phase commit of candidate rules |
| `POST` | `/api/v1/firewall/confirm` | `firewall_confirm` | Confirm candidate transaction |
| `POST` | `/api/v1/firewall/abort` | `firewall_abort` | Abort pending transaction and rollback |

---

### PPPoE WAN Client

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/pppoe/status` | `pppoe_status` | WAN session status, IP address, uptime, LCP stats |
| `GET` | `/api/v1/pppoe/config` | `pppoe_config` | PPPoE credentials and configuration |
| `POST` | `/api/v1/pppoe/config` | `update_pppoe_config` | Update PPPoE settings |
| `POST` | `/api/v1/pppoe/reconnect` | `pppoe_reconnect` | Terminate session and redial |
| `POST` | `/api/v1/pppoe/disconnect` | `pppoe_disconnect` | Disconnect PPPoE session |

---

### IPv6 Router Advertisements

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/ra/status` | `ra_status` | Advertised prefixes, RDNSS, lifetime, flags (M/O) |
| `GET` | `/api/v1/ra/config` | `ra_config` | Router Advertisement configuration |
| `POST` | `/api/v1/ra/config` | `update_ra_config` | Update Router Advertisement settings |
| `POST` | `/api/v1/ra/trigger` | `ra_trigger` | Dispatch an immediate unsolicited RA |

---

### Traffic Shaping & SQM

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/traffic/status` | `traffic_status` | Active SQM queue disciplines and tuning state |
| `GET` | `/api/v1/traffic/telemetry` | `traffic_telemetry` | Interface packet throughput and drop counters |
| `GET` | `/api/v1/traffic/config` | `traffic_config` | Traffic shaping and hardware offload configuration |
| `POST` | `/api/v1/traffic/config` | `update_traffic_config` | Update SQM rules and interface masks |

---

### System Services & Setup

| Method | Path | RPC | Description |
|:-------|:-----|:----|:-----------|
| `GET` | `/api/v1/system/setup-status` | `system_setup_status` | Check first-run onboarding status |
| `POST` | `/api/v1/system/setup` | `system_setup` | Complete first-run setup wizard |
| `GET` | `/api/v1/system/service_banners` | `service_banners` | Real-time status banners of all services |
| `POST` | `/api/v1/system/services/{id}/control` | `service_control` | Start, stop, or restart a background service |
| `GET` | `/api/v1/system/config/export` | `system_config_export` | Bulk export database configuration |
| `POST` | `/api/v1/system/config/import` | `system_config_import` | Bulk import database configuration |


---

## Axum Implementation Notes

- Use `axum::response::sse::Sse` for all SSE endpoints.
- All route handlers receive a shared `AppState` (Arc) containing the RPC channel to the daemon's internal bus.
- Middleware stack (applied globally): CORS → auth extractor → compression → routes. Auth extractor short-circuits with `401` before reaching any handler, except for `POST /api/v1/auth/validate` which is explicitly excluded.
- `DELETE /api/v1/db` should require a `X-Confirm: wipe` header in addition to auth, as a minimal mechanical safeguard against accidental calls from scripts.
- UDS-only routes (`POST /auth/tokens`, `DELETE /auth/tokens/{id}`, `POST /auth/tokens/{id}/renew`) should be registered normally but return `403` immediately in the handler body — this way they appear correctly in any auto-generated API documentation.
