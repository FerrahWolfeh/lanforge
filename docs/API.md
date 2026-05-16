# Lanforge API Specification

This document outlines the JSON-RPC-like API provided by the `lanforged` daemon over its Unix Domain Socket (UDS) and HTTP interface.

## HybridStream Pattern

Several endpoints support a unified streaming contract used throughout the API:

- `n: Option<usize>` — number of historical entries to replay before streaming. `None` or `0` means no replay.
- `follow: bool` — if `false`, emits up to `n` entries and closes. If `true`, emits the `n` historical entries then keeps the connection open, streaming new events from the event bus as they arrive.
- Entries are always emitted oldest-first, so the stream reads chronologically.

Endpoints that follow this pattern are marked **HybridStream**.

---

## Categories

### System

| Method | Description | Streaming | Input | Output |
| :--- | :--- | :--- | :--- | :--- |
| `status` | Returns daemon uptime, version, and general health. | No | No | Status api type |
| `reload` | Soft reboot; reloads configuration from disk. | No | No | Empty on success, error on failure |
| `scan` | Triggers an immediate network scan (ARP/NDP). | No | No | Empty on success, error on failure |
| `shutdown` | Gracefully shuts down the daemon and exits. | No | No | Empty on success, error on failure |
| `log` | Retrieves entries from the system event log and optionally streams live events. Backing endpoint for the CLI `watch` command. Follows the **HybridStream** pattern. | Optional | `follow: bool`, `n: Option<usize>`, `filter: Option<Vec<EventKind>>` | HybridStream of Event entries |
| `context_dump` | Dumps full program state as JSON. **TUI-internal only — not exposed via CLI.** | Yes | `only_devices: bool`, `only_orphans: bool` | JSON Value stream |

> `filter` in `log` is evaluated server-side. The daemon retains only events whose `EventKind` is present in the filter list before emitting them. An absent or empty filter passes all events through.

---

### Devices (Discovery)

| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `list_devices` | Returns a list of all discovered and known devices. | Optional: `filter`, `vendor`, `method`, `format` | List of device api types |
| `whois` | Returns detailed information and history for a specific device. | MAC, IP, or Hostname | Device api type |
| `wol` | Triggers a Wake-on-LAN magic packet for a device. | MAC or Hostname | Empty on success, error on failure |
| `topology` | Returns the inferred physical network topology. | No | Topology api type |
| `purge` | Removes a device's data from both memory and database. Propagates deletion to all subsystems via the event bus (including removal of any associated `dev:` DNS rewrites). | MAC or Hostname | Empty on success, error on failure |

---

### Hosts (Static Configuration)

| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `host_list` | Lists all manually configured static hosts. | No | List of static host api types |
| `host_add` | Adds or updates a static host configuration (full upsert). | Static host api type | Empty on success, error on failure |
| `host_set` | Updates a single field (`hostname`, `v4`, `v6_suffix`) for an existing host entry. | MAC, field name, new value | Empty on success, error on failure |
| `host_remove` | Removes a static host configuration. | MAC or Hostname | Empty on success, error on failure |
| `host_import` | Bulk imports static device configurations. | List of static host api types | Empty on success, error on failure |
| `host_export` | Bulk exports all static host configurations. | No | List of static host api types |

> `host_add` performs a full upsert. `host_set` performs a partial field update. Both promote the device to `Static` origin.

---

### DNS Resolver

| Method | Description | Streaming | Input | Output |
| :--- | :--- | :--- | :--- | :--- |
| `dns_stats` | Returns performance and state counters of the DNS resolver. | No | No | DNS stats api type |
| `dns_analytics` | Returns top domains, top clients, query rates, and protocol stats. | No | `limit: Option<usize>` | DNS analytics api type |
| `dns_query` | Performs a diagnostic DNS resolution via the daemon. Supports automatic PTR reverse lookup formatting when an IP address is provided. | No | Domain name or hostname (PTR), optional record type | DNS query result api type |
| `dns_query_log` | Retrieves or streams the DNS query history. Follows the **HybridStream** pattern. | Optional | `follow: bool`, `n: Option<usize>`, `client: Option<String>` | HybridStream of DNS query log entry api types |
| `dns_upstreams` | Returns health and performance statistics for all configured upstream resolvers. | No | No | List of DNS upstream status api types |
| `dns_rewrite_list` | Returns all DNS rewrite rules. | No | No | List of DNS rewrite rule api types |
| `dns_rewrite_add` | Adds a new DNS rewrite rule or updates an existing one. A, AAAA, and CNAME rules for the same domain follow individual merging rules (see note). | No | DNS rewrite rule api type | Empty on success, error on failure |
| `dns_rewrite_remove` | Removes a DNS rewrite rule by ID. | No | Rule ID | Empty on success, error on failure |
| `dns_rewrite_clear` | Removes all DNS rewrite rules. | No | No | Empty on success, error on failure |
| `dns_rewrite_import` | Bulk imports DNS rewrite rules, additively merging with existing rules if the same domain exists. | No | List of DNS rewrite rule api types | Empty on success, error on failure |
| `dns_rewrite_export` | Bulk exports all DNS rewrite rules. | No | No | List of DNS rewrite rule api types |

> **`dev:` rewrites:** The `answer` field of a rewrite rule accepts the special prefix `dev:<hostname>`. This creates a dynamic rewrite resolved by `lanforge-dns` against the current known addresses of the named device. The rewrite is automatically updated whenever the device's IP changes (via event bus propagation from `lanforge-core`), and is removed when the device is purged. For `dev:` entries, the daemon enriches the returned rewrite rule objects with their currently resolved IP addresses (`resolved_ips`), allowing clients to display live target addresses without secondary L1 requests.
>
> **Merging rules:** Separate A and AAAA rules for the same domain are allowed. CNAME rules require that no other CNAME exists for that domain (one CNAME per domain).

---

### DNS Cache

| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `dns_cache_flush` | Clears all entries from the DNS cache. | No | Empty on success, error on failure |
| `dns_cache_dump` | Lists all current entries in the DNS cache. | No | List of DNS cache entry api types |
| `dns_cache_stats_ext` | Returns in-depth cache statistics and memory usage. | No | DNS cache stats api type |

---

### DNS Adblock (Filter)

| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `dns_adblock_status` | Current filter status (enabled, size, active timer if any). | No | DNS adblock status api type |
| `dns_adblock_set` | Toggles the adblocker on or off, optionally for a duration (see note). | `enabled: bool`, `duration_secs: Option<u64>` | Empty on success, error on failure |
| `dns_adblock_reload` | Triggers a reload of all blocklists and allowlists from their source URLs. | No | Empty on success, error on failure |
| `dns_adblock_urls` | Lists configured source URLs for blocklists and allowlists. | No | List of DNS adblock URL api types |
| `dns_adblock_url_add` | Adds a new source URL for blocklists or allowlists. | DNS adblock URL api type | Empty on success, error on failure |
| `dns_adblock_url_remove` | Removes a source URL. | DNS adblock URL api type | Empty on success, error on failure |
| `dns_adblock_allowlist` | Lists all domains currently in the allowlist. | No | List of allowlist entry api types (id, domain) |
| `dns_block` | Persistently blocks a domain (rewrite to `0.0.0.0`). | Domain name | Empty on success, error on failure |
| `dns_allow` | Adds a domain to the allowlist (bypasses all filters). | Domain name | Empty on success, error on failure |
| `dns_unallow` | Removes a domain from the allowlist. | Domain name or allowlist entry ID | Empty on success, error on failure |

> **`dns_adblock_set` timer semantics:**
> - Calling with `enabled: true` immediately enables adblocking and cancels any active disable timer.
> - Calling with `enabled: false` and a `duration_secs` always resets to a fresh countdown with the new value, overwriting any previous timer.
> - Calling with `enabled: false` and `duration_secs: None` disables adblocking permanently (no timer).

---

### DHCP

| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `leases` | Lists all active DHCPv4/v6 leases. | `count: bool` | List of DHCP lease api types |
| `dhcp_pools` | Returns utilization statistics for all DHCP pools. | No | DHCP pool stats api type |
| `lease_renew` | Forces a lease renewal for a specific device. | MAC or Hostname, `target: Option<LeaseTarget>` (V4/V6/Both) | Empty on success, error on failure |
| `lease_release` | Forces a lease release for a specific device. | MAC or Hostname, `target: Option<LeaseTarget>` (V4/V6/Both) | Empty on success, error on failure |

---

### Database

| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `db_vacuum` | Performs a VACUUM operation on the SQLite database. | No | Empty on success, error on failure |
| `db_prune` | Prunes old history and log entries based on retention policy. | No | Empty on success, error on failure |
| `db_log_clean` | Clears the transient system event log from the database. | No | Empty on success, error on failure |
| `db_reset` | Wipes the entire database. **DANGEROUS.** | No | Empty on success, error on failure |

---

### Auth (UDS Only)

All endpoints in this section are restricted to local UDS connections. API key generation and management must originate from a local session to prevent external RPC-based attacks.

| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `ak_generate` | Generates a new API token. **UDS-only.** | Token name | API token api type (includes secret, shown once) |
| `ak_delete` | Deletes an existing API token. | API token ID or name | Empty on success, error on failure |
| `ak_renew` | Regenerates an API token (deletes old, creates new). | API token ID or name | API token api type (new secret, shown once) |
| `ak_list` | Lists all API tokens (metadata only — no secret keys). | No | List of API token api types |
| `ak_validate` | Validates a provided API token. Used by the CLI `login` flow over HTTP. | API token string | Boolean (true if valid) |
