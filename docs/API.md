# Lanforge API Specification

This document outlines the JSON-RPC-like API provided by the `lanforged` daemon over its Unix Domain Socket (UDS).

## Categories

### System
| Method | Description | Streaming |
| :--- | :--- | :--- |
| `status` | Returns daemon uptime, version, and general health. | No |
| `reload` | Soft reboot; reloads configuration from disk. | No |
| `scan` | Triggers an immediate network scan (ARP/NDP). | No |
| `shutdown` | Gracefully shuts down the daemon and exits. | No |
| `watch` | Streams all events from the internal event bus. | Yes |
| `context_dump` | Streams the full program state (used by TUI). | Yes | (this one is quite dangerous due to constant state locking, we will plan what to do with it later)

### Devices (Discovery)
| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `list_devices` | Returns a list of all discovered and known devices. | No | List of device api types |
| `whois` | Returns detailed information and history for a specific MAC/IP/Hostname. | MAC, IP or Hostname | Device api type |
| `wol` | Triggers a Wake-on-LAN magic packet for a device. | MAC or Hostname | Empty on success, error on failure |
| `topology` | Returns the inferred physical network topology. | No | Topology api type |
| `purge` | Removes a device's data from both memory and database. | MAC or Hostname | Empty on success, error on failure |

### Hosts (Static Configuration)
| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `host_list` | Lists all manually configured static hosts. | No | List of static host api types |
| `host_add` | Adds or updates a static host configuration. | Static host api type | Empty on success, error on failure |
| `host_remove` | Removes a static host configuration. | MAC or Hostname | Empty on success, error on failure |
| `host_import` | Bulk imports static device configurations using API types. | List of static host api types | Empty on success, error on failure |

### DNS Resolver
| Method | Description | Streaming | Input | Output |
| :--- | :--- | :--- | :--- | :--- |
| `dns_stats` | Returns performance and state counters of the DNS resolver. | No | No | DNS stats api type
| `dns_analytics` | Returns top domains, top clients, query rates, and protocol stats. | No | No | DNS analytics api type
| `dns_query` | Performs a diagnostic DNS resolution via the daemon and returns a result (A, AAAA, etc.). | No | Domain name or hostname (PTR) | DNS query result api type
| `dns_query_log` | Returns/streams the DNS query history. | Optional - fetches 20 entries by default and up to 1000 max | boolean for stream, optional initial amount to fetch | EventBus stream of dns query events or up to 1000 stored dns query events api type 
| `dns_rewrites` | Returns all DNS rewrite rules. | No | No | List of DNS rule api types
| `dns_rewrite_add` | Adds a new DNS rewrite rule or updates an existing similar rule (separate A and AAAA rules for the same domain are allowed, CNAME rules require that there is only one) | No | DNS rewrite rule api type | Empty on success, error on failure
| `dns_rewrite_remove`| Removes a DNS rewrite rule. | No | DNS rule id | Empty on success, error on failure
| `dns_rewrite_clear` | Removes all DNS rewrite rules. | No | No | Empty on success, error on failure
| `dns_rewrite_import`| Bulk imports DNS rewrite rules. (additively updates existing rewrites if the same domain exists) | No | List of DNS rule api types | Empty on success, error on failure
| `dns_rewrite_export`| Bulk exports DNS rewrite rules. | No | No | List of DNS rule api types

### DNS Cache
| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `dns_cache_flush` | Clears all entries from the DNS cache. | No | No |
| `dns_cache_dump` | Lists all current entries in the DNS cache with filtering support. | No | List of DNS cache api types
| `dns_cache_stats_ext`| Returns in-depth cache statistics and memory usage. | No | DNS cache stats api type |

### DNS Adblock (Filter)
| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `dns_adblock_status`| Current filter status (enabled, size, timers). | No | DNS adblock status api type |
| `dns_adblock_set` | Toggles the adblocker on or off (optionally for a duration). | Boolean and optional duration | Empty on success, error on failure
| `dns_adblock_reload`| Triggers a reload of all blocklists and allowlists. | No | Empty on success, error on failure |
| `dns_adblock_urls` | Lists configured source URLs for blocklists/allowlists. | No | List of DNS adblock url api types |
| `dns_adblock_url_add`| Adds a new source URL for blocklists/allowlists. | DNS adblock url api type | Empty on success, error on failure |
| `dns_adblock_url_remove`| Removes a source URL. | DNS adblock url api type | Empty on success, error on failure |
| `dns_block` | Persistently blocks a domain (via rewrite to 0.0.0.0). | Domain name | Empty on success, error on failure |
| `dns_allow` | Adds a domain to the allowlist (bypass filters). | Domain name or id | Empty on success, error on failure |
| `dns_unallow` | Removes a domain from the allowlist. | Domain name or id | Empty on success, error on failure |

### DHCP
| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `leases` | Lists all active DHCPv4/v6 leases. | No | List of DHCP lease api types |
| `dhcp_pools` | Returns utilization statistics for all DHCP pools. | No | DHCP pool stats api type |
| `lease_renew` | Forces a lease renewal for a specific MAC. | MAC or Hostname | Empty on success, error on failure |
| `lease_release` | Forces a lease release for a specific MAC. | MAC or Hostname | Empty on success, error on failure |

### Database
| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `db_vacuum` | Performs a VACUUM operation on the database. | No | Empty on success, error on failure |
| `db_prune` | Prunes old history and log entries based on retention policy. | No | Empty on success, error on failure |
| `db_reset` | Wipes the database (DANGEROUS). | No | Empty on success, error on failure |

### Auth (UDS Only)
| Method | Description | Input | Output |
| :--- | :--- | :--- | :--- |
| `ak_generate` | Generates a new API token for HTTP auth. | No | API token api type |
| `ak_delete` | Deletes an existing API token. | API token id or name | Empty on success, error on failure |
| `ak_renew` | Recreates api token (by deleting and generating a new one). | API token id or name | API token api type |
| `ak_list` | Lists all API tokens. | No | List of API token api types (display only names, empty keys) |
