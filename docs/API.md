# Lanforge RPC API Specification

This document specifies the JSON-RPC interface implemented by the `lanforged` daemon. The RPC contract is defined in the `LanforgeRpc` trait (`lanforge-api`) and is exposed locally over Unix Domain Sockets (UDS) and remotely via the HTTP/REST gateway (`lanforge-http`).

---

## 1. Streaming Contract (`HybridStream`)

Endpoints supporting event streaming implement the **HybridStream** contract:
- `n: Option<usize>` — Number of historical entries to replay before streaming. `None` or `0` means no historical replay.
- `follow: bool` — If `false`, emits up to `n` entries and closes. If `true`, replays `n` historical entries and keeps the stream open, broadcasting new events from the `EventBus` as they occur.
- Entries are always transmitted oldest-first (chronologically).

---

## 2. API Method Reference

### System & Daemon Management

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `status` | None | `StatusResponse` | Full router status (uptime, resources, active interfaces, database vitals). |
| `service_banners` | None | `ServiceBannersResponse` | Real-time status banners and metrics from all registered background services. |
| `service_control` | `id: String`, `action: ServiceAction` | `SimpleSuccess` | Controls a background service (`Start`, `Stop`, `Restart`). |
| `reload` | None | `SimpleSuccess` | In-place configuration reload across active services. |
| `shutdown` | None | `SimpleSuccess` | Gracefully shuts down the router daemon. |
| `log` | `follow: bool`, `n: Option<usize>`, `filter: Option<Vec<EventKind>>` | `Stream<Event>` | Retrieves system event history and optionally streams live events. |
| `system_setup_status` | None | `SetupStatusResponse` | Checks onboarding completion and network hardware readiness. |
| `system_setup` | `payload: SetupPayload` | `SetupResponse` | Completes initial first-run router provisioning. |
| `system_config_export` | None | `SystemConfigExport` | Exports entire database configuration (hosts, DNS, tokens, pools). |
| `system_config_import` | `config: SystemConfigExport` | `SystemConfigImportResponse` | Bulk imports system configuration into the database. |
| `context_dump` | `only_devices: bool`, `only_orphans: bool` | `serde_json::Value` | Diagnostic state inspection dump. |

---

### Device Discovery & Inventory

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `list_devices` | `query: DeviceListQuery` | `DevicesResponse` | Lists discovered network devices with pagination and filters. |
| `whois` | `target: String` (MAC, IP, hostname) | `WhoisResponse` | Returns detailed identity, lease history, and SLAAC addresses. |
| `wol` | `target: String` (MAC or hostname) | `SimpleSuccess` | Dispatches a Wake-on-LAN Ethernet magic packet. |
| `purge` | `mac: MacAddr` | `SimpleSuccess` | Removes a device from active state and storage, clearing dynamic DNS mappings. |
| `transient_host_list` | None | `TransientHostsResponse` | Lists transient discovered hostnames pending static promotion. |

---

### Static Host Reservations

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `host_list` | None | `HostsResponse` | Lists all static host reservations. |
| `host_add` | `entry: HostConfigEntry` | `SimpleSuccess` | Creates or updates a static host reservation. |
| `host_set` | `mac: MacAddr`, `field: String`, `value: String` | `SimpleSuccess` | Updates a specific field (`hostname`, `v4`, `v6_suffix`) on a host. |
| `host_remove` | `mac: MacAddr` | `SimpleSuccess` | Deletes a static host reservation. |
| `host_import` | `hosts: Vec<HostConfigEntry>` | `SimpleSuccess` | Bulk imports static host configurations. |

---

### DHCPv4 & DHCPv6

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `leases` | `count: bool` | `LeasesResponse` | Returns active DHCPv4 and DHCPv6 leases with lease expiration timestamps. |
| `dhcp_pools` | None | `DhcpPoolsResponse` | Returns utilization metrics for all configured dynamic pools. |
| `dhcp_options` | None | `DhcpOptionsResponse` | Inspects global DHCP options (PXE boot, DNS, NTP, custom codes). |
| `update_dhcp_options` | `options: DhcpOptionsConfig` | `SimpleSuccess` | Updates global DHCP options in-place. |
| `dhcp_pools_config` | None | `DhcpPoolsConfigResponse` | Returns pool configuration definitions (IPv4/IPv6 ranges). |
| `update_dhcp_pools_config` | `v4_pools: Vec<Dhcpv4Pool>`, `v6_pools: Vec<Dhcpv6Pool>` | `SimpleSuccess` | Updates address assignment pools. |
| `dhcp_reconcile` | None | `DhcpReconcileResponse` | Reconciles lease state against current active interfaces. |
| `lease_renew` | `mac: MacAddr`, `target: Option<LeaseTarget>` | `SimpleSuccess` | Forces lease renewal for a client (`V4`, `V6`, or `Both`). |
| `lease_release` | `mac: MacAddr`, `target: Option<LeaseTarget>` | `SimpleSuccess` | Releases an active lease allocation. |

---

### DNS Resolver & Filtering

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `dns_stats` | None | `DnsStatsResponse` | Resolver performance counters (queries, cache hits, blocks). |
| `dns_analytics` | `limit: Option<usize>`, `client: Option<String>` | `DnsAnalyticsResponse` | Top queried domains, top clients, and query type trends. |
| `dns_query` | `name: String`, `record_type: Option<DnsRecordType>` | `DnsQueryResponse` | Diagnostic DNS query through the local resolver engine. |
| `dns_query_log` | `follow: bool`, `n: Option<usize>`, filters... | `DnsQueryLogResponse` | Retrieves or streams query audit logs (**HybridStream**). |
| `dns_upstreams` | None | `DnsUpstreamsResponse` | Health, latency, and status of configured upstream resolvers. |
| `dns_upstream_add` | `addr: SocketAddr`, `protocol: UpstreamProtocol`, `domain: Option<String>` | `SimpleSuccess` | Adds an upstream forwarding resolver (UDP, DoT, DoQ, DoH). |
| `dns_upstream_remove` | `addr: SocketAddr`, `protocol: UpstreamProtocol`, `domain: Option<String>` | `SimpleSuccess` | Removes an upstream forwarding resolver. |
| `dns_rewrites` | None | `DnsRewritesResponse` | Lists local DNS rewrite rules (including dynamic `dev:` and `srv:`). |
| `dns_rewrite_add` | `rule: RewriteRule` | `SimpleSuccess` | Adds or updates a local DNS rewrite rule. |
| `dns_rewrite_remove` | `id: i64` | `SimpleSuccess` | Deletes a DNS rewrite rule by ID. |
| `dns_rewrite_clear` | None | `SimpleSuccess` | Clears all local DNS rewrite rules. |
| `dns_rewrite_import` | `rules: Vec<RewriteRule>` | `SimpleSuccess` | Bulk imports DNS rewrite rules. |
| `dns_rewrite_export` | None | `DnsRewritesResponse` | Bulk exports DNS rewrite rules. |
| `dns_reverse_resolver_add` | `subnet: String`, `resolver_uri: String` | `SimpleSuccess` | Registers subnet reverse lookup routing. |
| `dns_reverse_resolver_remove` | `subnet: String` | `SimpleSuccess` | Removes a subnet reverse resolver. |
| `dns_reverse_resolver_list` | None | `DnsReverseResolversResponse` | Lists subnet reverse lookup routing rules. |

---

### DNS Cache & Adblock

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `dns_cache_dump` | `limit: Option<usize>`, `offset: Option<usize>`, `q: Option<String>`, `kind: Option<DnsRecordType>` | `DnsCacheResponse` | Inspects cached DNS resource records. |
| `dns_cache_flush` | None | `SimpleSuccess` | Clears the in-memory DNS record cache immediately. |
| `dns_cache_stats_ext` | None | `DnsCacheStatsExtResponse` | Detailed cache statistics and memory utilization. |
| `dns_adblock_status` | None | `DnsAdblockStatusResponse` | Current adblocking state, list sizes, and pause timers. |
| `dns_adblock_set` | `enabled: bool`, `duration_secs: Option<u64>` | `SimpleSuccess` | Toggles adblocking on/off, optionally with an auto-resume timer. |
| `dns_adblock_config_set` | `blocking_mode`, `ip_v4`, `ip_v6`, `refresh_time` | `SimpleSuccess` | Updates sinkhole blocking mode and daily update schedule. |
| `dns_adblock_reload` | None | `SimpleSuccess` | Triggers background compilation of all filter list sources. |
| `dns_adblock_url_list` | None | `DnsAdblockUrlsResponse` | Lists configured remote filter list sources. |
| `dns_adblock_url_add` | `url: String`, `kind: AdblockUrlKind`, `format: Option<AdblockSourceFormat>` | `SimpleSuccess` | Adds a remote blocklist/allowlist source URL. |
| `dns_adblock_url_remove` | `url: String` | `SimpleSuccess` | Removes a remote filter list source. |
| `dns_adblock_sources` | None | `DnsAdblockSourcesResponse` | Returns detailed metadata on loaded filter sources. |
| `dns_adblock_check` | `domain: String` | `AdblockCheckResponse` | Tests whether a domain is blocked and identifies matching rules. |
| `dns_allowlist` | None | `DnsAllowlistResponse` | Lists custom allowlist entries. |
| `dns_block` | `domain: String` | `SimpleSuccess` | Adds a domain to the local custom blocklist. |
| `dns_allow` | `domain: String` | `SimpleSuccess` | Adds a domain to the local custom allowlist. |
| `dns_unallow` | `domain: String` | `SimpleSuccess` | Removes a domain from the custom allowlist. |

---

### Stateful Firewall & NAT (`lanforge-nft`)

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `firewall_status` | None | `FirewallStatus` | Active firewall state, zone assignments, and rule counts. |
| `firewall_config` | None | `FirewallConfig` | Retrieves active firewall configuration (zones, rules, NAT). |
| `update_firewall_config` | `cfg: FirewallConfig` | `SimpleSuccess` | Updates firewall configuration in-place. |
| `firewall_reload` | None | `SimpleSuccess` | Recompiles and commits Netlink/nftables ruleset (~5ms). |
| `firewall_propose` | `candidate: FirewallConfig` | `FirewallValidationReport` | Dry-run validates a candidate firewall configuration. |
| `firewall_commit` | `req: FirewallCommitRequest` | `FirewallCommitResponse` | Transactional two-phase commit for candidate firewall rules. |
| `firewall_confirm` | `tx_id: String` | `SimpleSuccess` | Confirms transaction, preventing automatic rollback. |
| `firewall_abort` | `tx_id: String` | `SimpleSuccess` | Aborts pending transaction and rolls back to previous state. |

---

### PPPoE WAN Client (`lanforge-pppoe`)

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `pppoe_status` | None | `PppoeStatusResponse` | Session state, uptime, assigned WAN IP, MTU, and LCP stats. |
| `pppoe_config` | None | `PppoeConfig` | Retrieves PPPoE credentials and interface settings. |
| `update_pppoe_config` | `cfg: PppoeConfig` | `SimpleSuccess` | Updates PPPoE configuration. |
| `pppoe_reconnect` | None | `SimpleSuccess` | Cooperatively terminates session (PADT) and renegotiates. |
| `pppoe_disconnect` | None | `SimpleSuccess` | Tears down the WAN PPPoE session. |

---

### IPv6 Router Advertisements (`lanforge-ra`)

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `ra_status` | None | `RaStatusResponse` | Advertised prefixes, RDNSS, lifetime, flags (M/O), and stats. |
| `ra_config` | None | `RaServerConfig` | Retrieves Router Advertisement server configuration. |
| `update_ra_config` | `cfg: RaServerConfig` | `SimpleSuccess` | Updates Router Advertisement settings in-place. |
| `ra_trigger` | None | `SimpleSuccess` | Dispatches an immediate unsolicited Router Advertisement. |

---

### Traffic Shaping & SQM (`lanforge-traffic`)

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `traffic_status` | None | `TrafficStatusResponse` | Active queue disciplines, interface tuning, and status. |
| `traffic_config` | None | `TrafficConfig` | Retrieves SQM and NIC hardware offloading settings. |
| `update_traffic_config` | `cfg: TrafficConfig` | `SimpleSuccess` | Applies updated SQM parameters and tuning masks. |
| `traffic_telemetry` | None | `TrafficTelemetryResponse` | Live packet rates, dropped packets, and interface throughput. |

---

### Database Maintenance (`lanforge-db`)

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `db_prune` | None | `SimpleSuccess` | Prunes historical query and event logs per retention policy. |
| `db_log_clean` | None | `SimpleSuccess` | Clears transient event log records. |
| `db_reset` | None | `SimpleSuccess` | Wipes the database (**destructive action**). |

---

### Users & Authentication

| Method | Parameters | Return Type | Description |
|:-------|:-----------|:------------|:------------|
| `user_list` | None | `UserListResponse` | Lists user accounts, roles, and last login timestamps. |
| `user_create` | `payload: CreateUserPayload` | `UserResponse` | Creates user account with Argon2id hashed password. |
| `user_delete` | `username: String` | `SimpleSuccess` | Deletes a user account. |
| `user_passwd` | `username: String`, `new_password: String` | `SimpleSuccess` | Updates password for a user account. |
| `ak_list` | None | `AuthTokensResponse` | Lists active API tokens (metadata only — no secret keys). |
| `ak_generate` | `name: String`, `scopes`, `expires_at` | `AuthTokenResponse` | Generates a new API token (secret returned once). |
| `ak_delete` | `id_or_name: String` | `SimpleSuccess` | Revokes an API token. |
| `ak_renew` | `id_or_name: String` | `AuthTokenResponse` | Re-issues an API token with a fresh secret key. |
