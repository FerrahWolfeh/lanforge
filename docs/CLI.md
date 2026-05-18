# Lanforge CLI v3 — Implementation Blueprint

> **Purpose:** This document is a prescriptive specification for rebuilding `lanforge-cli` from scratch against the v3 API. It defines the command tree, argument signatures, display behavior, interactivity rules, and rendering details for every command. An AI or developer should be able to implement the entire CLI frontend from this document alone.

---

## 1. Architecture & Global Design

### 1.1 — Stack

- **Argument parsing:** `clap` (derive mode) with `multicall = true`.
- **Rendering engine:** `iocraft` components for all structured output (tables, cards, dashboards).
- **Terminal control:** `crossterm` (via iocraft) for color detection, terminal width.
- **Interactive prompts:** `inquire` with a custom theme matching the iocraft aesthetic.
- **Duration parsing:** `humantime` (already a project dependency). Used wherever a human-readable duration is accepted (e.g., `5m`, `1h30m`, `90s`, `2d`).
- **Error handling:** `color_eyre`. Connection failures produce a clean one-liner, never a Rust backtrace.

### 1.2 — Invocation

```
lanforge [GLOBAL FLAGS] <COMMAND> [SUBCOMMAND] [ARGS/FLAGS]
```

Running bare `lanforge` prints the help menu. Exit codes: `0` success, `1` runtime/connection error, `2` bad arguments. All exit codes are set manually via `std::process::exit`.

### 1.3 — Global Flags

| Flag | Env Var | Default | Description |
|:-----|:--------|:--------|:-----------|
| `-s, --socket <PATH>` | `LANFORGE_CONTROL_SOCKET` | `/run/lanforge/control.sock` | UDS path |
| `--remote <URL>` | `LANFORGE_REMOTE_URL` | — | Remote daemon (HTTPS). Switches to JSON/REST mode |
| `--token <TOKEN>` | `LANFORGE_TOKEN` | — | API key for remote. Falls back to `$XDG_DATA_DIR/lanforge/login.json` |
| `--no-compress` | — | `false` | Disable response compression |
| `--json` | — | `false` | Output raw API JSON. No formatting, no colors. **Ignored on streaming commands** (see §1.5). Replaces the old `query` command entirely. |
| `--no-color` | `NO_COLOR` | auto-detect | Disable ANSI colors |
| `--ascii` | — | `false` | Replace Unicode box-drawing, symbols, and emoji with ASCII equivalents |
| `-y, --yes` | — | `false` | Skip all confirmation prompts |

### 1.4 — Connection Failure

**Local Mode (UDS):**
```text
✗ Cannot connect to lanforged (socket /run/lanforge/control.sock)
  Is the daemon running? Try: systemctl status lanforge
```

**Remote Mode (HTTP):**
```text
✗ Cannot connect to lanforged at https://192.168.1.1:8080
  Reason: Connection refused (or Timeout / DNS lookup failed)
  Check the URL and your network connection.
```

Exit code `1`. Never show raw IO errors.

### 1.5 — Streaming and `--json`

Commands that open a persistent stream (`watch`, `dns log -f`) ignore the `--json` flag for formatted output. If `--json` is explicitly passed to a streaming command, the CLI switches to **newline-delimited JSON mode**: each `LanforgeEvent` is serialized to a single JSON line and written to stdout as it arrives, until the socket closes. No formatting, no color, no headers.

### 1.6 — Interactivity Contract

All commands that modify state follow the **wizard-if-missing** pattern:
- If all required arguments are provided via flags → execute immediately, no prompts.
- If required arguments are missing → launch an `inquire` interactive wizard for the missing fields.
- Destructive commands always prompt `[y/N]` unless `--yes` is passed.
- `db reset` requires **two** separate confirmations.
- **Fuzzy Filtering:** All interactive pickers (`wol`, `purge`, `lease renew/release`, `host set/remove`) utilize `inquire::Select`. `inquire::Select` provides built-in fuzzy filtering out of the box. Implementors must enable and rely on this default behavior to handle large networks effortlessly, rather than implementing custom manual filtering loops.

### 1.7 — Visual Language

**Status indicators** (replace with `[ON]`/`[OFF]`/`[S]`/`[D]` in `--ascii` mode):

| Symbol | Meaning | Color |
|:-------|:--------|:------|
| `●` | Online / Active | Green |
| `○` | Offline / Inactive | Dim grey |
| `★` | Static device | Cyan |
| `·` | Dynamic device | Dim grey |

**Feedback symbols:**
- `✓` green — success
- `✗` red — failure
- `ℹ` cyan — informational note (e.g., "will take effect on next DHCP cycle")

**API errors:** The API follows a "message, nothing, or error" model. On error, print `✗ {error_message}` in red, where `error_message` is the string from the API error response. The daemon's error strings are already user-readable; no additional wrapping or transformation is needed.

**Layout patterns:**
- **Bordered boxes** (`╭╮╰╯│`) for dashboard sections and detail cards.
- **Tables** with dim grey headers, `─` separator, then data rows.
- **Summary headers** on list commands: `TITLE · {count} · {status} · {metadata}`.

**Relative time formatting:**
- `now` — last seen under 1 minute ago.
- `{N}m` — minutes (1–59).
- `{N}h` — hours (1–23).
- `{N}d` — days (1+).
- `never` — device has never been seen online.

**Emoji in `--ascii` mode:** Emoji icons are omitted entirely. No ASCII substitute — the label text alone is sufficient.

### 1.8 — Multicall Aliases

| Alias binary | Maps to |
|:-------------|:--------|
| `wake [target]` | `lanforge wol [target]` |
| `lf-status` | `lanforge status` |
| `lf-devices [flags]` | `lanforge devices [flags]` |
| `lf-scan` | `lanforge scan` |
| `lf-topology` | `lanforge topology` |

---

## 2. Command Tree

```
lanforge
├── status                          # Dashboard
├── scan                            # Trigger NDP/ARP scan
├── reload                          # Reload daemon config from disk
├── shutdown                        # Graceful daemon shutdown
├── watch [filters] [--initial N] [--verbose] # Stream EventBus (calls log API)
├── login                           # Persist remote credentials
│
├── devices                         # List all devices (default: table view)
├── whois <target>                  # Detail card for one device
├── wol [target]                    # Wake-on-LAN (interactive picker if no target)
├── topology                        # Network topology tree
├── purge [target]                  # Delete device from memory + DB (interactive picker if no target)
│
├── host
│   ├── list                        # List static hosts
│   ├── add [mac] [--hostname] [--v4] [--v6-suffix]
│   ├── remove [target]             # Remove static host (interactive picker if no target)
│   ├── set [mac] [field] [value]   # Update hostname / IPs (interactive picker if no args)
│   ├── export <file>               # Export static hosts to pretty-printed JSON
│   └── import <file>               # Bulk import from JSON
│
├── dns
│   ├── stats                       # Resolver counters
│   ├── analytics [--limit N]       # Top domains, clients, rates
│   ├── query <name> [type]         # Diagnostic resolution
│   ├── log [-f] [-l N] [-c filter] # DNS query log (optional streaming)
│   ├── upstreams                   # Upstream server health
│   ├── cache
│   │   ├── dump                    # List cache entries
│   │   ├── flush                   # Clear cache
│   │   └── stats                   # Extended cache stats
│   ├── adblock
│   │   ├── status                  # Filter status
│   │   ├── enable                  # Turn on
│   │   ├── disable [duration]      # Turn off (optionally timed)
│   │   ├── reload                  # Re-download lists
│   │   ├── block <domain>          # Force-block domain
│   │   ├── allow <domain>          # Add to allowlist
│   │   ├── unallow <domain>        # Remove from allowlist
│   │   ├── allowlist               # Show allowlist entries
│   │   └── sources
│   │       ├── list
│   │       ├── add <url> [--kind]
│   │       └── remove <url>
│   └── rewrite
│       ├── list                    # List rewrite rules
│       ├── add <domain> <answer>   # Add rule (supports dev:<host>)
│       ├── remove <id>             # Remove by rule ID
│       ├── clear                   # Remove all (confirmation required)
│       ├── import <file>           # Bulk import
│       └── export <file>           # Bulk export
│
├── dhcp
│   ├── leases [--v4|--v6]          # Active lease table
│   └── pool                        # Pool utilization with bars
│
├── lease
│   ├── renew [target] [-6]         # Force renew (interactive picker if no target)
│   └── release [target] [-6]       # Force release (interactive picker if no target)
│
├── db
│   ├── vacuum                      # SQLite VACUUM
│   ├── prune                       # Remove zombie entries
│   ├── log-clean                   # Clear transient log DB
│   └── reset                       # FACTORY RESET (double confirm)
│
└── auth
    ├── list                        # Token names + dates (no secrets)
    ├── gen <NAME>                  # Generate token (show secret once)
    ├── del <id|name>               # Delete token
    └── renew <id|name>             # Regenerate token
```

---

## 3. Command Specifications

### 3.1 — `status`

**API:** `status`

**Purpose:** Primary dashboard. The first thing an admin runs to check system health.

**Rendering:** Four sections, each rendered as an `iocraft` bordered box:

1. **Header:** Single line above everything:
   - Format: `LANFORGE · v{version} · uptime {days}d {hours}h {minutes}m`
   - Version in white, uptime in white, separators (`·`) in dim grey.

2. **INFRASTRUCTURE** box (yellow bold title):
   - Key-value rows, labels in dim grey, values in white:
     - `Iface` — LAN interface name (e.g., `end0`)
     - `IPv4` — LAN IPv4 with CIDR (e.g., `192.168.0.1/24`)
     - `GUA Prefix` — Global Unicast prefix, or `stabilizing...` in cyan if not yet known
     - `ULA Prefix` — Unique Local prefix, or `unavailable` in dim
     - `Memory RSS` — Process memory in human units (green)

3. **SERVICES** box (yellow bold title):
   - Two groups separated by `────────── Protocols ──────────` divider (dim grey).
   - **Core services:** DB Worker, mDNS, Iface Monitor, NDP Monitor, Control API, HTTP API (if feature-enabled).
   - **Protocol services:** RA, DHCPv4, DHCPv6, DNS.
   - Each line: `● {name:<10} {state:<10} {description/metadata}`
   - `●` is green if the service is in its active/running state, red otherwise.
   - Metadata examples: `8 leases · 7414 free` for DHCPv4, `upstream udp://9.9.9.9:53` for DNS, `8 tracked · scan 0s ago` for NDP.

4. **INSIGHTS** box (yellow bold title):
   - `Devices` — `{online} / {total} online  ★{static_count}  ·{dynamic_count}`
   - `SQLite` — `{size}  at {path}` (size in cyan)
   - `Last Sync` — `{N}s ago`

5. **CAPABILITIES** box (yellow bold title):
   - Lists all capabilities with badges indicating their status:
   - `[COMPILED]` (green) vs `[ENABLED]` (cyan) vs `[DISABLED]` (dim grey).
   - E.g., `DNS [COMPILED] [ENABLED]`, `Upstream DoH [COMPILED] [DISABLED]`.

6. **Footer legend:** `★ TOML static  · CLI managed` (dim grey)

### 3.2 — `scan`

**API:** `scan`
**Display:** `✓ {message}`

### 3.3 — `reload`

**API:** `reload`
**Display:** `✓ {message}`

### 3.4 — `shutdown`

**API:** `shutdown`
**Display:** `✓ {message}`. The CLI should expect the socket to close immediately after.

### 3.5 — `watch [filters] [--initial N] [--verbose]`

**API:** `log` (HybridStream)

**Arguments:**
- `[filters]`: Optional space-separated list of `EventKind` values to include (e.g., `dhcp dns`). Sent to the server as `filter: Vec<EventKind>` — filtering is performed **server-side**.
- `--initial <N>`: Replay the last `N` events from the server-side buffer before streaming live. Maps to `n` in the HybridStream pattern.
- `-v, --verbose`: Show verbose periodic background events (e.g., background neighbor scan summaries when no new neighbors are discovered).

**Behavior:** Calls `log(follow=true, n=N, filter=[...])`. Prints `Watching for events... (Ctrl+C to stop)`, then enters an infinite loop reading `Event` entries from the stream. Exits cleanly on `UnexpectedEof`. Background periodic events like empty neighbor scan summaries are filtered out by default unless `--verbose` is passed.

**Event rendering:** Each incoming `LanforgeEvent` is matched against all known variants and sub-variants. Every variant produces a specific, human-readable one-line message with a timestamp prefix. Example output:
```
14:32:01  ● Device online        Solarium [04:d9:f5:0a:25:94]  192.168.0.10
14:32:05  ✦ DHCP lease granted   Archie [e0:d5:5e:e2:d4:89]   192.168.0.22  expires 24h
14:32:07  ✗ DNS blocked          tracker.example.com  ← 192.168.0.15 (Archie)
```
Unknown or unhandled variants fall back to a dim grey raw debug line so nothing is silently swallowed. Mandatory fallback format: `{timestamp}  [?] {variant_name}  {raw_json_compact}`.

**`--json` mode:** If `--json` is passed, the CLI emits one serialized `LanforgeEvent` JSON object per line to stdout, continuously, until the socket closes. No headers, no color. Intended for piping to external tools.

**Distinction from `dns log -f`:** `watch dns` streams general DNS-related `LanforgeEvent`s from the event bus (e.g., `DnsBlocked`, `DnsRewriteUpdated`). `dns log -f` streams the dedicated DNS **query log** — a separate, structured record of every resolution with latency, answer, and client info. Use `dns log -f` for query-level detail; use `watch dns` for event-level activity.

### 3.6 — `login`

**API:** `ak_validate` (over HTTP)

**Behavior:**
1. Requires `--remote` to be set.
2. Prompts for the API key via `inquire`.
3. Calls `ak_validate` to verify the token.
4. On success: saves `{ "remote": "<url>", "token": "<key>" }` to `$XDG_DATA_DIR/lanforge/login.json`.
5. Display: `✓ Authenticated successfully` or `✗ Invalid token`.

---

### 3.7 — `devices`

**API:** `list_devices`

**Flags:**

| Flag | Type | Default | Description |
|:-----|:-----|:--------|:-----------|
| `-f, --filter <STRING>` | Option | — | Full-text search across hostname, MAC, IP |
| `-s, --sort <MODE>` | enum | `last-seen` | One of: `mac`, `host`, `last-seen`, `ip`, `ipv6`, `online` |

**Table mode display:**

```
 DEVICES   ·  34 total  ·  18 online  ·  last scan 3s ago

   HOST                   MAC ADDRESS         IPv4              IPv6 / SLAAC                   SEEN
 ────────────────────────────────────────────────────────────────────────────────────────────────────────
 ● Solarium ★             04:d9:f5:0a:25:94   192.168.0.x       —                              now
 ● Archie ★               e0:d5:5e:e2:d4:89   192.168.0.x       fd97::xxxx                     1m
 ○ Samsung ·              54:44:a3:46:c2:94   192.168.0.x       —                              never

★ static   · dynamic
```

**Rendering rules:**
- Summary header: total, online (green), last scan time (dim).
- `●` green if online, `○` dim grey if offline.
- Hostname truncated at 20 chars with `…`. Origin symbol appended after hostname.
- IPv6 shows the shortest printable address. Full detail via `whois`.
- SEEN column: relative time per §1.7. Default sort: most recently seen first.

### 3.8 — `whois <target>`

**API:** `whois`
**Argument:** MAC, IP, or hostname.

**Display:** A detail card followed by an optional lease history table:

- **Card** (bordered box): Vendor, Method, Origin (with symbol), Status (Online green / Offline red), Last Seen.
- **NETWORK subsection** inside card: IPv4, IPv6, all known addresses.
- **LEASE HISTORY table** (if DB has entries): Columns `TIME | IP ADDRESS | TYPE | ACTION`. Time as relative per §1.7.

### 3.9 — `wol [target]`

**API:** `wol`
**Argument:** Optional MAC or hostname.

**Interactive:** If no target provided, fetches the device list via `list_devices` and presents an `inquire::Select` picker showing `{hostname} [{mac}]` for each device, with online/offline status visible.

**Display:** `Triggering Wake-on-LAN for {target}...` then `✓ {message}`.

### 3.10 — `topology`

**API:** `topology`

**Display:** Tree grouped by parent device (switch/router):

```
┏━ 🖧  RouterName [aa:bb:cc:dd:ee:ff]
┃  ┣━ 💻 Device1 [mac] (Port: 1) [seen: 3s ago]
┃  ┗━ 💻 Device2 [mac] (Port: 4) [seen: 1m ago]

┏━ ❓ Unlinked Devices
   ┗━ 💻 Orphan [mac]
```

Children sorted by port, then MAC. Recursive rendering for nested topologies. In `--ascii` mode, emoji icons are omitted entirely — label text alone is displayed.

### 3.11 — `purge [target]`

**API:** `purge`

**Argument:** Optional MAC or hostname.

**Interactive:** If no target provided, fetches the device list via `list_devices` and presents an `inquire::Select` picker showing `{hostname} [{mac}]` for each device.

**Confirmation:** `[y/N]` unless `--yes`.
**Display:** `✓ {message}`

---

### 3.12 — `host add [mac]`

**API:** `host_add`

**Flags:** `--hostname`, `--v4`, `--v6-suffix`.

**Interactive wizard** (when args missing):
1. MAC prompt (if no positional arg).
2. Hostname prompt.
3. Fixed IPv4 prompt (Enter to leave empty/dynamic).
4. ULA Suffix prompt (Enter to leave empty/none).
5. **CONFIRM ADDITION** summary card (bordered box with MAC, Hostname, optional V4, optional V6).
6. `Save host configuration? [y/N]`

**Non-interactive:** All flags provided → skip wizard, execute directly.
**Side effect:** Promotes the device to Static origin.
**Display:** `✓ {message}`

### 3.13 — `host set [mac] [field] [value]`

**API:** `host_set`

**Arguments:** `[mac]`, `[field]` (one of `hostname`, `v4`, `v6_suffix`), `[value]`.

**Interactive:** If arguments are missing, fetches the static host list via `host_list` — not `list_devices`, since `host_set` only operates on already-static hosts — and presents an `inquire::Select` picker. Then prompts for the field to update and the new value, then confirms.

**Display:** `✓ {message}`.
**Info note:** If field is `v4`, print `ℹ The device will receive the new IP in the next DHCP cycle`.

### 3.14 — `host list`

**API:** `host_list`
**Display:** Table with columns `HOST | MAC ADDRESS | FIXED IPv4 | IPv6 SUFFIX`.

### 3.15 — `host remove [target]`

**API:** `host_remove`

**Argument:** Optional MAC or hostname.

**Interactive:** If no argument provided, fetches the static host list via `host_list` and presents an `inquire::Select` picker, then confirms.

**Display:** `✓ {message}`

### 3.16 — `host export <file>`

**API:** `host_export`
**Display:** `✓ Exported {n} static hosts to {file}` (pretty-printed JSON).

### 3.17 — `host import <file>`

**API:** `host_import`
**Display:** `✓ Imported {n} hosts ({success} ok, {failed} failed)`.

---

### 3.18 — `dns stats`

**API:** `dns_stats`
**Display:** Bordered box with labeled rows: Total Requests, Cache Hits (green), Cache Misses (yellow), Upstream Errors (red), Auth Queries, Recursions, Blocked Queries (cyan), Resolved Total (green), Failed Total (red). Labels dim grey, values colored.

### 3.19 — `dns upstreams` subcommands

- **`list`:** Table: `UPSTREAM | PROTO | RTT | SUCCESS RATE | STATUS`. RTT in ms (yellow), proto (cyan), status green/yellow/red per `healthy`/`degraded`/`unreachable`.
- **`add <addr> [--protocol udp|tcp|tls|https] [--domain <domain>]`:** Adds a new runtime upstream resolver to the database. `✓ {message}`.
- **`remove <id|addr>`:** Removes a runtime upstream resolver from the database. `✓ {message}`.

### 3.20 — `dns analytics [--limit N]`

**API:** `dns_analytics`
**Display:** Multiple ranked tables — Top Domains, Top Clients, query rate breakdowns. `--limit` controls how many entries per table (default 10).

### 3.21 — `dns query <name> [type]`

**API:** `dns_query`
**Default type:** `A`.

**PTR Auto-Detection:** If the `<name>` argument is a valid IPv4 or IPv6 address and no explicit `[type]` is provided, the CLI automatically detects it as a reverse lookup, sets the query type to `PTR`, converts the IP into its corresponding `in-addr.arpa` or `ip6.arpa` format, and submits the query.

**Display:** `dog`-style output:
```
 QUERY RESULT   latency: 12ms  (Authoritative)
<record> -> <response> TTL: <ttl> - <query time>
```

If no records: `No records found.` (red).

### 3.22 — `dns log`

**API:** `dns_query_log` (HybridStream)

**Flags:** `-f, --follow` (stream), `-l, --limit <N>` (default 50), `-c, --client <FILTER>`.

**Display:** Fixed-width table:

```
 TIME       CLIENT            TYPE  DOMAIN                        RESULT    ANSWER                   LATENCY
```

**Result colors:** Blocked=Red, Local/Rewritten=Green, Cached=Cyan, CacheBlocked=Orange, NxDomain=Yellow, Forwarded=White, Failed=Red.
**Client column:** Shows hostname if device is known, raw IP otherwise.
**Follow mode:** After history replay, streams new query log entries line-by-line.

**Distinction from `watch`:** `dns log` streams the dedicated DNS query log — one structured entry per resolution, with latency, answer, and client info. `watch dns` streams general DNS-related `LanforgeEvent`s from the event bus (blocks, rewrite changes, etc). They are separate data sources serving different use cases.

### 3.23 — `dns cache dump` / `dns cache flush` / `dns cache stats`

- **`dump`:** List of `{TYPE:<5} {NAME:<30} -> {DATA}  {TTL}s`. Type cyan, TTL yellow.
- **`flush`:** `✓ {message}`
- **`stats`:** Bordered box with cache capacity, memory footprint, eviction rates.

### 3.24 — `dns adblock` subcommands

- **`status`:** Bordered box: Enabled/Disabled (green/red), optional remaining timer in yellow, blocklist/allowlist sizes.
- **`enable`:** `✓ {message}`. API: `dns_adblock_set(enabled=true, duration_secs=None)`. Cancels any active disable timer.
- **`disable [duration]`:** Accepts any `humantime`-compatible string (`5m`, `1h`, `1h30m`, `90s`, `2d`). Converts to seconds. API: `dns_adblock_set(enabled=false, duration_secs=Some(n))`. Always resets to a fresh countdown, overwriting any previous timer. No duration arg = permanent disable (`duration_secs=None`).
- **`reload`:** `✓ {message}`.
- **`block <domain>`:** `✓ {message}`. Creates a rewrite to `0.0.0.0`.
- **`allow <domain>`:** `✓ {message}`.
- **`unallow <domain>`:** `✓ {message}`. Accepts domain name or allowlist entry ID.
- **`allowlist`:** API: `dns_adblock_allowlist`. Bordered list `● {id:<6} {domain}` (bullet green).
- **`sources list`:** Table `{KIND:<10} {URL}`. Blocklist=red label, Allowlist=green label.
- **`sources add <url> [--kind blocklist|allowlist]`:** Default `blocklist`. `✓ {message}`.
- **`sources remove <url>`:** `✓ {message}`.

### 3.25 — `dns rewrite` subcommands

- **`list`:** Table with columns `ID | DOMAIN | TYPE | TARGET`. Domain in cyan. `dev:` entries display the resolved hostname, the currently resolved IP addresses (provided via `resolved_ips` from the daemon), and a `[dynamic]` badge in dim yellow (e.g., `dev:solarium (192.168.0.10) [dynamic]`).
- **`add <domain> <answer>`:** Server auto-detects record type (IPv4→A, IPv6→AAAA, hostname→CNAME, `dev:<hostname>`→dynamic). `✓ {message}` with assigned Rule ID. Interactive mode provides autocomplete for `dev:` prefix using hostnames fetched from `list_devices`.
- **`remove <id>`:** `✓ {message}`.
- **`clear`:** Confirmation `[y/N]`. `✓ {message}`.
- **`import <file>`:** Reads JSON, additively merges. Summary output.
- **`export <file>`:** `✓ Exported to {path}`.

---

### 3.26 — `dhcp leases`

**API:** `leases`
**Flags:** `--v4` (V4 only), `--v6` (V6 only).
**Display:** Merged per-device table with columns `HOST | MAC | IPv4 | IPv6 | EXPIRES`.

### 3.27 — `dhcp pool`

**API:** `dhcp_pools`

**Display:** Per-subnet section:
```
 IPv4 Subnet: 192.168.0.0/24
 ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  8.2%
 Used: 12 / Total: 155                     Available: 143
```

Bar color: Green (<75%), Yellow (75–90%), Red (>90%). In `--ascii` mode: `[====      ] 8.2%`.

### 3.28 — `lease renew [target]` / `lease release [target]`

**API:** `lease_renew`, `lease_release`

**Argument:** Optional MAC or hostname.

**Flags:** `-6, --v6` — target the V6 lease instead of V4. Maps to `LeaseTarget::V6`; default is `LeaseTarget::V4`.

**Interactive:** If no target provided, fetches the device list via `list_devices` and presents an `inquire::Select` picker showing `{hostname} [{mac}]`.

**Display:** `✓ {message}`

---

### 3.29 — `db` subcommands

- **`vacuum`:** `✓ {message}`
- **`prune`:** `✓ {message}` — removes zombie entries (dynamic, no IP, no hostname, past retention window).
- **`log-clean`:** `✓ {message}` — clears the transient system event log from the database. API: `db_log_clean`.
- **`reset`:** Two `[y/N]` prompts: "Are you sure?" then "This will DELETE ALL DATA. Are you REALLY sure?". `✓ {message}`.

### 3.30 — `auth` subcommands

- **`list`:** Table with `ID | NAME | CAPABILITIES | CREATED AT | LAST USED`. No secret keys displayed.
- **`gen <NAME> [--scopes <list>] [--expires <duration>]`:** Positional argument. Generates new token with optional comma-separated scopes and humantime duration. Display in a bordered emphasis box:
  ```
  ✓ Token generated successfully for: {name}

  ┌─ SECRET KEY (shown only once) ─────────────────┐
  │  lf_ak_7f3a9b2c4d5e6f1a8b9c0d1e2f3a4b5c       │
  └─────────────────────────────────────────────────┘

  Store this key securely. It cannot be retrieved later.
  ```
- **`del <id|name>`:** `✓ {message}`.
- **`renew <id|name>`:** Invalidates old, creates new. Shows new secret in bordered box identical to `gen`.

---

## 4. Dropped Commands (v2 → v3)

| v2 Command | Reason | Replacement |
|:-----------|:-------|:-----------|
| `query status/devices/hosts/state/leases/topology` | Replaced by global `--json` flag | `lanforge --json status`, `lanforge --json devices`, etc. |
| `log` (top-level) | Replaced by `watch`, which calls the `log` API endpoint with `follow=true` | `lanforge watch` with optional `--initial N` and event kind filters |
| `config set-password` | Legacy endpoint removed; password-based auth replaced by API token family | `lanforge auth gen`, `lanforge auth list`, etc. |
| `tui` | Separate feature, unchanged | Stays as `lanforge tui` (feature-gated) |
