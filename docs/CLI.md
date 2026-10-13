# Lanforge CLI — User Guide & Command Reference

The `lanforge` CLI tool (`crates/bin/lanforge-cli`) is the primary administration client for the Lanforge router daemon. It communicates locally over Unix Domain Sockets (UDS) or remotely via HTTPS/REST.

---

## 1. Architecture & Global Flags

### 1.1 Stack & Implementation
- **Argument Parsing**: `clap` with derive macros and subcommand aliases.
- **Table & Terminal Formatting**: `comfy-table` with Unicode / ASCII box drawing, column wrapping, and dynamic width detection.
- **Terminal Colorization**: `colored` with automatic TTY detection and `NO_COLOR` environment support.
- **Interactive Prompts**: `inquire` with fuzzy-filtering selection lists for devices, leases, and hosts.
- **Duration Parsing**: `duration-str` supporting human durations (`10m`, `1h`, `30s`, `2d`).
- **Error Handling**: `color-eyre` generating clean user-facing error messages without stack traces on connection issues.

### 1.2 Invocation
```bash
lanforge [GLOBAL FLAGS] [COMMAND] [SUBCOMMAND] [OPTIONS]
```
Running bare `lanforge` without arguments automatically executes `lanforge status` and displays the system dashboard.

### 1.3 Global Flags

| Flag | Environment Variable | Default | Description |
|:-----|:---------------------|:--------|:------------|
| `-s, --socket <PATH>` | `LANFORGE_CONTROL_SOCKET` | `/run/lanforge/control.sock` | Path to local Unix Domain Socket. |
| `--remote <URL>` | `LANFORGE_REMOTE_URL` | — | Remote daemon URL (e.g. `https://192.168.1.1:8088`). |
| `--token <TOKEN>` | `LANFORGE_TOKEN` | — | Bearer token for remote authentication. |
| `--json` | — | `false` | Output machine-readable JSON instead of formatted tables. |
| `--no-color` | `NO_COLOR` | `false` | Disable ANSI terminal color codes. |
| `--ascii` | — | `false` | Replace Unicode box-drawing with pure ASCII characters. |
| `-y, --yes` | — | `false` | Skip interactive confirmation prompts for destructive actions. |

---

## 2. Command Reference

### `status`
Displays the real-time system dashboard including service states, uptime, CPU/memory consumption, WAN/LAN addressing, and database status.
```bash
lanforge status
```

### `service`
Inspects and manages background daemon services supervised by `lanforged`.
```bash
lanforge service list                  # List all services, states, and uptime
lanforge service show <service-id>     # Detailed state and metrics for a specific service
lanforge service restart <service-id>  # Restart a background service
lanforge service start <service-id>    # Start an inactive service
lanforge service stop <service-id>     # Stop an active service
```

### `watch` *(alias: `events`)*
Streams real-time daemon events (device discoveries, DHCP leases, DNS queries, firewall updates, PPPoE status) directly from the event bus.
```bash
lanforge watch                         # Stream all system events live
lanforge watch --filter dhcp           # Filter by category: dhcp, dns, firewall, pppoe, device
lanforge watch -n 50                   # Replay the last 50 historical events before streaming
lanforge watch --json                  # Output newline-delimited JSON events
```

### `devices` *(alias: `device`)*
Inspects, filters, and manages connected and discovered network devices.
```bash
lanforge devices                       # List devices (sorted by last seen)
lanforge devices --online              # Show only currently online devices
lanforge devices -f 192.168.1.50       # Filter by IP, MAC, or hostname
lanforge devices -a                    # Include stale and offline devices
lanforge devices show <mac-or-name>    # Detailed identity card, lease history, and SLAAC addrs
lanforge devices purge <mac-or-name>   # Remove device and its dynamic DNS records from DB
```

### `host` *(alias: `hosts`)*
Manages static DHCP reservations and manual local DNS host overrides.
```bash
lanforge host list                     # List all configured static hosts
lanforge host add                      # Launch interactive wizard to pin MAC to IP/hostname
lanforge host add 00:11:22:33:44:55 --hostname nas --v4 192.168.1.10
lanforge host set <mac> <field> <val>  # Update a specific field (hostname, v4, v6_suffix)
lanforge host remove <mac-or-name>     # Delete a static host reservation
lanforge host export hosts.json        # Export static hosts to JSON
lanforge host import hosts.json        # Bulk import static hosts from JSON
```

### `wol` *(alias: `wake`)*
Injects a Wake-on-LAN Ethernet broadcast magic packet to power on a networked device.
```bash
lanforge wol                           # Launch interactive fuzzy-picker of known devices
lanforge wol 00:11:22:33:44:55         # Send magic packet directly to MAC
lanforge wol desktop-pc                # Send magic packet resolved from device hostname
```

### `reload`
Requests an in-place configuration reload across all running services without dropping active sockets or rebooting the daemon.
```bash
lanforge reload
```

### `pppoe`
Monitors and manages the native PPPoE WAN client session.
```bash
lanforge pppoe status                  # Session status, assigned IP, MTU, uptime, LCP stats
lanforge pppoe reconnect               # Terminate active session (PADT) and renegotiate
lanforge pppoe disconnect              # Tear down WAN PPPoE session
```

### `ra`
Manages the IPv6 Router Advertisement (RFC 4861) engine.
```bash
lanforge ra status                     # View advertised prefixes, RDNSS, lifetime, flags (M/O)
lanforge ra trigger                    # Send an immediate unsolicited Router Advertisement
lanforge ra config                     # View active RA server configuration parameters
```

### `dns`
Manages the integrated DNS resolver, upstream forwarders, cache, and adblock filter rules.

```bash
# General resolver statistics & diagnostics
lanforge dns status                    # Health, query throughput, cache hit rate, adblock state
lanforge dns analytics                 # Top domains, top clients, query type distribution
lanforge dns query example.com A       # Diagnostic resolution through local engine

# Query logs & cache
lanforge dns logs                      # Show recent query audit logs
lanforge dns logs --follow             # Stream DNS queries in real-time
lanforge dns cache dump                # Inspect cached DNS resource records
lanforge dns flush                     # Flush in-memory DNS cache

# Upstreams & local rewrites
lanforge dns upstreams                 # Health and round-trip latency of upstream resolvers
lanforge dns rewrites list             # List local DNS rewrite rules (including dev: and srv:)

# Adblocking control
lanforge dns adblock status            # Active rules, blocklists, and blocking mode
lanforge dns adblock pause 15m         # Temporarily pause adblocking for 15 minutes
lanforge dns adblock resume            # Re-enable adblocking immediately
lanforge dns adblock block ads.foo.com # Add domain to custom blocklist
lanforge dns adblock allow cdn.foo.com # Add domain to custom allowlist
lanforge dns adblock check doubleclick.net # Test attribution and matching rules for a domain
```

### `dhcp`
Inspects DHCPv4/DHCPv6 lease allocations and pool utilization.
```bash
lanforge dhcp leases                   # List active IPv4 and IPv6 leases with expiration
lanforge dhcp pools                    # Show pool utilization percentages and free address counts
lanforge dhcp reconcile                # Reconcile lease table against active network interfaces
lanforge dhcp renew <mac>              # Force lease extension for a device
lanforge dhcp release <mac>            # Release an active DHCP lease
```

### `firewall`
Manages the stateful Netlink/nftables firewall engine.
```bash
lanforge firewall status               # Active zones, interface assignments, rule counts
lanforge firewall reload               # Recompile and apply firewall ruleset in-place (~5ms)
```

### `traffic` *(alias: `qos`)*
Inspects traffic shaping (SQM / CAKE), hardware NIC offloads, and real-time bandwidth rates.
```bash
lanforge traffic status                # SQM queue status, active disciplines, tuning state
lanforge traffic rates                 # Real-time RX/TX rates per interface
```

### `db`
Performs maintenance on the embedded `redb` database.
```bash
lanforge db vacuum                     # Compact database and reclaim fragmented storage
lanforge db prune                      # Prune historical query logs and event logs
lanforge db clean                      # Clear transient runtime event logs
```

### `config`
Inspects, exports, imports, and validates the system configuration.
```bash
lanforge config export backup.json     # Export full database configuration to JSON
lanforge config import backup.json     # Import and merge configuration
lanforge config validate               # Validate /etc/lanforge/lanforge.toml syntax
```

### `user` *(alias: `users`)*
Manages local router user accounts and authorization roles (`admin`, `operator`, `viewer`).
```bash
lanforge user list                     # List user accounts and last login timestamps
lanforge user add <username>           # Create user with interactive password prompt
lanforge user passwd <username>        # Change password for a user account
lanforge user delete <username>        # Remove user account
```

### `auth` *(alias: `token`, `tokens`)*
Manages API authentication tokens and access keys.
```bash
lanforge auth list                     # List active tokens with scopes and expiration
lanforge auth generate <name>          # Generate a new API token (secret shown once)
lanforge auth delete <id-or-name>      # Revoke an API token
lanforge auth renew <id-or-name>       # Re-issue token with a fresh secret
```

### `setup`
First-run router onboarding wizard that inspects physical interfaces and configures LAN IP, DHCP ranges, upstream DNS, firewall zones, and the initial administrator account.
```bash
lanforge setup
```

### `login`
Saves remote daemon credentials to `$XDG_DATA_DIR/lanforge/login.json` for passwordless CLI access to remote routers.
```bash
lanforge login https://router.local:8088
```

### `shutdown`
Gracefully stops all background network services, writes persistent state to disk, and terminates the daemon.
```bash
lanforge shutdown
```
