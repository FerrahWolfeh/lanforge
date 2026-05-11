# lanforge CLI — Specification

Command line interface and control socket for the `lanforge` daemon.

---

## Overview

The CLI communicates with the daemon via a JSON Unix socket at `/run/lanforge/control.sock`.
Query and monitoring commands work without special permissions.
Commands that modify state require the socket to be accessible (group `lanforge` or root).

```
lanforge <command> [subcommand] [flags]
```

---

## Planned Commands

### Query and Monitoring

| Command | Description |
|---|---|
| `lanforge devices` | List all known devices |
| `lanforge devices --verbose` | List with full details (DUID, expiration, SLAAC) |
| `lanforge devices --filter <hostname\|mac\|ip>` | Filter the listing |
| `lanforge devices --format json` | JSON output for scripting |
| `lanforge watch` | Reactive live view via socket (no polling) |
| `lanforge status` | Health of services, pool, network, persistence |
| `lanforge log [--follow]` | Real-time internal EventBus |

### Lease Management

| Command | Description |
|---|---|
| `lanforge lease renew <mac>` | Sends DHCP FORCERENEW (RFC 3203) to the device |
| `lanforge lease release <mac>` | Releases the lease and removes from the dynamic table |
| `lanforge scan` | Triggers immediate NDP cycle with feedback |
| `lanforge export [--format json\|csv]` | Full table snapshot |

### Custom Device Management

| Command | Description |
|---|---|
| `lanforge host add` | Interactive prompt to add device |
| `lanforge host add <mac>` | Adds device with pre-filled MAC |
| `lanforge host set <mac> <field> <value>` | Updates specific field of a device |
| `lanforge host list` | Lists devices managed via CLI (not from TOML) |
| `lanforge host remove <mac>` | Removes device from the runtime table |

### Maintenance

| Command | Description |
|---|---|
| `lanforge reload` | Sends SIGUSR1 (reloads static config from TOML) |
| `lanforge db vacuum` | Compacts SQLite and removes expired entries |
| `lanforge shutdown` | Graceful shutdown with immediate flush |

### Individual Subsystems (for debug/test)

| Command | Description |
|---|---|
| `lanforge run --only ra` | Starts only the RA service |
| `lanforge run --only dhcpv4` | Starts only DHCPv4 |
| `lanforge run --only dhcpv6` | Starts only DHCPv6 |
| `lanforge run --only dns` | Starts only DNS |
| `lanforge run --only slaac` | Starts only the SLAAC tracker |

---

## Custom Device Management

### Philosophy

Devices added via CLI live in an intermediate layer between static entries
from TOML (immutable at runtime) and dynamic entries learned by protocols.
They are persisted in SQLite with a `managed = true` flag and survive reboots.

Three possible configuration levels, from simplest to most complete:

1. **Hostname only** — associates a readable name with the MAC. The device still receives a dynamic IP from the pool but resolves in DNS with the configured hostname.

2. **Hostname + Static V4** — equivalent to `dhcp-host=` in dnsmasq.
   The pool reserves the IP and DHCPv4 always delivers it to that MAC.

3. **Hostname + V4 + ULA suffix** — complete configuration, equivalent to a
   `[[devices]]` in TOML, but added at runtime without editing a file.

### Interactive Prompt: `lanforge host add`

```
$ lanforge host add

  Add device

  MAC address: aa:bb:cc:dd:ee:ff
  Hostname:    my-device

  Configuration level:
  [1] Hostname only (dynamic IP from pool)
  [2] Hostname + Static IPv4
  [3] Hostname + Static IPv4 + ULA suffix

  Choice [1]: 2

  Static IPv4: 192.168.0.50

  Confirm?
    MAC       aa:bb:cc:dd:ee:ff
    hostname  my-device
    Static V4 192.168.0.50

  [y/N]: y

  ✓ Device added. Hostname resolves immediately in .lan
```

### With Pre-filled MAC: `lanforge host add <mac>`

```
$ lanforge host add aa:bb:cc:dd:ee:ff

  Add device  ·  aa:bb:cc:dd:ee:ff

  ℹ  Device already seen on network (last seen 4 minutes ago, IP 192.168.0.142)

  Hostname:    solarium

  Configuration level:
  [1] Hostname only (dynamic IP from pool)
  [2] Hostname + Static IPv4
  [3] Hostname + Static IPv4 + ULA suffix

  Choice [1]: 1

  ✓ Hostname "solarium" associated with aa:bb:cc:dd:ee:ff
    Resolves immediately as solarium.lan → 192.168.0.142
```

### Point Update: `lanforge host set`

```
$ lanforge host set aa:bb:cc:dd:ee:ff hostname new-name
  ✓ hostname updated: my-device → new-name

$ lanforge host set aa:bb:cc:dd:ee:ff v4 192.168.0.55
  ✓ Static IPv4 defined: 192.168.0.55
  ℹ  The device will receive the new IP in the next DHCP cycle

$ lanforge host set aa:bb:cc:dd:ee:ff v6-suffix ::1234
  ✓ ULA suffix defined: fd97:f00d:cafe:3731::1234
```

### Listing: `lanforge host list`

```
$ lanforge host list

  DEVICES MANAGED VIA CLI  ·  3 entries

  MAC                HOSTNAME       STATIC V4        ULA SUFFIX       ADDED
  ─────────────────────────────────────────────────────────────────────────────
  aa:bb:cc:dd:ee:ff  solarium       —                —                yesterday 14:22
  11:22:33:44:55:66  printer        192.168.0.50     —                3 days ago
  de:ad:be:ef:00:01  nas-storage    192.168.0.20     ::dead:beef      1 week ago

  Use "lanforge host remove <mac>" to remove.
```

### Removal: `lanforge host remove`

```
$ lanforge host remove aa:bb:cc:dd:ee:ff

  Remove device aa:bb:cc:dd:ee:ff (solarium)?

  ℹ  The device is still active on the network (IP 192.168.0.142)
     After removal, it will continue with a dynamic IP but without a hostname.

  [y/N]: y

  ✓ Device removed from managed table.
```

---

## Mockup: `lanforge devices`

```
$ lanforge devices

  DEVICES  ·  12 known  ·  10 online  ·  last scan 3s ago

  ──────────────────────────────────────────────────────────────────────────────
  HOST              MAC                V4               V6 / SLAAC
  ──────────────────────────────────────────────────────────────────────────────
  Archie      ★    e0:d5:5e:e2:d4:89  192.168.0.2      fd97::1057:cafe        ↑
                                                        2804:abcd::e2d5:5eff   ↑
              V4 lease until tomorrow 08:14  ·  V6 until tomorrow 08:14

  Fuyu-PC     ★    aa:bb:cc:dd:ee:ff  192.168.0.3      fd97::bbcc:ddff        ↑
              V4 lease until tomorrow 14:22  ·  no DHCPv6

  solarium    ·    3c:0a:7a:d8:11:78  192.168.0.104    fd97::3e0a:7aff        ↑
                                                        2804:abcd::3e0a:7aff   ↑
              V4 lease expires in 6h  ·  V6 expires in 6h

  PrinterHQ   ★    11:22:33:44:55:66  192.168.0.10     —
              no active lease  ·  last seen 2 days ago

  printer     ·    11:22:33:44:55:66  192.168.0.50     —
              V4 lease expires in 18h  ·  static IP via CLI

  host-aabb…  –    bb:aa:dd:cc:ee:ff  192.168.0.187    —
              V4 lease expires in 18h  ·  no DHCPv6

  ──────────────────────────────────────────────────────────────────────────────
  ★ Static TOML   · Managed via CLI   – Dynamic   ↑ SLAAC active
```

---

## Mockup: `lanforge devices --verbose`

```
$ lanforge devices --verbose

  DEVICES  ·  12 known  ·  10 online  ·  last scan 3s ago

  ┌─ Archie ★ ─────────────────────────────────────────────────────────────────┐
  │  MAC        e0:d5:5e:e2:d4:89                                             │
  │  DUID       00:03:00:01:e0:d5:5e:e2:d4:89  (DUID-LL)                     │
  │  last seen  3 seconds ago                                                  │
  │  origin     Static TOML                                                   │
  │                                                                            │
  │  V4         192.168.0.2              expires 2026-03-22 08:14  (reserved) │
  │  V6         fd97::1057:cafe          expires 2026-03-22 08:14  (reserved) │
  │  SLAAC      fd97::e2d5:5eff:fee2:d489                                     │
  │             2804:abcd:1234:5678::e2d5:5eff:fee2:d489                      │
  └────────────────────────────────────────────────────────────────────────────┘

  ┌─ solarium · ───────────────────────────────────────────────────────────────┐
  │  MAC        3c:0a:7a:d8:11:78                                             │
  │  DUID       00:01:00:01:2a:4b:6c:8d:3c:0a:7a:d8:11:78  (DUID-LLT)       │
  │  last seen  3 seconds ago                                                  │
  │  origin     hostname via CLI (added yesterday 14:22)                      │
  │                                                                            │
  │  V4         192.168.0.104            expires in 6h (dynamic)              │
  │  V6         fd97::3e0a:7aff:fed8:1178 expires in 6h (dynamic)             │
  │  SLAAC      fd97::3e0a:7aff:fed8:1178                                     │
  │             2804:abcd::3e0a:7aff:fed8:1178                                │
  └────────────────────────────────────────────────────────────────────────────┘
```

---

## Mockup: `lanforge status`

```
$ lanforge status

  LANFORGE  ·  uptime 4d 12h 33m  ·  v0.5.0

  SERVICES
  ─────────────────────────────────────────────────────────────────────────────
  ● RA          online    uptime 4d 12h
                          GUA  2804:abcd:1234:5678::/64  (dynamic)
                          ULA  fd97:f00d:cafe:3731::/64
                          interval ~100s  ·  MTU 1492  ·  M=1 O=1

  ● DHCPv4      online    uptime 4d 12h
                          pool 192.168.0.100–254
                          12 active leases  ·  143 free
                          next expiration in 6h  (solarium)

  ● DHCPv6      online    uptime 4d 12h
                          pool fd97::100–200
                          9 active leases  ·  247 free
                          next expiration in 6h  (solarium)

  ● DNS         online    uptime 4d 12h
                          listening 0.0.0.0:5300
                          upstream 127.0.0.1:5335 (Unbound)
                          domain .lan  ·  TTL 60s

  ● SLAAC       online    uptime 4d 12h
                          24 addresses tracked
                          last scan 3s ago  ·  GUA 2804:abcd::/64

  DEVICES
  ─────────────────────────────────────────────────────────────────────────────
  12 known  ·  10 online  ·  2 static without activity
  7 from TOML  ·  3 managed via CLI  ·  2 pure dynamic

  PERSISTENCE
  ─────────────────────────────────────────────────────────────────────────────
  SQLite   /var/lib/lanforge/leases.db  ·  148 KB
           last flush 12s ago  ·  debounce 3s
           WAL mode  ·  no errors

  NETWORK
  ─────────────────────────────────────────────────────────────────────────────
  LAN      end0  ·  192.168.0.1/16  ·  fd97::1/64
  WAN      ppp0  ·  CGNAT (no public IPv4)
           GUA   2804:abcd:1234:5678::/64  (ISP delegated)
```

---

## Socket Protocol (`/run/lanforge/control.sock`)

Unix domain socket, newline-delimited JSON messages (`\n`).

### Requests

```json
{ "cmd": "devices" }
{ "cmd": "devices", "filter": "solarium" }
{ "cmd": "status" }
{ "cmd": "scan" }
{ "cmd": "reload" }
{ "cmd": "shutdown" }

{ "cmd": "host_add", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "solarium" }
{ "cmd": "host_add", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "printer", "v4": "192.168.0.50" }
{ "cmd": "host_add", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "nas", "v4": "192.168.0.20", "v6_suffix": "::dead:beef" }

{ "cmd": "host_set", "mac": "aa:bb:cc:dd:ee:ff", "field": "hostname", "value": "new-name" }
{ "cmd": "host_set", "mac": "aa:bb:cc:dd:ee:ff", "field": "v4", "value": "192.168.0.55" }
{ "cmd": "host_set", "mac": "aa:bb:cc:dd:ee:ff", "field": "v6_suffix", "value": "::1234" }

{ "cmd": "host_remove", "mac": "aa:bb:cc:dd:ee:ff" }
{ "cmd": "host_list" }

{ "cmd": "lease_renew",  "mac": "aa:bb:cc:dd:ee:ff" }
{ "cmd": "lease_release","mac": "aa:bb:cc:dd:ee:ff" }
```

### Response — `devices`

```json
{
  "devices": [
    {
      "mac": "e0:d5:5e:e2:d4:89",
      "hostname": "Archie",
      "origin": "static",
      "online": true,
      "last_seen": "2026-03-21T14:32:00Z",
      "duid": "00:03:00:01:e0:d5:5e:e2:d4:89",
      "v4": { "ip": "192.168.0.2", "expires": "2026-03-22T08:14:00Z", "reserved": true },
      "v6": { "ip": "fd97::1057:cafe", "expires": "2026-03-22T08:14:00Z", "reserved": true },
      "slaac": [
        "fd97::e2d5:5eff:fee2:d489",
        "2804:abcd::e2d5:5eff:fee2:d489"
      ]
    }
  ],
  "meta": {
    "total": 12,
    "online": 10,
    "last_scan_secs_ago": 3
  }
}
```

### Response — `status`

```json
{
  "uptime_secs": 390813,
  "version": "0.5.0",
  "services": {
    "ra":     { "state": "running", "uptime_secs": 390813, "gua": "2804:abcd::/64", "ula": "fd97:f00d:cafe:3731::/64" },
    "dhcp_v4":{ "state": "running", "uptime_secs": 390813, "leases_active": 12, "pool_free": 143 },
    "dhcp_v6":{ "state": "running", "uptime_secs": 390813, "leases_active": 9,  "pool_free": 247 },
    "dns":    { "state": "running", "uptime_secs": 390813, "upstream": "127.0.0.1:5335" },
    "slaac":  { "state": "running", "uptime_secs": 390813, "addrs_tracked": 24, "last_scan_secs_ago": 3 }
  },
  "db": {
    "path": "/var/lib/lanforge/leases.db",
    "size_bytes": 151552,
    "last_flush_secs_ago": 12
  },
  "network": {
    "lan_iface": "end0",
    "wan_iface": "ppp0",
    "gua": "2804:abcd:1234:5678::/64",
    "ula": "fd97:f00d:cafe:3731::/64"
  },
  "devices": {
    "total": 12,
    "online": 10,
    "static_toml": 7,
    "managed_cli": 3,
    "dynamic": 2
  }
}
```

---

## SQLite Schema — Additional field for CLI devices

```sql
-- Devices managed via CLI have managed = true and origin = 'cli'
-- Devices from TOML have is_static = true and origin = 'toml'
-- Dynamic devices have both false and origin = 'dynamic'

ALTER TABLE devices ADD COLUMN origin TEXT NOT NULL DEFAULT 'dynamic';
ALTER TABLE devices ADD COLUMN managed_at INTEGER;  -- unix timestamp of addition via CLI
```

The `origin` distinction allows `lanforge host list` to filter only entries
added via CLI, and for bootstrap to know not to overwrite TOML entries
with what came from the DB (TOML always has precedence).

---

## Implementation Notes

**Runtime Configuration Precedence:**

```
Static TOML  >  Managed CLI  >  Protocol Dynamic
```

A device added via CLI with hostname `"solarium"` does not overwrite a
`[[devices]]` from TOML that has the same MAC — TOML always wins.

**CLI Entries Persistence:**

Entries added via CLI are written to SQLite immediately (without debounce),
as they are explicit user actions. The normal `db_worker` covers the rest.

**`host add` with MAC already in table:**

If the MAC already exists as a dynamic device, the command elevates the entry to `managed`
without losing the active lease. The hostname starts resolving in DNS immediately.

If the MAC already exists as a TOML entry, the command refuses with an explanatory error
and suggests editing the configuration file.