# lanforge

> Unified IPv4/IPv6 network control daemon for Linux edge gateways.

**lanforge** is a single-process daemon that replaces the fragile stack of radvd + dnsmasq + custom trackers typically found on small Linux routers and Raspberry Pi gateways. It manages RA, DHCPv4, DHCPv6, and SLAAC hostname tracking as coordinated tasks with a shared device table, rather than separate processes that communicate through files and signals.

This is a personal project built for a Raspberry Pi 4B running a self-hosted home network stack. It is opinionated, but the core is generic enough to be useful on any Linux gateway.

---

## Why

The conventional setup looks like this:

```
radvd          → sends Router Advertisements
dnsmasq        → DHCPv4 + DHCPv6 + local DNS upstream
ipv6_namer     → watches NDP table, tries to associate SLAAC addresses to hostnames
                  by reading dnsmasq's lease file
pihole-FTL     → DNS resolver, pulls hostnames from dnsmasq as upstream
```

This works, until the router reboots with clients already on the network. The devices have active addresses, but dnsmasq's lease file is empty and ipv6_namer has no state — so nothing gets a hostname until each device happens to renew its DHCP lease. On a network where devices renew every 24 hours, that means flying blind for most of the day.

The root cause is that the hostname lives in dnsmasq, the SLAAC address lives in ipv6_namer, and they only communicate through a file that evaporates on reboot.

lanforge keeps a single `DeviceTable` in memory, backed by SQLite, that associates a MAC address with a hostname and all of its addresses — v4 lease, v6 lease, and SLAAC addresses — as one record. On startup, the table is restored from SQLite before the first NDP query runs. Hostnames are available immediately, with no dependency on lease renewal timing.

---

## Status

Early development. The RA service is functional. DHCPv4/v6 and the unified device table are in progress.

| Component       | Status      |
|-----------------|-------------|
| RA service      | ✅ done      |
| SLAAC tracker   | ✅ done (ipv6_namer, being migrated) |
| DeviceTable     | 🔨 in progress |
| DHCPv4 server   | 🔨 in progress |
| DHCPv6 server   | planned     |
| Control socket  | planned     |
| PPPoE client    | future      |

---

## Architecture

Each network service runs as a supervised tokio task inside a single process. A broadcast `EventBus` carries events between tasks — a `LeaseGranted` from the DHCP server triggers a hosts file write; a `PrefixChanged` from the netlink watcher triggers an updated RA. One netlink connection serves everything.

```
┌──────────────────────────────────────────────────────────┐
│                      lanforge                            │
│                                                          │
│   RA service ── DHCPv4 ── DHCPv6 ── SLAAC tracker       │
│         │           │         │          │               │
│         └───────────┴─────────┴──────────┘               │
│                          │                               │
│                      EventBus                            │
│                          │                               │
│              DeviceTable (Arc<RwLock>)                   │
│              Supervisor (backoff restart)                │
└──────────────────────────────────────────────────────────┘
                           │ SIGHUP + addn-hosts
                           ▼
                       pihole-FTL
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design.

---

## Configuration

```toml
[general]
iface_lan      = "end0"
iface_wan      = "ppp0"
hosts_file     = "/mnt/ram/lanforge/hosts"
devices_db     = "/var/lib/lanforge/devices.db"
dns_reload_cmd = "pkill -HUP pihole-FTL"

[ra]
enabled         = true
managed         = true
other_config    = true
max_interval    = 100
router_lifetime = 1800
mtu             = 1492

[[ra.prefix]]
source  = "ula"
address = "fd97:f00d:cafe:3731::"

[[ra.prefix]]
source = "auto_gua"

[[ra.rdnss]]
servers  = ["fd97:f00d:cafe:3731::1"]
lifetime = 600

[dhcp.v4]
enabled     = true
range_start = "192.168.0.100"
range_end   = "192.168.0.254"
lease_time  = 86400
router      = "192.168.0.1"
dns         = ["192.168.0.1"]

[dhcp.v6]
enabled    = true
lease_time = 86400

# One [[devices]] block per physical device.
# Both stacks, one place. v4_ip and v6_suffix are optional.
[[devices]]
mac       = "e0:d5:5e:e2:d4:89"
hostname  = "Archie"
v4_ip     = "192.168.0.2"
v6_suffix = "::1057:cafe"

[[devices]]
mac      = "aa:bb:cc:dd:ee:ff"
hostname = "Fuyu-PC"
v4_ip    = "192.168.0.3"
```

---

## CLI

```
lanforge run         # start all enabled services
lanforge ra          # RA service only (debug/isolation)
lanforge dhcp        # DHCP servers only
lanforge devices     # list known devices (v4, v6, SLAAC, last seen)
lanforge devices -v  # include DUID and lease expiry details
lanforge status      # service health
lanforge reload      # send SIGUSR1 to running daemon
```

`devices` and `status` communicate with the running daemon via `/run/lanforge/control.sock` and can be run without root.

---

## Building

```bash
cargo build --release
```

Requires `CAP_NET_RAW`, `CAP_NET_ADMIN`, and `CAP_NET_BIND_SERVICE` to run. The included systemd unit sets these via `AmbientCapabilities`.

```bash
# Install
install -Dm755 target/release/lanforge /usr/local/sbin/lanforge
install -Dm644 contrib/lanforge.service /etc/systemd/system/lanforge.service
install -Dm644 contrib/lanforge.toml    /etc/lanforge/lanforge.toml

systemctl enable --now lanforge
```

---

## Related

- [`longseer`](https://github.com/...) — the SLAAC hostname tracker this project grew out of
- [`farcaster`](https://github.com/...) — command passing over SSH

---

## License

MIT
