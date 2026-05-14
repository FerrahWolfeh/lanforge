# Lanforge CLI Command Structure

This document outlines the command hierarchy for the `lanforge-cli` utility.

## Global Commands
- `status`: Show daemon status, uptime, and version.
- `scan`: Trigger a network scan.
- `reload`: Reload configuration.
- `shutdown`: Shut down the daemon.
- `watch`: Live stream event bus events (logs).

## Device Management (`devices`)
- `list`: List all discovered devices (pure display).
- `whois <target>`: Detailed info and history for a device.
- `wol <target>`: Send Wake-on-LAN magic packet.
- `topo`: Show network topology.
- `purge <mac>`: Remove device from memory and database.

## Host Management (`host`)
- `list`: List static host configurations.
- `add <mac> [options]`: Add or update a static host.
- `set <mac> <field> <value>`: Update a specific field for a host.
- `remove <mac>`: Remove a static host configuration.
- `import <file>`: Import static hosts from a JSON/TOML file.
- `export <file>`: Export static hosts to a JSON file.

## DNS Management (`dns`)
- `stats`: Show DNS resolver statistics.
- `analytics [--limit N]`: Show top domains, clients, etc.
- `query <name> [type]`: Perform a diagnostic DNS query.
- `log [--follow]`: View or stream DNS query logs.

### DNS Cache (`dns cache`)
- `list [--filter F]`: List current cache entries.
- `flush`: Clear the DNS cache.
- `stats`: Show detailed cache performance metrics.

### DNS Adblock (`dns adblock`)
- `status`: Show adblocker status and stats.
- `on`: Enable the adblocker.
- `off [--duration N]`: Disable the adblocker (temporarily or permanently).
- `reload`: Reload blocklist and allowlist rules.
- `urls [list|add|remove]`: Manage blocklist/allowlist source URLs.
- `block <domain>`: Persistently block a domain.
- `allow <domain>`: Add a domain to the allowlist.

### DNS Rewrites (`dns rewrite`)
- `list`: List all DNS rewrite rules.
- `add <domain> <answer>`: Add a new rewrite rule.
- `remove <domain>`: Remove a rewrite rule.

## DHCP Management (`dhcp`)
- `leases`: List active DHCP leases.
- `pools`: Show DHCP pool status and utilization.
- `renew <mac> [v4|v6]`: Force renew a lease.
- `release <mac> [v4|v6]`: Force release a lease.

## Database Management (`db`)
- `vacuum`: Reclaim space and optimize the database.
- `prune`: Remove old historical data.
- `reset`: Reset the database to factory defaults.

## Auth Management (`auth`)
- `gen <name>`: Generate a new API token.
- `del <name>`: Delete an API token.
- `refresh <name>`: Refresh an API token.
