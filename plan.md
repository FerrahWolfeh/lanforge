# lanforge-cli Enhancements

This plan outlines the implementation of several requested features for `lanforge-cli`, including Wake on LAN, DNS diagnostics, lease history, and improved filtering/status.

## User Review Required

> [!IMPORTANT]
> **Wake on LAN (WoL)** will be implemented by sending a standard Magic Packet via UDP broadcast on port 9 of the configured LAN interface. If a hostname matches multiple devices, a fuzzy-search selection menu (using `iocraft`) will be shown.
> **DNS Query** will return results based on the mode: authoritative (showing A/AAAA/PTR with rich formatting) or recursive (supporting specific record types, defaulting to A/AAAA).
> **Whois/Lease Show** will be added as a command/tool to show all known details for a given MAC or IP.

## Proposed Changes

---

### [Component] lanforge-api

Updates to the communication protocol between CLI and Daemon.

#### [MODIFY] [api.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-api/src/api.rs)
- Add new variants to `Command` enum:
  - `Wol { target: String }` (target can be MAC or Hostname)
  - `DnsQuery { name: String, record_type: Option<String> }`
  - `Whois { target: String }` (alias for LeaseShow, providing full device details)
- Add corresponding response structures:
  - `DnsQueryResponse`
  - `LeaseHistoryResponse` (extending `DeviceEntry` or separate)

#### [MODIFY] [handlers.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-api/src/handlers.rs)
- Implement `handle_wol`, `handle_dns_query`, and `handle_lease_show`.
- Enhance `handle_devices` with advanced filtering logic.
- Enhance `handle_status` to include more granular service info if missing.

#### [MODIFY] [server.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-api/src/server.rs)
- Dispatch new commands to their respective handlers.

---

### [Component] lanforge-cli

Updates to the CLI tool to expose the new functionality.

#### [MODIFY] [args.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-cli/src/args.rs)
- Add subcommands for:
  - `wol <target>`
  - `dns query <name> [--type <T>]`
  - `whois <target>` (MAC or IP)
- Add flags to `devices` for filtering: `--vendor`, `--since`, etc.
- Add `--mode` or `--module` to `log follow`.

#### [NEW] [wol.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-cli/src/cli/commands/wol.rs)
- Handler for processing the `wol` response.

#### [NEW] [whois.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-cli/src/cli/commands/whois.rs)
- Handler for displaying detailed device information (Whois).

#### [NEW] [dns.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-cli/src/cli/commands/dns.rs)
- Handler for displaying DNS query results with latency.

#### [MODIFY] [devices.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-cli/src/cli/commands/devices.rs)
- Update to support new filtering options and learning method display.

---

### [Component] lanforge-core

Support logic for the new features.

#### [MODIFY] [device.rs](file:///home/datcr/Projects/Rust/lanforge/lanforge-core/src/device.rs)
- Add `learning_method` field to address states if not present.
- Add basic OUI prefix matching logic.

## Open Questions

> [!NOTE]
> 1. Should `lanforge dns query` use a specific record type by default (e.g., A/AAAA)?
> 2. For `lanforge wol`, if multiple devices match a hostname, should we wake all of them or ask for clarification?

## Verification Plan

### Automated Tests
- `cargo test` in all modified crates.
- Manual integration testing using the `lanforge-cli` against a running `lanforge` daemon.

### Manual Verification
- Test `lanforge wol` by checking for magic packets using `tcpdump -i <iface> udp port 9`.
- Test `lanforge dns query` against known local and upstream domains.
- Verify `lanforge devices` filtering behaves as expected.
