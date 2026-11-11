# Lanforge Configuration Documentation

This directory contains modular configuration snippets for each Lanforge service.
These files are sections to merge into the single `lanforge.toml` the daemon reads.

## Module Numbering System

The files are prefixed with numbers to suggest a logical loading order:

- **00-09**: Core System & Database
- **10-19**: DNS & Neighbor Discovery (RA)
- **20-29**: Address Assignment (DHCP, TFTP)
- **30-39**: APIs & External Interfaces
- **40-49**: Background Monitoring & Probing (mDNS)
- **50+**:   Static Definitions (Devices, Static Leases)

## Usage

To use these as a base for your configuration:

1. Copy the desired sections into your `/etc/lanforge/lanforge.toml` (the daemon reads that one
   file; `lanforge.example.toml` has every section together).
2. Customize the parameters (especially `system.iface`).
3. Run `lanforge reload`: it applies the file in place, without restarting the daemon. A wrong
   value is left out and listed by `lanforge status` and the WebUI.

Every file here is checked by the daemon's tests: each parses with the strict file form and
has no config issue.
