# Lanforge Configuration Documentation

This directory contains modular configuration snippets for each Lanforge service.
These files can be merged into a single `lanforge.toml` or read individually by the daemon.

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

1. Copy the desired sections into your `/etc/lanforge/lanforge.toml`.
2. Customize the parameters (especially `system.iface` and `system.ula_prefix`).
3. Restart the `lanforged` daemon.
