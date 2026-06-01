-- Migration 0014: Add performance indexes for hostname lookup, lease/prefix expiry, and IP lookups.

-- Functional index for case-insensitive hostname lookups
CREATE INDEX IF NOT EXISTS idx_devices_hostname_lower ON devices (LOWER(hostname));

-- Indexes for active/expired leases and prefix lookups/pruning
CREATE INDEX IF NOT EXISTS idx_v4_leases_expires ON v4_leases (expires);
CREATE INDEX IF NOT EXISTS idx_v6_leases_expires ON v6_leases (expires);
CREATE INDEX IF NOT EXISTS idx_v6_prefixes_expires ON v6_prefixes (expires);

-- Indexes on IP columns in seen/SLAAC tables for IP-to-MAC lookups
CREATE INDEX IF NOT EXISTS idx_seen_v4_ip ON seen_v4 (ip);
CREATE INDEX IF NOT EXISTS idx_slaac_addrs_ip ON slaac_addrs (ip);
