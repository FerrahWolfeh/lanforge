-- Migration 28: Add config JSONB column to dhcp.v4_pools and dhcp.v6_pools for scoped options
ALTER TABLE dhcp.v4_pools ADD COLUMN IF NOT EXISTS config JSONB;
ALTER TABLE dhcp.v6_pools ADD COLUMN IF NOT EXISTS config JSONB;
