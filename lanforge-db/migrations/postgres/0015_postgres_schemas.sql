-- Migration: Restructure Postgres into logical schemas (Option A)
CREATE SCHEMA IF NOT EXISTS dns;
CREATE SCHEMA IF NOT EXISTS dhcp;
CREATE SCHEMA IF NOT EXISTS net;
CREATE SCHEMA IF NOT EXISTS auth;

-- 1. Move and rename custom enum type
ALTER TYPE dns_blocking_mode SET SCHEMA dns;
ALTER TYPE dns.dns_blocking_mode RENAME TO blocking_mode;

-- 2. Move and rename dns tables
ALTER TABLE dns_adblock_config SET SCHEMA dns;
ALTER TABLE dns.dns_adblock_config RENAME TO adblock_config;

ALTER TABLE dns_adblock_urls SET SCHEMA dns;
ALTER TABLE dns.dns_adblock_urls RENAME TO adblock_urls;

ALTER TABLE dns_allowlist SET SCHEMA dns;
ALTER TABLE dns.dns_allowlist RENAME TO allowlist;

ALTER TABLE dns_reverse_resolvers SET SCHEMA dns;
ALTER TABLE dns.dns_reverse_resolvers RENAME TO reverse_resolvers;

ALTER TABLE dns_rewrites SET SCHEMA dns;
ALTER TABLE dns.dns_rewrites RENAME TO rewrites;

ALTER TABLE dns_upstreams SET SCHEMA dns;
ALTER TABLE dns.dns_upstreams RENAME TO upstreams;

-- 3. Move dhcp tables
ALTER TABLE v4_leases SET SCHEMA dhcp;
ALTER TABLE v6_leases SET SCHEMA dhcp;
ALTER TABLE lease_history SET SCHEMA dhcp;
ALTER TABLE static_devices SET SCHEMA dhcp;

-- 4. Move net tables
ALTER TABLE devices SET SCHEMA net;
ALTER TABLE device_topology SET SCHEMA net;
ALTER TABLE seen_v4 SET SCHEMA net;
ALTER TABLE slaac_addrs SET SCHEMA net;
ALTER TABLE v6_prefixes SET SCHEMA net;

-- 5. Move auth tables
ALTER TABLE api_tokens SET SCHEMA auth;
