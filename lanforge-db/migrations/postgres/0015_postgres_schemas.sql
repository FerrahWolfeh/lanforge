-- Migration: Restructure Postgres into logical schemas (Option A)
CREATE SCHEMA IF NOT EXISTS dns;
CREATE SCHEMA IF NOT EXISTS dhcp;
CREATE SCHEMA IF NOT EXISTS net;
CREATE SCHEMA IF NOT EXISTS auth;

-- 1. Move and rename custom enum type
ALTER TYPE public.dns_blocking_mode SET SCHEMA dns;
ALTER TYPE dns.dns_blocking_mode RENAME TO blocking_mode;

-- 2. Move and rename dns tables
ALTER TABLE public.dns_adblock_config SET SCHEMA dns;
ALTER TABLE dns.dns_adblock_config RENAME TO adblock_config;

ALTER TABLE public.dns_adblock_urls SET SCHEMA dns;
ALTER TABLE dns.dns_adblock_urls RENAME TO adblock_urls;

ALTER TABLE public.dns_allowlist SET SCHEMA dns;
ALTER TABLE dns.dns_allowlist RENAME TO allowlist;

ALTER TABLE public.dns_reverse_resolvers SET SCHEMA dns;
ALTER TABLE dns.dns_reverse_resolvers RENAME TO reverse_resolvers;

ALTER TABLE public.dns_rewrites SET SCHEMA dns;
ALTER TABLE dns.dns_rewrites RENAME TO rewrites;

ALTER TABLE public.dns_upstreams SET SCHEMA dns;
ALTER TABLE dns.dns_upstreams RENAME TO upstreams;

-- 3. Move dhcp tables
ALTER TABLE public.v4_leases SET SCHEMA dhcp;
ALTER TABLE public.v6_leases SET SCHEMA dhcp;
ALTER TABLE public.lease_history SET SCHEMA dhcp;
ALTER TABLE public.static_devices SET SCHEMA dhcp;

-- 4. Move net tables
ALTER TABLE public.devices SET SCHEMA net;
ALTER TABLE public.device_topology SET SCHEMA net;
ALTER TABLE public.seen_v4 SET SCHEMA net;
ALTER TABLE public.slaac_addrs SET SCHEMA net;
ALTER TABLE public.v6_prefixes SET SCHEMA net;

-- 5. Move auth tables
ALTER TABLE public.api_tokens SET SCHEMA auth;
