-- Migration 14: Restructure Postgres schemas and convert adblock config to structured table

-- 1. Create new schemas
CREATE SCHEMA IF NOT EXISTS dns;
CREATE SCHEMA IF NOT EXISTS dhcp;
CREATE SCHEMA IF NOT EXISTS net;
CREATE SCHEMA IF NOT EXISTS auth;

-- 2. Move existing tables to their new schemas
ALTER TABLE IF EXISTS public.dns_adblock_config SET SCHEMA dns;

ALTER TABLE IF EXISTS public.dns_adblock_urls SET SCHEMA dns;
ALTER TABLE dns.dns_adblock_urls RENAME TO adblock_urls;

ALTER TABLE IF EXISTS public.dns_allowlist SET SCHEMA dns;
ALTER TABLE dns.dns_allowlist RENAME TO allowlist;

ALTER TABLE IF EXISTS public.dns_reverse_resolvers SET SCHEMA dns;
ALTER TABLE dns.dns_reverse_resolvers RENAME TO reverse_resolvers;

ALTER TABLE IF EXISTS public.dns_rewrites SET SCHEMA dns;
ALTER TABLE dns.dns_rewrites RENAME TO rewrites;

ALTER TABLE IF EXISTS public.dns_upstreams SET SCHEMA dns;
ALTER TABLE dns.dns_upstreams RENAME TO upstreams;

ALTER TABLE IF EXISTS public.v4_leases SET SCHEMA dhcp;
ALTER TABLE IF EXISTS public.v6_leases SET SCHEMA dhcp;
ALTER TABLE IF EXISTS public.lease_history SET SCHEMA dhcp;
ALTER TABLE IF EXISTS public.static_devices SET SCHEMA dhcp;

ALTER TABLE IF EXISTS public.devices SET SCHEMA net;
ALTER TABLE IF EXISTS public.device_topology SET SCHEMA net;
ALTER TABLE IF EXISTS public.seen_v4 SET SCHEMA net;
ALTER TABLE IF EXISTS public.slaac_addrs SET SCHEMA net;
ALTER TABLE IF EXISTS public.v6_prefixes SET SCHEMA net;

ALTER TABLE IF EXISTS public.api_tokens SET SCHEMA auth;

-- 3. Create custom enum type inside dns schema
CREATE TYPE dns.blocking_mode AS ENUM (
    'nxdomain',
    'null_ip',
    'custom_ip',
    'refused'
);

-- 4. Create new structured table directly in dns schema
CREATE TABLE dns.adblock_config (
    id               BOOLEAN PRIMARY KEY DEFAULT true,
    CONSTRAINT       single_row CHECK (id),
    enabled          BOOLEAN NOT NULL DEFAULT false,
    blocking_mode    dns.blocking_mode NOT NULL DEFAULT 'nxdomain',
    blocking_ip_v4   INET,
    blocking_ip_v6   INET,
    refresh_hours    SMALLINT NOT NULL DEFAULT 12 CHECK (refresh_hours >= 0),
    refresh_at_night BOOLEAN NOT NULL DEFAULT false,
    extras           JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT custom_ip_requires_v4 CHECK (
        blocking_mode != 'custom_ip' OR blocking_ip_v4 IS NOT NULL
    )
);

-- 5. Insert default config
INSERT INTO dns.adblock_config (id, enabled, blocking_mode, blocking_ip_v4, blocking_ip_v6, refresh_hours, refresh_at_night, extras)
VALUES (true, false, 'nxdomain', NULL, NULL, 12, false, '{}');

-- 6. Migrate data from old KV table (which was moved to dns.dns_adblock_config)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'dns' AND tablename = 'dns_adblock_config') THEN
        UPDATE dns.adblock_config
        SET enabled = COALESCE((SELECT value = 'true' FROM dns.dns_adblock_config WHERE key = 'enabled'), false),
            blocking_mode = COALESCE(
                (SELECT CASE WHEN value IN ('nxdomain', 'null_ip', 'custom_ip', 'refused') THEN value::dns.blocking_mode ELSE 'nxdomain'::dns.blocking_mode END FROM dns.dns_adblock_config WHERE key = 'blocking_mode'),
                'nxdomain'::dns.blocking_mode
            ),
            blocking_ip_v4 = (SELECT CASE WHEN value ~ '^[0-9.]+$' THEN value::inet ELSE NULL END FROM dns.dns_adblock_config WHERE key = 'blocking_ip_v4'),
            blocking_ip_v6 = (SELECT CASE WHEN value ~ '^[0-9a-fA-F:.]+$' THEN value::inet ELSE NULL END FROM dns.dns_adblock_config WHERE key = 'blocking_ip_v6'),
            refresh_hours = COALESCE((SELECT value::smallint FROM dns.dns_adblock_config WHERE key = 'refresh_hours'), 12::smallint),
            refresh_at_night = COALESCE((SELECT value = 'true' FROM dns.dns_adblock_config WHERE key = 'refresh_at_night'), false);
            
        DROP TABLE dns.dns_adblock_config;
    END IF;
END $$;
