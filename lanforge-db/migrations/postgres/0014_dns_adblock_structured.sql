-- Migration: Structured dns_adblock_config for Postgres
CREATE TYPE dns_blocking_mode AS ENUM (
    'nxdomain',
    'null_ip',
    'custom_ip',
    'refused'
);

CREATE TABLE dns_adblock_config_new (
    id               BOOLEAN PRIMARY KEY DEFAULT true,
    CONSTRAINT       single_row CHECK (id),
    enabled          BOOLEAN NOT NULL DEFAULT false,
    blocking_mode    dns_blocking_mode NOT NULL DEFAULT 'nxdomain',
    blocking_ip_v4   INET,
    blocking_ip_v6   INET,
    refresh_hours    SMALLINT NOT NULL DEFAULT 12 CHECK (refresh_hours >= 0),
    refresh_at_night BOOLEAN NOT NULL DEFAULT false,
    extras           JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT custom_ip_requires_v4 CHECK (
        blocking_mode != 'custom_ip' OR blocking_ip_v4 IS NOT NULL
    )
);

-- Insert default row
INSERT INTO dns_adblock_config_new (id, enabled, blocking_mode, blocking_ip_v4, blocking_ip_v6, refresh_hours, refresh_at_night, extras)
VALUES (true, false, 'nxdomain', NULL, NULL, 12, false, '{}');

-- Migrate data safely
UPDATE dns_adblock_config_new
SET enabled = COALESCE((SELECT value = 'true' FROM dns_adblock_config WHERE key = 'enabled'), false),
    blocking_mode = COALESCE(
        (SELECT CASE WHEN value IN ('nxdomain', 'null_ip', 'custom_ip', 'refused') THEN value::dns_blocking_mode ELSE 'nxdomain'::dns_blocking_mode END FROM dns_adblock_config WHERE key = 'blocking_mode'),
        'nxdomain'::dns_blocking_mode
    ),
    blocking_ip_v4 = (SELECT CASE WHEN value ~ '^[0-9.]+$' THEN value::inet ELSE NULL END FROM dns_adblock_config WHERE key = 'blocking_ip_v4'),
    blocking_ip_v6 = (SELECT CASE WHEN value ~ '^[0-9a-fA-F:.]+$' THEN value::inet ELSE NULL END FROM dns_adblock_config WHERE key = 'blocking_ip_v6'),
    refresh_hours = COALESCE((SELECT value::smallint FROM dns_adblock_config WHERE key = 'refresh_hours'), 12::smallint),
    refresh_at_night = COALESCE((SELECT value = 'true' FROM dns_adblock_config WHERE key = 'refresh_at_night'), false);

DROP TABLE dns_adblock_config;
ALTER TABLE dns_adblock_config_new RENAME TO dns_adblock_config;
