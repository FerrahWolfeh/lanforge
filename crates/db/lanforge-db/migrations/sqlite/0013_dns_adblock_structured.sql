-- Migration 13: Rename SQLite tables to flat names and convert adblock config to structured table

-- 1. Rename existing tables to drop 'dns_' prefixes
ALTER TABLE dns_adblock_urls RENAME TO adblock_urls;
ALTER TABLE dns_allowlist RENAME TO allowlist;
ALTER TABLE dns_reverse_resolvers RENAME TO reverse_resolvers;
ALTER TABLE dns_rewrites RENAME TO rewrites;
ALTER TABLE dns_upstreams RENAME TO upstreams;

-- 2. Create new structured table directly
CREATE TABLE adblock_config (
    id               INT PRIMARY KEY CHECK (id = 1),
    enabled          INT NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    blocking_mode    TEXT NOT NULL DEFAULT 'nxdomain' CHECK (blocking_mode IN ('nxdomain', 'null_ip', 'custom_ip', 'refused')),
    blocking_ip_v4   TEXT,
    blocking_ip_v6   TEXT,
    refresh_hours    INT NOT NULL DEFAULT 12 CHECK (refresh_hours >= 0),
    refresh_at_night INT NOT NULL DEFAULT 0 CHECK (refresh_at_night IN (0, 1)),
    extras           TEXT NOT NULL DEFAULT '{}',
    CONSTRAINT custom_ip_requires_v4 CHECK (
        blocking_mode != 'custom_ip' OR blocking_ip_v4 IS NOT NULL
    )
) STRICT;

INSERT INTO adblock_config (id, enabled, blocking_mode, blocking_ip_v4, blocking_ip_v6, refresh_hours, refresh_at_night, extras)
VALUES (1, 0, 'nxdomain', NULL, NULL, 12, 0, '{}');

-- 3. Migrate data from old KV table (dns_adblock_config)
UPDATE adblock_config
SET enabled = COALESCE((SELECT CASE WHEN value = 'true' THEN 1 ELSE 0 END FROM dns_adblock_config WHERE key = 'enabled'), 0),
    blocking_mode = COALESCE((SELECT value FROM dns_adblock_config WHERE key = 'blocking_mode'), 'nxdomain'),
    blocking_ip_v4 = (SELECT value FROM dns_adblock_config WHERE key = 'blocking_ip_v4'),
    blocking_ip_v6 = (SELECT value FROM dns_adblock_config WHERE key = 'blocking_ip_v6'),
    refresh_hours = COALESCE((SELECT CAST(value AS INT) FROM dns_adblock_config WHERE key = 'refresh_hours'), 12),
    refresh_at_night = COALESCE((SELECT CASE WHEN value = 'true' THEN 1 ELSE 0 END FROM dns_adblock_config WHERE key = 'refresh_at_night'), 0);

DROP TABLE dns_adblock_config;
