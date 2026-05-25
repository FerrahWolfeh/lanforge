-- Migration: Structured dns_adblock_config for SQLite
CREATE TABLE dns_adblock_config_new (
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

INSERT INTO dns_adblock_config_new (id, enabled, blocking_mode, blocking_ip_v4, blocking_ip_v6, refresh_hours, refresh_at_night, extras)
VALUES (1, 0, 'nxdomain', NULL, NULL, 12, 0, '{}');

UPDATE dns_adblock_config_new
SET enabled = COALESCE((SELECT CASE WHEN value = 'true' THEN 1 ELSE 0 END FROM dns_adblock_config WHERE key = 'enabled'), 0),
    blocking_mode = COALESCE((SELECT value FROM dns_adblock_config WHERE key = 'blocking_mode'), 'nxdomain'),
    blocking_ip_v4 = (SELECT value FROM dns_adblock_config WHERE key = 'blocking_ip_v4'),
    blocking_ip_v6 = (SELECT value FROM dns_adblock_config WHERE key = 'blocking_ip_v6'),
    refresh_hours = COALESCE((SELECT CAST(value AS INT) FROM dns_adblock_config WHERE key = 'refresh_hours'), 12),
    refresh_at_night = COALESCE((SELECT CASE WHEN value = 'true' THEN 1 ELSE 0 END FROM dns_adblock_config WHERE key = 'refresh_at_night'), 0);

DROP TABLE dns_adblock_config;
ALTER TABLE dns_adblock_config_new RENAME TO dns_adblock_config;
