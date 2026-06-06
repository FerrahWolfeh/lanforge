-- Phase 2: Schema Type Improvements (SQLite)

-- 1. STRICT tables for DNS configuration
-- Recreating these tables with STRICT keyword for better integrity

ALTER TABLE dns_rewrites RENAME TO dns_rewrites_old;
CREATE TABLE dns_rewrites (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain  TEXT NOT NULL UNIQUE,
    answer  TEXT NOT NULL
) STRICT;
INSERT INTO dns_rewrites (id, domain, answer) SELECT id, domain, answer FROM dns_rewrites_old;
DROP TABLE dns_rewrites_old;

ALTER TABLE dns_allowlist RENAME TO dns_allowlist_old;
CREATE TABLE dns_allowlist (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain  TEXT NOT NULL UNIQUE
) STRICT;
INSERT INTO dns_allowlist (id, domain) SELECT id, domain FROM dns_allowlist_old;
DROP TABLE dns_allowlist_old;

ALTER TABLE dns_adblock_config RENAME TO dns_adblock_config_old;
CREATE TABLE dns_adblock_config (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
) STRICT;
INSERT INTO dns_adblock_config (key, value) SELECT key, value FROM dns_adblock_config_old;
DROP TABLE dns_adblock_config_old;

ALTER TABLE dns_adblock_urls RENAME TO dns_adblock_urls_old;
CREATE TABLE dns_adblock_urls (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT NOT NULL UNIQUE,
    kind    TEXT NOT NULL DEFAULT 'block'
) STRICT;
INSERT INTO dns_adblock_urls (id, url, kind) SELECT id, url, kind FROM dns_adblock_urls_old;
DROP TABLE dns_adblock_urls_old;

-- 2. devices table with CHECK constraints
-- Using the 'new table' approach to avoid breaking foreign keys in other tables.

CREATE TABLE devices_new (
    mac             TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    hostname_origin INTEGER NOT NULL DEFAULT 0,
    is_static       INTEGER NOT NULL,
    duid            BLOB,
    last_seen       INTEGER NOT NULL,
    origin          TEXT NOT NULL DEFAULT 'dynamic',
    managed_at      INTEGER,
    v4_static       TEXT,
    v6_suffix       TEXT,
    vendor          TEXT,
    parent_mac      TEXT,
    parent_port     TEXT,
    local_ifindex   INTEGER NOT NULL DEFAULT 0,
    topo_updated    INTEGER NOT NULL DEFAULT 0,
    boot_file       TEXT,
    CHECK(length(vendor) <= 128),
    CHECK(length(hostname) <= 253)
);

INSERT INTO devices_new SELECT 
    mac, hostname, hostname_origin, is_static, duid, last_seen, origin, 
    managed_at, v4_static, v6_suffix, vendor, parent_mac, parent_port, 
    local_ifindex, topo_updated, boot_file 
FROM devices;

DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;

-- 3. seen_v4 with ip_int computed column
-- Recreating seen_v4 to add the computed column

ALTER TABLE seen_v4 RENAME TO seen_v4_old;
CREATE TABLE seen_v4 (
    mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    ip      TEXT NOT NULL,
    ip_int  INTEGER GENERATED ALWAYS AS (
        (CAST(substr(ip, 1, instr(ip, '.') - 1) AS INT) << 24) |
        (CAST(substr(substr(ip, instr(ip, '.') + 1), 1, instr(substr(ip, instr(ip, '.') + 1), '.') - 1) AS INT) << 16) |
        (CAST(substr(substr(ip, instr(ip, '.') + 1 + instr(substr(ip, instr(ip, '.') + 1), '.')), 1, instr(substr(ip, instr(ip, '.') + 1 + instr(substr(ip, instr(ip, '.') + 1), '.')), '.') - 1) AS INT) << 8) |
        CAST(substr(ip, instr(ip, '.') + 1 + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + 1 + instr(substr(ip, instr(ip, '.') + 1), '.')), '.')) AS INT)
    ) VIRTUAL,
    PRIMARY KEY (mac, ip)
);
INSERT INTO seen_v4 (mac, ip) SELECT mac, ip FROM seen_v4_old;
DROP TABLE seen_v4_old;

CREATE INDEX idx_seen_v4_ip_int ON seen_v4(ip_int);
