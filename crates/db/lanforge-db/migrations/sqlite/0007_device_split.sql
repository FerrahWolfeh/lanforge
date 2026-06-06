-- Phase 3: Device Table Split (SQLite)

-- 1. Create specialized tables
CREATE TABLE device_topology (
    mac             TEXT PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
    parent_mac      TEXT,
    parent_port     TEXT,
    local_ifindex   INTEGER NOT NULL DEFAULT 0,
    topo_updated    INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE static_devices (
    mac             TEXT PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
    v4_static       TEXT,
    v6_suffix       TEXT,
    boot_file       TEXT
) STRICT;

-- 2. Migrate data to new tables
INSERT INTO device_topology (mac, parent_mac, parent_port, local_ifindex, topo_updated)
SELECT mac, parent_mac, parent_port, local_ifindex, topo_updated
FROM devices
WHERE parent_mac IS NOT NULL OR parent_port IS NOT NULL OR local_ifindex != 0 OR topo_updated != 0;

INSERT INTO static_devices (mac, v4_static, v6_suffix, boot_file)
SELECT mac, v4_static, v6_suffix, boot_file
FROM devices
WHERE v4_static IS NOT NULL OR v6_suffix IS NOT NULL OR boot_file IS NOT NULL;

-- 3. Recreate devices table
CREATE TABLE devices_new (
    mac             TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    hostname_origin INTEGER NOT NULL DEFAULT 0,
    duid            BLOB,
    last_seen       INTEGER NOT NULL,
    origin          TEXT NOT NULL DEFAULT 'dynamic',
    managed_at      INTEGER,
    class           INTEGER NOT NULL DEFAULT 0,
    CHECK(length(hostname) <= 253),
    CHECK(origin IN ('static', 'system', 'dynamic'))
) STRICT;

INSERT INTO devices_new (mac, hostname, hostname_origin, duid, last_seen, origin, managed_at)
SELECT 
    mac, hostname, hostname_origin, duid, last_seen,
    CASE 
        WHEN origin IN ('toml', 'managed_cli', 'api', 'static') THEN 'static'
        WHEN origin = 'system' THEN 'system'
        ELSE 'dynamic'
    END,
    managed_at
FROM devices;

-- 4. Switch tables
PRAGMA foreign_keys=OFF;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
PRAGMA foreign_keys=ON;
