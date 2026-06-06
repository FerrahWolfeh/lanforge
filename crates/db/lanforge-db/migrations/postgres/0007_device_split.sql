-- Phase 3: Device Table Split (PostgreSQL)

-- 1. Create specialized tables
CREATE TABLE device_topology (
    mac             MACADDR PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
    parent_mac      MACADDR,
    parent_port     TEXT,
    local_ifindex   INTEGER NOT NULL DEFAULT 0,
    topo_updated    BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE static_devices (
    mac             MACADDR PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
    v4_static       INET,
    v6_suffix       TEXT,
    boot_file       TEXT
);

-- 2. Migrate data to new tables
INSERT INTO device_topology (mac, parent_mac, parent_port, local_ifindex, topo_updated)
SELECT mac, parent_mac::MACADDR, parent_port, local_ifindex, topo_updated
FROM devices
WHERE parent_mac IS NOT NULL OR parent_port IS NOT NULL OR local_ifindex != 0 OR topo_updated != 0;

INSERT INTO static_devices (mac, v4_static, v6_suffix, boot_file)
SELECT mac, v4_static::INET, v6_suffix, boot_file
FROM devices
WHERE v4_static IS NOT NULL OR v6_suffix IS NOT NULL OR boot_file IS NOT NULL;

-- 3. Update origin values
UPDATE devices SET origin = 'static' WHERE origin IN ('toml', 'managed_cli', 'api');

-- 4. Remove columns from devices and add class
ALTER TABLE devices DROP COLUMN parent_mac;
ALTER TABLE devices DROP COLUMN parent_port;
ALTER TABLE devices DROP COLUMN local_ifindex;
ALTER TABLE devices DROP COLUMN topo_updated;
ALTER TABLE devices DROP COLUMN v4_static;
ALTER TABLE devices DROP COLUMN v6_suffix;
ALTER TABLE devices DROP COLUMN boot_file;
ALTER TABLE devices DROP COLUMN is_static;
ALTER TABLE devices DROP COLUMN vendor;

ALTER TABLE devices ADD COLUMN class INTEGER NOT NULL DEFAULT 0;

-- 5. Add constraint for origin
ALTER TABLE devices ADD CONSTRAINT check_origin CHECK (origin IN ('static', 'system', 'dynamic'));
