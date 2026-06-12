-- PostgreSQL schema improvements

-- 1. Create Enums
CREATE TYPE device_origin AS ENUM ('static', 'system', 'dynamic');
CREATE TYPE hostname_origin_t AS ENUM ('dhcp', 'dns', 'mdns', 'ndp', 'netbios', 'static', 'system', 'user');
CREATE TYPE lease_action_t AS ENUM ('granted', 'renewed', 'released', 'expired', 'declined', 'purged');
CREATE TYPE lease_type_t AS ENUM ('v4', 'v6', 'prefix');

-- 2. Migrate devices enums & timestamps
ALTER TABLE devices DROP CONSTRAINT IF EXISTS check_origin;

ALTER TABLE devices ALTER COLUMN origin DROP DEFAULT;
ALTER TABLE devices ALTER COLUMN origin TYPE device_origin USING origin::device_origin;
ALTER TABLE devices ALTER COLUMN origin SET DEFAULT 'dynamic'::device_origin;

ALTER TABLE devices ALTER COLUMN hostname_origin DROP DEFAULT;

ALTER TABLE devices ALTER COLUMN hostname_origin TYPE hostname_origin_t USING (
    CASE hostname_origin
        WHEN 0 THEN 'dhcp'::hostname_origin_t
        WHEN 1 THEN 'static'::hostname_origin_t
        WHEN 2 THEN 'dns'::hostname_origin_t
        WHEN 3 THEN 'mdns'::hostname_origin_t
        WHEN 4 THEN 'ndp'::hostname_origin_t
        WHEN 5 THEN 'netbios'::hostname_origin_t
        WHEN 6 THEN 'user'::hostname_origin_t
        ELSE 'dhcp'::hostname_origin_t
    END
);

ALTER TABLE devices ALTER COLUMN hostname_origin SET DEFAULT 'dhcp'::hostname_origin_t;

ALTER TABLE devices ALTER COLUMN last_seen DROP DEFAULT;
ALTER TABLE devices ALTER COLUMN last_seen TYPE TIMESTAMPTZ USING to_timestamp(last_seen);
ALTER TABLE devices ALTER COLUMN managed_at DROP DEFAULT;
ALTER TABLE devices ALTER COLUMN managed_at TYPE TIMESTAMPTZ USING to_timestamp(managed_at);

-- 3. Migrate leases timestamps
ALTER TABLE v4_leases ALTER COLUMN expires DROP DEFAULT;
ALTER TABLE v4_leases ALTER COLUMN expires TYPE TIMESTAMPTZ USING to_timestamp(expires);
ALTER TABLE v6_leases ALTER COLUMN expires DROP DEFAULT;
ALTER TABLE v6_leases ALTER COLUMN expires TYPE TIMESTAMPTZ USING to_timestamp(expires);
ALTER TABLE v6_prefixes ALTER COLUMN expires DROP DEFAULT;
ALTER TABLE v6_prefixes ALTER COLUMN expires TYPE TIMESTAMPTZ USING to_timestamp(expires);

-- 4. Migrate device_topology timestamp
ALTER TABLE device_topology ALTER COLUMN topo_updated DROP DEFAULT;
ALTER TABLE device_topology ALTER COLUMN topo_updated TYPE TIMESTAMPTZ USING to_timestamp(topo_updated);
ALTER TABLE device_topology ALTER COLUMN topo_updated SET DEFAULT to_timestamp(0);

-- 5. Migrate api_tokens timestamps
ALTER TABLE api_tokens ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE api_tokens ALTER COLUMN created_at TYPE TIMESTAMPTZ USING to_timestamp(created_at);
ALTER TABLE api_tokens ALTER COLUMN last_used DROP DEFAULT;
ALTER TABLE api_tokens ALTER COLUMN last_used TYPE TIMESTAMPTZ USING to_timestamp(last_used);
ALTER TABLE api_tokens ALTER COLUMN expires_at DROP DEFAULT;
ALTER TABLE api_tokens ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING to_timestamp(expires_at);

-- 6. Migrate lease_history
-- Rename timestamp to occurred_at, and change lease_type / action to enums
ALTER TABLE lease_history RENAME COLUMN timestamp TO occurred_at;
ALTER TABLE lease_history ALTER COLUMN occurred_at DROP DEFAULT;
ALTER TABLE lease_history ALTER COLUMN occurred_at TYPE TIMESTAMPTZ USING to_timestamp(occurred_at);

ALTER TABLE lease_history ALTER COLUMN lease_type TYPE lease_type_t USING (
    CASE lease_type
        WHEN 'v4' THEN 'v4'::lease_type_t
        WHEN 'v6' THEN 'v6'::lease_type_t
        WHEN 'prefix' THEN 'prefix'::lease_type_t
        ELSE 'v4'::lease_type_t
    END
);

ALTER TABLE lease_history ALTER COLUMN action TYPE lease_action_t USING (
    CASE action
        WHEN 'granted' THEN 'granted'::lease_action_t
        WHEN 'renewed' THEN 'renewed'::lease_action_t
        WHEN 'released' THEN 'released'::lease_action_t
        WHEN 'expired' THEN 'expired'::lease_action_t
        WHEN 'declined' THEN 'declined'::lease_action_t
        WHEN 'purged' THEN 'purged'::lease_action_t
        ELSE 'granted'::lease_action_t
    END
);

-- 7. Add last_seen to seen_v4 and slaac_addrs
ALTER TABLE seen_v4 ADD COLUMN last_seen TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE slaac_addrs ADD COLUMN last_seen TIMESTAMPTZ NOT NULL DEFAULT now();

-- 8. Compound and auxiliary indexes
DROP INDEX IF EXISTS idx_lease_history_mac;
DROP INDEX IF EXISTS idx_lease_history_timestamp;
CREATE INDEX IF NOT EXISTS idx_lease_history_mac_occurred ON lease_history(mac, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_duid ON devices(duid);
