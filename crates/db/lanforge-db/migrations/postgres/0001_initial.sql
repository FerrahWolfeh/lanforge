-- Initial schema for devices and leases (PostgreSQL)
CREATE TABLE IF NOT EXISTS devices (
    mac             TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    hostname_origin INTEGER NOT NULL DEFAULT 0,
    is_static       BOOLEAN NOT NULL,
    duid            BYTEA,
    last_seen       BIGINT NOT NULL,
    origin          TEXT NOT NULL DEFAULT 'dynamic',
    managed_at      BIGINT,
    v4_static       TEXT,
    v6_suffix       TEXT,
    vendor          TEXT
);

CREATE TABLE IF NOT EXISTS v4_leases (
    mac     TEXT PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
    ip      TEXT NOT NULL,
    expires BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS v6_leases (
    mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    iaid    BIGINT NOT NULL,
    ip      TEXT NOT NULL,
    expires BIGINT NOT NULL,
    PRIMARY KEY (mac, iaid)
);

CREATE TABLE IF NOT EXISTS v6_prefixes (
    mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    iaid    BIGINT NOT NULL,
    prefix  TEXT NOT NULL,
    len     INTEGER NOT NULL,
    expires BIGINT NOT NULL,
    PRIMARY KEY (mac, iaid)
);

CREATE TABLE IF NOT EXISTS slaac_addrs (
    mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    ip      TEXT NOT NULL,
    PRIMARY KEY (mac, ip)
);

CREATE TABLE IF NOT EXISTS seen_v4 (
    mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    ip      TEXT NOT NULL,
    PRIMARY KEY (mac, ip)
);

CREATE TABLE IF NOT EXISTS lease_history (
    id         SERIAL PRIMARY KEY,
    mac        TEXT NOT NULL,
    ip         TEXT NOT NULL,
    lease_type TEXT NOT NULL,
    action     TEXT NOT NULL,
    timestamp  BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lease_history_mac ON lease_history(mac);
CREATE INDEX IF NOT EXISTS idx_lease_history_timestamp ON lease_history(timestamp);
