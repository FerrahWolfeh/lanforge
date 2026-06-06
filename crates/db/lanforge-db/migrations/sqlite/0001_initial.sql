-- Initial schema for devices and leases
CREATE TABLE IF NOT EXISTS devices (
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
    vendor          TEXT
);

CREATE TABLE IF NOT EXISTS v4_leases (
    mac     TEXT PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
    ip      TEXT NOT NULL,
    expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS v6_leases (
    mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    iaid    INTEGER NOT NULL,
    ip      TEXT NOT NULL,
    expires INTEGER NOT NULL,
    PRIMARY KEY (mac, iaid)
);

CREATE TABLE IF NOT EXISTS v6_prefixes (
    mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    iaid    INTEGER NOT NULL,
    prefix  TEXT NOT NULL,
    len     INTEGER NOT NULL,
    expires INTEGER NOT NULL,
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
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mac        TEXT NOT NULL,
    ip         TEXT NOT NULL,
    lease_type TEXT NOT NULL,
    action     TEXT NOT NULL,
    timestamp  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lease_history_mac ON lease_history(mac);
CREATE INDEX IF NOT EXISTS idx_lease_history_timestamp ON lease_history(timestamp);
