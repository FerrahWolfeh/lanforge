-- SQLite schema improvements: add last_seen to observed/SLAAC tables and optimize history indexes
ALTER TABLE seen_v4 ADD COLUMN last_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now'));
ALTER TABLE slaac_addrs ADD COLUMN last_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now'));

DROP INDEX IF EXISTS idx_lease_history_mac;
CREATE INDEX IF NOT EXISTS idx_lease_history_mac_timestamp ON lease_history(mac, timestamp DESC);
