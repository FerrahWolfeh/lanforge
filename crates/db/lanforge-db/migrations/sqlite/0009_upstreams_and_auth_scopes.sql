-- Phase 4: Runtime DNS Upstreams and API Token Scopes (SQLite)

-- 1. Create dns_upstreams table
CREATE TABLE dns_upstreams (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    addr     TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'udp',
    domain   TEXT,
    UNIQUE(addr, protocol)
);

-- 2. Add scopes and expires_at to api_tokens
ALTER TABLE api_tokens ADD COLUMN scopes TEXT NOT NULL DEFAULT 'admin';
ALTER TABLE api_tokens ADD COLUMN expires_at INTEGER;
