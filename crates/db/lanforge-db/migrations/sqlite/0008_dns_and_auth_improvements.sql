-- Phase 4: DNS Rewrites and API Token Improvements (SQLite)

-- 1. Improve dns_rewrites to support multiple record types per domain
CREATE TABLE dns_rewrites_new (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain  TEXT NOT NULL,
    rtype   TEXT NOT NULL DEFAULT 'A', -- A, AAAA, CNAME
    answer  TEXT NOT NULL,
    UNIQUE(domain, rtype)
);

INSERT INTO dns_rewrites_new (id, domain, answer)
SELECT id, domain, answer FROM dns_rewrites;

DROP TABLE dns_rewrites;
ALTER TABLE dns_rewrites_new RENAME TO dns_rewrites;

-- 2. Improve api_tokens
CREATE TABLE api_tokens_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used  INTEGER
);

INSERT INTO api_tokens_new (token, name, created_at, last_used)
SELECT token, name, created_at, last_used FROM api_tokens;

DROP TABLE api_tokens;
ALTER TABLE api_tokens_new RENAME TO api_tokens;
