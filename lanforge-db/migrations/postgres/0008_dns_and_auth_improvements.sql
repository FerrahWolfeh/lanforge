-- Phase 4: DNS Rewrites and API Token Improvements (PostgreSQL)

-- 1. Improve dns_rewrites to support multiple record types per domain
CREATE TABLE dns_rewrites_new (
    id      SERIAL PRIMARY KEY,
    domain  TEXT NOT NULL,
    rtype   TEXT NOT NULL DEFAULT 'A', -- A, AAAA, CNAME
    answer  TEXT NOT NULL,
    UNIQUE(domain, rtype)
);

-- Note: We assume existing 'answer' can be converted if it was meant to be INET, 
-- but since it can also be a domain (CNAME), we keep it as TEXT for now.
INSERT INTO dns_rewrites_new (domain, answer)
SELECT domain, answer FROM dns_rewrites;

DROP TABLE dns_rewrites;
ALTER TABLE dns_rewrites_new RENAME TO dns_rewrites;

-- 2. Improve api_tokens
CREATE TABLE api_tokens_new (
    id         SERIAL PRIMARY KEY,
    token      TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    last_used  BIGINT
);

INSERT INTO api_tokens_new (token, name, created_at, last_used)
SELECT token, name, created_at, last_used FROM api_tokens;

DROP TABLE api_tokens;
ALTER TABLE api_tokens_new RENAME TO api_tokens;
