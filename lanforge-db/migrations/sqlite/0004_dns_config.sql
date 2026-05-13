-- DNS rewrite rules (currently [[dns.rewrites]] in TOML)
CREATE TABLE IF NOT EXISTS dns_rewrites (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain  TEXT NOT NULL UNIQUE,
    answer  TEXT NOT NULL
);

-- DNS allowlist domains (currently dns.allowlist in TOML)
CREATE TABLE IF NOT EXISTS dns_allowlist (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain  TEXT NOT NULL UNIQUE
);

-- Adblock key-value configuration
CREATE TABLE IF NOT EXISTS dns_adblock_config (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

-- Adblock source URLs
CREATE TABLE IF NOT EXISTS dns_adblock_urls (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT NOT NULL UNIQUE,
    kind    TEXT NOT NULL DEFAULT 'block'  -- 'block' or 'allow'
);
