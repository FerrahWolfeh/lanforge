-- API Tokens for HTTP authentication
CREATE TABLE IF NOT EXISTS api_tokens (
    token      TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used  INTEGER
);
