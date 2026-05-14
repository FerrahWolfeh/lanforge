-- API Tokens for HTTP authentication
CREATE TABLE IF NOT EXISTS api_tokens (
    token      TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used  BIGINT
);
