-- Migration 26: Add ra.state table for persistent active GUA prefix across daemon restarts
CREATE TABLE IF NOT EXISTS ra.state (
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_gua INET,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
