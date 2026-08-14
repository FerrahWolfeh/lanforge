-- Migration 27: Add table for DHCP scope options and TFTP parameters
CREATE TABLE IF NOT EXISTS dhcp.options (
    id INT PRIMARY KEY DEFAULT 1,
    config JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT single_row CHECK (id = 1)
);