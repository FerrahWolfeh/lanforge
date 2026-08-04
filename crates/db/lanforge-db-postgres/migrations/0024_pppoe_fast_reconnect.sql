-- Migration 24: Add fast reconnect / debug and PADI tuning columns to pppoe.config
ALTER TABLE pppoe.config
ADD COLUMN IF NOT EXISTS send_padt_on_shutdown BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS discovery_padi_retries INT NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS discovery_padi_timeout_secs BIGINT NOT NULL DEFAULT 3;