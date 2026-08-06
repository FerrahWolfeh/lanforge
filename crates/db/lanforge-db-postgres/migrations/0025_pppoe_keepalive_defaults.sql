-- Migration 25: Update default keepalive interval and max failures in pppoe.config
ALTER TABLE pppoe.config
    ALTER COLUMN lcp_echo_interval_secs SET DEFAULT 20,
    ALTER COLUMN lcp_echo_max_failures SET DEFAULT 5;

UPDATE pppoe.config
SET lcp_echo_interval_secs = 20,
    lcp_echo_max_failures = 5
WHERE lcp_echo_interval_secs = 10 AND lcp_echo_max_failures = 3;
