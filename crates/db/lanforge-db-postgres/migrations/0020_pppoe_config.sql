-- Migration 20: Add table for PPPoE dynamic configuration
CREATE SCHEMA IF NOT EXISTS pppoe;

CREATE TABLE pppoe.config (
    id INT PRIMARY KEY DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT false,
    wan_iface TEXT NOT NULL DEFAULT 'eth1',
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    auth TEXT NOT NULL DEFAULT 'chap_md5',
    mru INT NOT NULL DEFAULT 1492,
    lcp_echo_interval_secs BIGINT NOT NULL DEFAULT 10,
    lcp_echo_max_failures INT NOT NULL DEFAULT 3,
    reconnect_delay_secs BIGINT NOT NULL DEFAULT 10,
    CONSTRAINT single_pppoe_config CHECK (id = 1)
);
