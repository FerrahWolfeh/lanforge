-- Migration 17: Add adblock rules table and action type
CREATE TYPE dns.adblock_action AS ENUM ('block', 'allow');

CREATE TABLE dns.adblock_rules (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    action dns.adblock_action NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true
);
