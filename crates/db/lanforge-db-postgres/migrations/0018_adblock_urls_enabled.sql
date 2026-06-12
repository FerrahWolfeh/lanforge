-- Migration 18: Add enabled column to dns.adblock_urls
ALTER TABLE dns.adblock_urls ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;
