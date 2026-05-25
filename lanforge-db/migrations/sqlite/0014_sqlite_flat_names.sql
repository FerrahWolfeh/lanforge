-- Migration: Rename SQLite tables to drop 'dns_' prefixes for Option A flat schema
ALTER TABLE dns_adblock_config RENAME TO adblock_config;
ALTER TABLE dns_adblock_urls RENAME TO adblock_urls;
ALTER TABLE dns_allowlist RENAME TO allowlist;
ALTER TABLE dns_reverse_resolvers RENAME TO reverse_resolvers;
ALTER TABLE dns_rewrites RENAME TO rewrites;
ALTER TABLE dns_upstreams RENAME TO upstreams;
