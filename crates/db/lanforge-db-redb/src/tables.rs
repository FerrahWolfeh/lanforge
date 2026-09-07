//! Table definitions for `lanforge-db-redb`.

use redb::TableDefinition;

pub const TABLE_DEVICES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("devices");
pub const TABLE_CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("config");
pub const TABLE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
pub const TABLE_USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
pub const TABLE_API_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("api_tokens");
pub const TABLE_DNS_REWRITES: TableDefinition<i64, &[u8]> = TableDefinition::new("dns_rewrites");
pub const TABLE_DNS_ALLOWLIST: TableDefinition<&str, i64> = TableDefinition::new("dns_allowlist");
pub const TABLE_DNS_UPSTREAMS: TableDefinition<i64, &[u8]> = TableDefinition::new("dns_upstreams");
pub const TABLE_ADBLOCK_URLS: TableDefinition<i64, &[u8]> = TableDefinition::new("adblock_urls");
pub const TABLE_ADBLOCK_RULES: TableDefinition<i64, &[u8]> = TableDefinition::new("adblock_rules");
pub const TABLE_LEASE_HISTORY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("lease_history");
pub const TABLE_LOG_EVENTS: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("log_events");
pub const TABLE_DNS_QUERIES: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("dns_queries");
pub const TABLE_DNS_BLOCKED: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("dns_blocked");
