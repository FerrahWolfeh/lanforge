use lanforge_core::bus::TimedEvent;
use lanforge_core::context::state::State;
use lanforge_core::types::LeaseTarget;
use lanforge_macros::CommandDispatch;
use serde::{Deserialize, Serialize};

pub mod common;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod system;

pub use common::*;
pub use devices::*;
pub use dhcp::*;
pub use dns::*;
pub use system::*;

/// Represents a command sent from a client to the Lanforge daemon.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Command {
    /// Override response encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Encoding>,
    /// Request response compression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<Compression>,
    /// The actual command to execute.
    #[serde(flatten)]
    pub action: CommandAction,
}

impl Command {
    /// Helper to create a command with default transport options.
    #[must_use]
    pub const fn new(action: CommandAction) -> Self {
        Self {
            encoding: None,
            compression: None,
            action,
        }
    }

    /// Pre-defined Status command.
    pub const STATUS: Self = Self {
        encoding: None,
        compression: None,
        action: CommandAction::Status,
    };
}

/// The actual action variants for a Command.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash, CommandDispatch)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum CommandAction {
    /// Retrieve general system status (uptime, versions, service states).
    #[dispatch(handler = "handle_status", readonly)]
    Status,
    /// List all managed devices with optional filtering.
    #[dispatch(handler = "handle_devices", args(filter, vendor, method, format), readonly)]
    Devices {
        /// Filter by hostname, MAC, or IP address.
        filter: Option<String>,
        /// Filter by specific vendor name (OUI).
        vendor: Option<String>,
        /// Filter by specific learning method.
        method: Option<String>,
        /// Output format (reserved for future use).
        format: Option<String>,
    },
    /// Request the daemon to reload its configuration from disk.
    #[dispatch(handler = "handle_reload")]
    Reload,
    /// Enter 'watch' mode to stream live state changes.
    #[dispatch(handler = "handle_watch", readonly)]
    Watch,
    /// Stream or fetch logs/events.
    #[dispatch(handler = "handle_log", args(follow, n), readonly)]
    Log {
        /// If true, keep the connection open and stream new events.
        follow: bool,
        /// Number of historical entries to fetch.
        n: Option<usize>,
    },
    /// Force an immediate network scan.
    #[dispatch(handler = "handle_scan")]
    Scan,
    /// Gracefully shut down the daemon.
    #[dispatch(handler = "handle_shutdown")]
    Shutdown,
    /// Add or update a static host configuration via CLI.
    #[dispatch(handler = "handle_host_add", args(mac, hostname, v4, v6_suffix))]
    HostAdd {
        /// Target device MAC address.
        mac: Option<String>,
        /// Desired hostname.
        hostname: Option<String>,
        /// Static IPv4 address.
        v4: Option<String>,
        /// IPv6 interface ID or Full address.
        v6_suffix: Option<String>,
    },
    /// Set a specific field for a host configuration.
    #[dispatch(handler = "handle_host_set", args(mac, field, value))]
    HostSet {
        /// Target device MAC address.
        mac: String,
        /// Field name (e.g., "hostname", "v4", "`v6_suffix`").
        field: String,
        /// New value for the field.
        value: String,
    },
    /// Remove a host configuration by MAC.
    #[dispatch(handler = "handle_host_remove", args(mac))]
    HostRemove {
        /// Target device MAC address.
        mac: String,
    },
    /// List all manually configured hosts.
    #[dispatch(handler = "handle_hosts", readonly)]
    HostList,
    /// Force a DHCP 'forcerenew' for a specific device.
    #[dispatch(handler = "handle_lease_renew", args(mac, target))]
    LeaseRenew {
        /// Target device MAC address.
        mac: String,
        /// Optional specific lease target (V4, V6, or `V6Prefix` with IAID).
        target: Option<LeaseTarget>,
    },
    /// Manually release a DHCP lease.
    #[dispatch(handler = "handle_lease_release", args(mac, target))]
    LeaseRelease {
        /// Target device MAC address.
        mac: String,
        /// Optional specific lease target (V4, V6, or `V6Prefix` with IAID).
        target: Option<LeaseTarget>,
    },
    /// Fetch DHCP pool utilization.
    #[dispatch(handler = "handle_dhcp_pools")]
    DhcpPools,
    /// Perform a VACUUM operation on the underlying `SQLite` database.
    #[dispatch(handler = "handle_db_vacuum")]
    DbVacuum,
    /// Clear all transient system logs.
    #[dispatch(handler = "handle_db_log_clean")]
    DbLogClean,
    /// Remove 'zombie' entries from the database (dynamic devices with no IPs/Hostname).
    #[dispatch(handler = "handle_db_prune")]
    DbPrune,
    /// Forcefully purge a device from memory and database by its MAC.
    #[dispatch(handler = "handle_purge", args(mac))]
    Purge {
        /// Target device MAC address.
        mac: String,
    },
    /// Send a Wake-on-LAN magic packet to a target (MAC or Name).
    #[dispatch(handler = "handle_wol", args(target))]
    Wol {
        /// Target device MAC or Hostname.
        target: String,
    },
    /// Retrieve detailed aggregated information about a device.
    #[dispatch(handler = "handle_whois", args(target), readonly)]
    Whois {
        /// Target MAC, IP, or Hostname.
        target: String,
    },
    #[dispatch(handler = "handle_dns_stats")]
    DnsStats,
    /// Retrieve DNS analytics (top domains, query types, query rate).
    #[dispatch(handler = "handle_dns_analytics", args(limit), readonly)]
    DnsAnalytics {
        /// Maximum number of top domains/clients to retrieve.
        limit: Option<usize>,
    },
    /// Retrieve DNS upstream status and health.
    #[dispatch(handler = "handle_dns_upstreams")]
    DnsUpstreams,
    /// Perform a diagnostic DNS query.
    #[dispatch(handler = "handle_dns_query", args(name, record_type))]
    DnsQuery {
        /// Name to resolve.
        name: String,
        /// Optional record type (A, AAAA, TXT, etc.).
        record_type: Option<String>,
    },
    /// Flush the DNS cache.
    #[dispatch(handler = "handle_dns_cache_flush")]
    DnsCacheFlush,
    /// Dump the DNS cache contents.
    #[dispatch(handler = "handle_dns_cache_dump")]
    DnsCacheDump,
    /// Enable or disable the DNS adblocker.
    #[dispatch(handler = "handle_dns_adblock_set", args(enabled, duration_secs))]
    DnsAdblockSet {
        /// Whether to enable or disable the adblocker.
        #[serde(default)]
        enabled: bool,
        /// Optional duration in seconds for temporary disabling.
        duration_secs: Option<u64>,
    },
    /// Force a reload of the adblock blocklists.
    #[dispatch(handler = "handle_dns_adblock_reload")]
    DnsAdblockReload,
    /// Retrieve recent DNS query logs.
    #[dispatch(handler = "handle_dns_query_log", args(limit, client, follow), readonly)]
    DnsQueryLog {
        /// Maximum number of entries to retrieve.
        limit: Option<usize>,
        /// Filter by client IP address.
        client: Option<String>,
        /// Whether to follow live logs.
        #[serde(default)]
        follow: bool,
    },
    /// Retrieve current adblock status and metrics.
    #[dispatch(handler = "handle_dns_adblock_status", readonly)]
    DnsAdblockStatus,
    /// Add a domain to the blocklist (persistent via rewrite to 0.0.0.0).
    #[dispatch(handler = "handle_dns_block", args(domain))]
    DnsBlock {
        /// Domain to block.
        domain: String,
    },
    /// Add a domain to the permanent allowlist.
    #[dispatch(handler = "handle_dns_allow", args(domain))]
    DnsAllow {
        /// Domain to allow.
        domain: String,
    },
    /// Remove a domain from the permanent allowlist.
    #[dispatch(handler = "handle_dns_unallow", args(domain))]
    DnsUnallow {
        /// Domain to remove from allowlist.
        domain: String,
    },
    /// Add a DNS rewrite rule.
    #[dispatch(handler = "handle_dns_rewrite_add", args(domain, answer))]
    DnsRewriteAdd {
        /// Domain name or pattern.
        domain: String,
        /// IPv4, IPv6, CNAME, or Device name.
        answer: String,
    },
    /// Remove a DNS rewrite rule.
    #[dispatch(handler = "handle_dns_rewrite_remove", args(domain))]
    DnsRewriteRemove {
        /// Domain to remove.
        domain: String,
    },
    /// List all DNS rewrite rules.
    #[dispatch(handler = "handle_dns_rewrites", readonly)]
    DnsRewriteList,
    /// List the permanent DNS allowlist.
    #[dispatch(handler = "handle_dns_allowlist", readonly)]
    DnsAllowlistList,
    /// Add an adblock source URL.
    #[dispatch(handler = "handle_dns_adblock_url_add", args(url, kind))]
    DnsAdblockUrlAdd {
        /// URL of the blocklist/allowlist.
        url: String,
        /// Kind: "blocklist" or "allowlist".
        kind: String,
    },
    /// Remove an adblock source URL.
    #[dispatch(handler = "handle_dns_adblock_url_remove", args(url))]
    DnsAdblockUrlRemove {
        /// URL to remove.
        url: String,
    },
    /// List all adblock source URLs.
    #[dispatch(handler = "handle_dns_adblock_urls", readonly)]
    DnsAdblockUrlList,
    /// Dump the full system context (for debugging).
    #[dispatch(handler = "handle_context_dump", args(only_devices, only_orphans))]
    ContextDump {
        #[serde(default)]
        only_devices: bool,
        #[serde(default)]
        only_orphans: bool,
    },
    /// Factory reset the database and in-memory state.
    #[dispatch(handler = "handle_db_reset")]
    DbReset,
    /// List active DHCP leases.
    #[dispatch(handler = "handle_leases", args(count), readonly)]
    Leases {
        #[serde(default)]
        count: bool,
    },
    /// Get network topology.
    #[dispatch(handler = "handle_topology", readonly)]
    Topology,
    /// Update the daemon's API password (requires UDS connection).
    #[dispatch(handler = "handle_config_set_password", args(password))]
    ConfigSetPassword {
        /// New plaintext password to hash and store.
        password: String,
    },
}

/// Represents a response sent from the daemon to a client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Detailed system status.
    Status(Box<StatusResponse>),
    /// List of managed devices.
    Devices(DevicesResponse),
    /// List of manually configured hosts.
    Hosts(HostsResponse),
    /// Generic error message.
    Error {
        /// Human-readable error description.
        error: String,
    },
    /// Generic success indicator.
    Success(SimpleSuccess),
    /// A live event from the internal bus (for 'watch' or 'log' commands).
    Event(TimedEvent),
    /// Response for a Whois query.
    Whois(Box<WhoisResponse>),
    /// Response for DNS statistics.
    DnsStats(DnsStatsResponse),
    /// Response for DNS analytics.
    DnsAnalytics(DnsAnalyticsResponse),
    /// Response for DNS upstreams status.
    DnsUpstreams(DnsUpstreamsResponse),
    /// Response for a DNS diagnostic query.
    DnsQuery(DnsQueryResponse),
    /// Response for DNS query logs.
    DnsQueryLog(DnsQueryLogResponse),
    /// Response for DNS adblock status.
    DnsAdblockStatus(DnsAdblockStatusResponse),
    /// Response for DHCP pool utilization.
    DhcpPools(DhcpPoolsResponse),
    /// Response for DNS cache dump.
    DnsCache(DnsCacheResponse),
    /// Response for a full context dump.
    ContextDump(Box<State>),
    /// List of active DHCP leases.
    Leases(LeasesResponse),
    /// Hierarchical physical topology.
    Topology(TopologyResponse),
    /// List of DNS rewrite rules.
    DnsRewrites(DnsRewritesResponse),
    /// List of DNS allowlist entries.
    DnsAllowlist(DnsAllowlistResponse),
    /// List of adblock source URLs.
    DnsAdblockUrls(DnsAdblockUrlsResponse),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serialization() {
        let cmd = Command::new(CommandAction::Status);
        let json = serde_json::to_string(&cmd).unwrap();
        assert_eq!(json, r#"{"command":"status"}"#);

        let cmd = Command::new(CommandAction::Devices {
            filter: Some("arch".to_string()),
            vendor: None,
            method: None,
            format: None,
        });
        let json = serde_json::to_string(&cmd).unwrap();
        assert_eq!(
            json,
            r#"{"command":"devices","filter":"arch","vendor":null,"method":null,"format":null}"#
        );
    }
}
